package googleworkspacepoller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBigQueryLookback        = 24 * time.Hour
	defaultBigQueryLateLookback    = 15 * time.Minute
	defaultBigQueryPollInterval    = 5 * time.Minute
	defaultBigQueryPageSize        = 1000
	defaultBigQueryMaxPages        = 20
	defaultBigQueryTokenScope      = "https://www.googleapis.com/auth/bigquery"
	defaultGoogleSTSTokenURL       = "https://sts.googleapis.com/v1/token"
	defaultGoogleIAMCredentialsURL = "https://iamcredentials.googleapis.com/v1"
	defaultGoogleBigQueryURL       = "https://bigquery.googleapis.com/bigquery/v2"
)

var bigQueryIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type BigQueryConfig struct {
	IntegrationID            string
	OrganizationID           string
	ExternalAccountID        string
	ProjectID                string
	RawDatasetID             string
	DatasetID                string
	Location                 string
	ServiceAccountEmail      string
	WorkloadIdentityProvider string
	AccessMode               string
}

type BigQueryValidationResult struct {
	IntegrationID       string
	Ok                  bool
	Message             string
	ProjectID           string
	DatasetID           string
	ActivityTable       string
	TableFound          bool
	SampleRows          int
	EstimatedBytes      int64
	RuntimeTokenPresent bool
}

type BigQueryPoller struct {
	db              *sql.DB
	httpClient      *http.Client
	interval        time.Duration
	lookback        time.Duration
	lateLookback    time.Duration
	nowFn           func() time.Time
	pageSize        int
	maxPages        int
	tokenSource     *wifTokenSource
	recordTypes     []string
	bigQueryBaseURL string
}

func NewBigQueryPoller(db *sql.DB) *BigQueryPoller {
	return &BigQueryPoller{
		db:              db,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		interval:        defaultBigQueryPollInterval,
		lookback:        defaultBigQueryLookback,
		lateLookback:    defaultBigQueryLateLookback,
		nowFn:           time.Now,
		pageSize:        defaultBigQueryPageSize,
		maxPages:        defaultBigQueryMaxPages,
		tokenSource:     newWIFTokenSourceFromEnv(),
		recordTypes:     append([]string(nil), DefaultApplications...),
		bigQueryBaseURL: envDefault("APERIO_GOOGLE_BIGQUERY_BASE_URL", defaultGoogleBigQueryURL),
	}
}

func (p *BigQueryPoller) WithHTTPClient(c *http.Client) *BigQueryPoller {
	p.httpClient = c
	p.tokenSource.httpClient = c
	return p
}

func (p *BigQueryPoller) WithInterval(d time.Duration) *BigQueryPoller  { p.interval = d; return p }
func (p *BigQueryPoller) WithNowFn(fn func() time.Time) *BigQueryPoller { p.nowFn = fn; return p }
func (p *BigQueryPoller) WithPageSize(n int) *BigQueryPoller            { p.pageSize = n; return p }
func (p *BigQueryPoller) WithMaxPages(n int) *BigQueryPoller            { p.maxPages = n; return p }
func (p *BigQueryPoller) WithRecordTypes(types []string) *BigQueryPoller {
	p.recordTypes = append([]string(nil), types...)
	return p
}
func (p *BigQueryPoller) WithTokenSource(source *wifTokenSource) *BigQueryPoller {
	p.tokenSource = source
	if p.tokenSource.httpClient == nil {
		p.tokenSource.httpClient = p.httpClient
	}
	return p
}
func (p *BigQueryPoller) WithBigQueryBaseURL(baseURL string) *BigQueryPoller {
	p.bigQueryBaseURL = strings.TrimRight(baseURL, "/")
	return p
}

func (p *BigQueryPoller) Run(ctx context.Context) error {
	if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("googleworkspacebigquery: first tick failed: %v", err)
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("googleworkspacebigquery: tick failed: %v", err)
			}
		}
	}
}

func (p *BigQueryPoller) Tick(ctx context.Context) error {
	configs, err := p.connectedBigQueryIntegrations(ctx)
	if err != nil {
		return err
	}
	for _, cfg := range configs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollIntegration(ctx, cfg); err != nil {
			log.Printf("googleworkspacebigquery: integration %s poll failed: %v", cfg.IntegrationID, err)
		}
	}
	return nil
}

func (p *BigQueryPoller) WakeIntegration(ctx context.Context, integrationID string) error {
	if strings.TrimSpace(integrationID) == "" {
		return nil
	}
	cfg, err := p.loadBigQueryConfig(ctx, integrationID, "")
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return p.pollIntegration(ctx, cfg)
}

func (p *BigQueryPoller) ValidateIntegration(ctx context.Context, integrationID, organizationID string) (BigQueryValidationResult, error) {
	cfg, err := p.loadBigQueryConfig(ctx, integrationID, organizationID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BigQueryValidationResult{}, err
		}
		return BigQueryValidationResult{}, fmt.Errorf("load BigQuery config: %w", err)
	}
	return p.ValidateConfig(ctx, cfg)
}

func (p *BigQueryPoller) ValidateConfig(ctx context.Context, cfg BigQueryConfig) (BigQueryValidationResult, error) {
	result := BigQueryValidationResult{
		IntegrationID:  cfg.IntegrationID,
		ProjectID:      cfg.ProjectID,
		DatasetID:      cfg.DatasetID,
		ActivityTable:  cfg.activityTable(),
		TableFound:     false,
		EstimatedBytes: 0,
	}
	if err := cfg.validate(); err != nil {
		result.Message = err.Error()
		return result, nil
	}
	subjectToken, err := p.tokenSource.subjectToken()
	if err != nil {
		result.Message = err.Error()
		return result, nil
	}
	result.RuntimeTokenPresent = true
	accessToken, err := p.tokenSource.accessToken(ctx, cfg, subjectToken)
	if err != nil {
		result.Message = "WIF token exchange failed: " + err.Error()
		return result, nil
	}
	tableCount, sampleRows, estimatedBytes, err := p.validateBigQueryExport(ctx, cfg, accessToken)
	if err != nil {
		result.Message = "BigQuery validation failed: " + err.Error()
		return result, nil
	}
	result.TableFound = tableCount > 0
	result.SampleRows = sampleRows
	result.EstimatedBytes = estimatedBytes
	if !result.TableFound {
		result.Message = fmt.Sprintf("Activity table %s.%s.%s was not found", cfg.ProjectID, cfg.DatasetID, cfg.activityTable())
		return result, nil
	}
	result.Ok = true
	result.Message = fmt.Sprintf("Validated %s.%s.%s with %d sample row(s)", cfg.ProjectID, cfg.DatasetID, cfg.activityTable(), sampleRows)
	return result, nil
}

func (p *BigQueryPoller) pollIntegration(ctx context.Context, cfg BigQueryConfig) error {
	if err := cfg.validate(); err != nil {
		p.recordBigQueryError(ctx, cfg.IntegrationID, "activity", err)
		return err
	}
	subjectToken, err := p.tokenSource.subjectToken()
	if err != nil {
		p.recordBigQueryError(ctx, cfg.IntegrationID, "activity", err)
		return err
	}
	accessToken, err := p.tokenSource.accessToken(ctx, cfg, subjectToken)
	if err != nil {
		p.recordBigQueryError(ctx, cfg.IntegrationID, "activity", err)
		return err
	}
	for _, recordType := range p.recordTypes {
		if err := p.pollRecordType(ctx, cfg, accessToken, recordType); err != nil {
			p.recordBigQueryError(ctx, cfg.IntegrationID, recordType, err)
			log.Printf("googleworkspacebigquery: integration=%s record_type=%s failed: %v", cfg.IntegrationID, recordType, err)
		}
	}
	_, _ = p.db.ExecContext(ctx, `UPDATE integration_connections SET last_sync_at = $1, updated_at = NOW() WHERE id = $2`, p.nowFn().UTC(), cfg.IntegrationID)
	return nil
}

func (p *BigQueryPoller) pollRecordType(ctx context.Context, cfg BigQueryConfig, accessToken, recordType string) error {
	cursor, err := p.loadBigQueryCursor(ctx, cfg.IntegrationID, recordType)
	if err != nil {
		return err
	}
	start := p.nowFn().Add(-p.lookback).UTC()
	if !cursor.LastEventTime.IsZero() {
		start = cursor.LastEventTime.Add(-p.lateLookback).UTC()
	}
	rows, _, err := p.queryActivityRows(ctx, cfg, accessToken, recordType, start, cursor)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		p.touchBigQueryCursor(ctx, cfg.IntegrationID, recordType, cursor.LastEventTime, cursor.LastRowHash, 0)
		return nil
	}
	var newest bigQueryActivityRow
	queued := 0
	for _, row := range rows {
		advancesCursor := cursor.isStrictlyAfter(row.EventTime, row.RowHash)
		activity, event, err := row.toReportsActivity()
		if err != nil {
			return err
		}
		if err := p.enqueueEvent(ctx, integrationRow{
			ID:                cfg.IntegrationID,
			OrganizationID:    cfg.OrganizationID,
			ExternalAccountID: cfg.ExternalAccountID,
		}, recordType, activity, event); err != nil {
			return err
		}
		queued++
		if advancesCursor && (newest.EventTime.IsZero() || row.EventTime.After(newest.EventTime) || (row.EventTime.Equal(newest.EventTime) && row.RowHash > newest.RowHash)) {
			newest = row
		}
	}
	nextCursor := cursor.advanceTo(newest)
	p.touchBigQueryCursor(ctx, cfg.IntegrationID, recordType, nextCursor.LastEventTime, nextCursor.LastRowHash, queued)
	return nil
}

func (p *BigQueryPoller) enqueueEvent(ctx context.Context, integ integrationRow, application string, activity reportsActivity, event reportsEvent) error {
	return enqueueGoogleWorkspaceEvent(ctx, p.db, integ, application, activity, event)
}

func (p *BigQueryPoller) connectedBigQueryIntegrations(ctx context.Context) ([]BigQueryConfig, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, organization_id, external_account_id,
		       google_workspace_bigquery_project_id,
		       google_workspace_bigquery_raw_dataset_id,
		       google_workspace_bigquery_dataset_id,
		       google_workspace_bigquery_location,
		       google_workspace_bigquery_service_account_email,
		       google_workspace_bigquery_wif_provider,
		       google_workspace_bigquery_access_mode
		FROM integration_connections
		WHERE provider = 'GOOGLE_WORKSPACE'
		  AND status = 'CONNECTED'
		  AND google_workspace_bigquery_project_id IS NOT NULL
		  AND google_workspace_bigquery_dataset_id IS NOT NULL
		  AND google_workspace_bigquery_location IS NOT NULL
		  AND google_workspace_bigquery_service_account_email IS NOT NULL
		  AND google_workspace_bigquery_wif_provider IS NOT NULL
		  AND google_workspace_bigquery_access_mode IS NOT NULL
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BigQueryConfig
	for rows.Next() {
		var cfg BigQueryConfig
		var rawDataset sql.NullString
		if err := rows.Scan(&cfg.IntegrationID, &cfg.OrganizationID, &cfg.ExternalAccountID, &cfg.ProjectID, &rawDataset, &cfg.DatasetID, &cfg.Location, &cfg.ServiceAccountEmail, &cfg.WorkloadIdentityProvider, &cfg.AccessMode); err != nil {
			return nil, err
		}
		cfg.RawDatasetID = rawDataset.String
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (p *BigQueryPoller) loadBigQueryConfig(ctx context.Context, integrationID, organizationID string) (BigQueryConfig, error) {
	query := `
		SELECT id, organization_id, external_account_id,
		       google_workspace_bigquery_project_id,
		       google_workspace_bigquery_raw_dataset_id,
		       google_workspace_bigquery_dataset_id,
		       google_workspace_bigquery_location,
		       google_workspace_bigquery_service_account_email,
		       google_workspace_bigquery_wif_provider,
		       google_workspace_bigquery_access_mode
		FROM integration_connections
		WHERE id = $1
		  AND provider = 'GOOGLE_WORKSPACE'
		  AND status = 'CONNECTED'
		  AND google_workspace_bigquery_project_id IS NOT NULL
		  AND google_workspace_bigquery_dataset_id IS NOT NULL
		  AND google_workspace_bigquery_location IS NOT NULL
		  AND google_workspace_bigquery_service_account_email IS NOT NULL
		  AND google_workspace_bigquery_wif_provider IS NOT NULL
		  AND google_workspace_bigquery_access_mode IS NOT NULL`
	args := []any{integrationID}
	if strings.TrimSpace(organizationID) != "" {
		query += ` AND organization_id = $2`
		args = append(args, organizationID)
	}
	var cfg BigQueryConfig
	var rawDataset sql.NullString
	err := p.db.QueryRowContext(ctx, query, args...).Scan(&cfg.IntegrationID, &cfg.OrganizationID, &cfg.ExternalAccountID, &cfg.ProjectID, &rawDataset, &cfg.DatasetID, &cfg.Location, &cfg.ServiceAccountEmail, &cfg.WorkloadIdentityProvider, &cfg.AccessMode)
	cfg.RawDatasetID = rawDataset.String
	return cfg, err
}

type bigQueryCursor struct {
	LastEventTime time.Time
	LastRowHash   string
}

func (c bigQueryCursor) isStrictlyAfter(t time.Time, rowHash string) bool {
	if c.LastEventTime.IsZero() {
		return true
	}
	if t.After(c.LastEventTime) {
		return true
	}
	return t.Equal(c.LastEventTime) && rowHash > c.LastRowHash
}

func (c bigQueryCursor) advanceTo(row bigQueryActivityRow) bigQueryCursor {
	if row.EventTime.IsZero() {
		return c
	}
	return bigQueryCursor{LastEventTime: row.EventTime, LastRowHash: row.RowHash}
}

func (p *BigQueryPoller) loadBigQueryCursor(ctx context.Context, integrationID, recordType string) (bigQueryCursor, error) {
	var c bigQueryCursor
	err := p.db.QueryRowContext(ctx, `
		SELECT last_event_time, last_row_hash
		FROM google_workspace_bigquery_sync_cursors
		WHERE integration_id = $1 AND record_type = $2
	`, integrationID, recordType).Scan(&c.LastEventTime, &c.LastRowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return bigQueryCursor{}, nil
	}
	return c, err
}

func (p *BigQueryPoller) touchBigQueryCursor(ctx context.Context, integrationID, recordType string, eventTime time.Time, rowHash string, rowCount int) {
	if eventTime.IsZero() {
		eventTime = p.nowFn().Add(-p.lookback).UTC()
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_bigquery_sync_cursors
			(integration_id, record_type, last_event_time, last_row_hash, last_polled_at, last_row_count, last_error)
		VALUES ($1, $2, $3, $4, $5, $6, NULL)
		ON CONFLICT (integration_id, record_type) DO UPDATE SET
			last_event_time = EXCLUDED.last_event_time,
			last_row_hash = EXCLUDED.last_row_hash,
			last_polled_at = EXCLUDED.last_polled_at,
			last_row_count = EXCLUDED.last_row_count,
			last_error = NULL
	`, integrationID, recordType, eventTime, rowHash, p.nowFn().UTC(), rowCount)
	if err != nil {
		log.Printf("googleworkspacebigquery: touch cursor failed integration=%s record_type=%s: %v", integrationID, recordType, err)
	}
}

func (p *BigQueryPoller) recordBigQueryError(ctx context.Context, integrationID, recordType string, pollErr error) {
	msg := pollErr.Error()
	if len(msg) > 480 {
		msg = msg[:480]
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO google_workspace_bigquery_sync_cursors
			(integration_id, record_type, last_event_time, last_row_hash, last_polled_at, last_row_count, last_error)
		VALUES ($1, $2, $3, '', $4, 0, $5)
		ON CONFLICT (integration_id, record_type) DO UPDATE SET
			last_polled_at = EXCLUDED.last_polled_at,
			last_error = EXCLUDED.last_error
	`, integrationID, recordType, p.nowFn().Add(-p.lookback).UTC(), p.nowFn().UTC(), msg)
	if err != nil {
		log.Printf("googleworkspacebigquery: record error failed integration=%s record_type=%s: %v", integrationID, recordType, err)
	}
}

type bigQueryActivityRow struct {
	RowJSON    string
	RowHash    string
	RecordType string
	EventName  string
	EventType  string
	Email      string
	IPAddress  string
	EventTime  time.Time
	Raw        map[string]any
}

func (r bigQueryActivityRow) toReportsActivity() (reportsActivity, reportsEvent, error) {
	parameters := parametersFromBigQueryRow(r.Raw, r.RecordType)
	event := reportsEvent{
		Type:       r.EventType,
		Name:       r.EventName,
		Parameters: parameters,
	}
	activity := reportsActivity{
		EventTime:       r.EventTime,
		UniqueQualifier: r.RowHash,
		Actor: reportsActor{
			Email: r.Email,
		},
		Events: []reportsEvent{event},
	}
	return activity, event, nil
}

func parametersFromBigQueryRow(raw map[string]any, recordType string) []reportsParameter {
	params := make([]reportsParameter, 0, len(raw))
	seen := map[string]struct{}{}
	add := func(name string, value any) {
		if strings.TrimSpace(name) == "" || value == nil {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		param := reportsParameter{Name: name}
		switch typed := value.(type) {
		case string:
			param.Value = typed
		case bool:
			next := typed
			param.BoolValue = &next
		case float64:
			param.IntValue = strconv.FormatInt(int64(typed), 10)
		case []any:
			for _, item := range typed {
				if text, ok := item.(string); ok {
					param.MultiValue = append(param.MultiValue, text)
				}
			}
			if len(param.MultiValue) == 0 {
				return
			}
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return
			}
			param.Value = string(encoded)
		}
		params = append(params, param)
	}
	for key, value := range raw {
		switch key {
		case recordType:
			continue
		default:
			add(key, value)
		}
	}
	if nested, ok := raw[recordType].(map[string]any); ok {
		for key, value := range nested {
			add(key, value)
		}
	}
	return params
}

func (p *BigQueryPoller) queryActivityRows(ctx context.Context, cfg BigQueryConfig, accessToken, recordType string, start time.Time, cursor bigQueryCursor) ([]bigQueryActivityRow, bool, error) {
	query, err := cfg.activityQuery(recordType, p.pageSize*p.maxPages)
	if err != nil {
		return nil, false, err
	}
	cursorUsec := int64(0)
	if !cursor.LastEventTime.IsZero() {
		cursorUsec = cursor.LastEventTime.UnixMicro()
	}
	params := []bigQueryParameter{
		stringQueryParam("record_type", recordType),
		intQueryParam("from_usec", start.UnixMicro()),
		timestampQueryParam("from_partition", start),
		intQueryParam("cursor_usec", cursorUsec),
		stringQueryParam("cursor_hash", cursor.LastRowHash),
	}
	var all []bigQueryActivityRow
	response, err := p.runBigQueryQuery(ctx, cfg, accessToken, query, params, false)
	if err != nil {
		return nil, false, err
	}
	rows, err := decodeBigQueryActivityRows(response)
	if err != nil {
		return nil, false, err
	}
	all = append(all, rows...)
	pageToken := response.PageToken
	jobID := response.JobReference.JobID
	for page := 1; page < p.maxPages && pageToken != ""; page++ {
		if strings.TrimSpace(jobID) == "" {
			return nil, false, errors.New("bigquery query returned a page token without a job id")
		}
		response, err := p.getBigQueryQueryResults(ctx, cfg, accessToken, jobID, pageToken)
		if err != nil {
			return nil, false, err
		}
		rows, err := decodeBigQueryActivityRows(response)
		if err != nil {
			return nil, false, err
		}
		all = append(all, rows...)
		if response.PageToken == "" {
			return all, true, nil
		}
		pageToken = response.PageToken
	}
	return all, pageToken == "", nil
}

func (p *BigQueryPoller) validateBigQueryExport(ctx context.Context, cfg BigQueryConfig, accessToken string) (int, int, int64, error) {
	tableQuery := fmt.Sprintf(
		"SELECT COUNT(1) AS table_count FROM `%s.%s.INFORMATION_SCHEMA.TABLES` WHERE table_name = @table_name",
		cfg.ProjectID,
		cfg.DatasetID,
	)
	tableResp, err := p.runBigQueryQuery(ctx, cfg, accessToken, tableQuery, []bigQueryParameter{stringQueryParam("table_name", cfg.activityTable())}, false)
	if err != nil {
		return 0, 0, 0, err
	}
	tableCount := intFromFirstField(tableResp)
	if tableCount == 0 {
		return tableCount, 0, 0, nil
	}
	sampleQuery := fmt.Sprintf(
		"SELECT time_usec, record_type FROM `%s.%s.%s` AS t WHERE %s >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY) LIMIT 1",
		cfg.ProjectID,
		cfg.DatasetID,
		cfg.activityTable(),
		cfg.partitionTimeExpression("t"),
	)
	dryRunResp, err := p.runBigQueryQuery(ctx, cfg, accessToken, sampleQuery, nil, true)
	if err != nil {
		return tableCount, 0, 0, err
	}
	sampleResp, err := p.runBigQueryQuery(ctx, cfg, accessToken, sampleQuery, nil, false)
	if err != nil {
		return tableCount, 0, dryRunResp.TotalBytesProcessedInt(), err
	}
	return tableCount, len(sampleResp.Rows), dryRunResp.TotalBytesProcessedInt(), nil
}

type bigQueryParameter struct {
	Name           string                 `json:"name"`
	ParameterType  map[string]string      `json:"parameterType"`
	ParameterValue map[string]interface{} `json:"parameterValue"`
}

func stringQueryParam(name, value string) bigQueryParameter {
	return bigQueryParameter{Name: name, ParameterType: map[string]string{"type": "STRING"}, ParameterValue: map[string]interface{}{"value": value}}
}

func intQueryParam(name string, value int64) bigQueryParameter {
	return bigQueryParameter{Name: name, ParameterType: map[string]string{"type": "INT64"}, ParameterValue: map[string]interface{}{"value": strconv.FormatInt(value, 10)}}
}

func timestampQueryParam(name string, value time.Time) bigQueryParameter {
	return bigQueryParameter{Name: name, ParameterType: map[string]string{"type": "TIMESTAMP"}, ParameterValue: map[string]interface{}{"value": value.UTC().Format(time.RFC3339)}}
}

type bigQueryQueryResponse struct {
	JobComplete         bool   `json:"jobComplete"`
	PageToken           string `json:"pageToken"`
	TotalBytesProcessed string `json:"totalBytesProcessed"`
	JobReference        struct {
		ProjectID string `json:"projectId"`
		JobID     string `json:"jobId"`
		Location  string `json:"location"`
	} `json:"jobReference"`
	Schema struct {
		Fields []struct {
			Name string `json:"name"`
		} `json:"fields"`
	} `json:"schema"`
	Rows []struct {
		F []struct {
			V any `json:"v"`
		} `json:"f"`
	} `json:"rows"`
}

func (r bigQueryQueryResponse) TotalBytesProcessedInt() int64 {
	value, _ := strconv.ParseInt(r.TotalBytesProcessed, 10, 64)
	return value
}

func (p *BigQueryPoller) runBigQueryQuery(ctx context.Context, cfg BigQueryConfig, accessToken, query string, params []bigQueryParameter, dryRun bool) (bigQueryQueryResponse, error) {
	body := map[string]any{
		"query":        query,
		"useLegacySql": false,
		"location":     cfg.Location,
		"maxResults":   p.pageSize,
		"timeoutMs":    10000,
		"dryRun":       dryRun,
	}
	if len(params) > 0 {
		body["parameterMode"] = "NAMED"
		body["queryParameters"] = params
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	endpoint := strings.TrimRight(p.bigQueryBaseURL, "/") + "/projects/" + url.PathEscape(cfg.ProjectID) + "/queries"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return bigQueryQueryResponse{}, fmt.Errorf("bigquery query %d: %s", resp.StatusCode, truncate(raw, 240))
	}
	var decoded bigQueryQueryResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return bigQueryQueryResponse{}, err
	}
	if !dryRun && !decoded.JobComplete {
		return bigQueryQueryResponse{}, errors.New("bigquery query did not complete before timeout")
	}
	return decoded, nil
}

func (p *BigQueryPoller) getBigQueryQueryResults(ctx context.Context, cfg BigQueryConfig, accessToken, jobID, pageToken string) (bigQueryQueryResponse, error) {
	endpoint := strings.TrimRight(p.bigQueryBaseURL, "/") + "/projects/" + url.PathEscape(cfg.ProjectID) + "/queries/" + url.PathEscape(jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	query := req.URL.Query()
	query.Set("location", cfg.Location)
	query.Set("maxResults", strconv.Itoa(p.pageSize))
	query.Set("pageToken", pageToken)
	query.Set("timeoutMs", "10000")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return bigQueryQueryResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return bigQueryQueryResponse{}, fmt.Errorf("bigquery query results %d: %s", resp.StatusCode, truncate(raw, 240))
	}
	var decoded bigQueryQueryResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return bigQueryQueryResponse{}, err
	}
	if !decoded.JobComplete {
		return bigQueryQueryResponse{}, errors.New("bigquery query results did not complete before timeout")
	}
	return decoded, nil
}

func decodeBigQueryActivityRows(response bigQueryQueryResponse) ([]bigQueryActivityRow, error) {
	names := make([]string, 0, len(response.Schema.Fields))
	for _, field := range response.Schema.Fields {
		names = append(names, field.Name)
	}
	var out []bigQueryActivityRow
	for _, row := range response.Rows {
		values := map[string]any{}
		for index, field := range row.F {
			if index < len(names) {
				values[names[index]] = field.V
			}
		}
		rowJSON := stringFromAnyBQ(values["row_json"])
		var raw map[string]any
		if err := json.Unmarshal([]byte(rowJSON), &raw); err != nil {
			return nil, fmt.Errorf("decode row_json: %w", err)
		}
		timeUsec, _ := strconv.ParseInt(stringFromAnyBQ(values["time_usec"]), 10, 64)
		eventTime := time.UnixMicro(timeUsec).UTC()
		rowHash := stringFromAnyBQ(values["row_hash"])
		if rowHash == "" {
			sum := sha256.Sum256([]byte(rowJSON))
			rowHash = hex.EncodeToString(sum[:])
		}
		out = append(out, bigQueryActivityRow{
			RowJSON:    rowJSON,
			RowHash:    rowHash,
			RecordType: strings.ToLower(stringFromAnyBQ(values["record_type"])),
			EventName:  stringFromAnyBQ(values["event_name"]),
			EventType:  stringFromAnyBQ(values["event_type"]),
			Email:      stringFromAnyBQ(values["email"]),
			IPAddress:  stringFromAnyBQ(values["ip_address"]),
			EventTime:  eventTime,
			Raw:        raw,
		})
	}
	return out, nil
}

func intFromFirstField(response bigQueryQueryResponse) int {
	if len(response.Rows) == 0 || len(response.Rows[0].F) == 0 {
		return 0
	}
	value, _ := strconv.Atoi(stringFromAnyBQ(response.Rows[0].F[0].V))
	return value
}

func stringFromAnyBQ(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return fmt.Sprint(typed)
	}
}

func (cfg BigQueryConfig) validate() error {
	if !bigQueryIdentifierPattern.MatchString(cfg.ProjectID) && !regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`).MatchString(cfg.ProjectID) {
		return errors.New("GCP project ID is invalid")
	}
	if !bigQueryIdentifierPattern.MatchString(cfg.DatasetID) {
		return errors.New("BigQuery dataset ID is invalid")
	}
	if cfg.RawDatasetID != "" && !bigQueryIdentifierPattern.MatchString(cfg.RawDatasetID) {
		return errors.New("Raw BigQuery dataset ID is invalid")
	}
	if cfg.AccessMode != "views" && cfg.AccessMode != "dataset" {
		return errors.New("BigQuery access mode must be views or dataset")
	}
	if strings.TrimSpace(cfg.Location) == "" || strings.ContainsAny(cfg.Location, " \t\r\n") {
		return errors.New("BigQuery location is invalid")
	}
	if strings.TrimSpace(cfg.ServiceAccountEmail) == "" || !strings.HasSuffix(cfg.ServiceAccountEmail, ".iam.gserviceaccount.com") {
		return errors.New("Service account email is invalid")
	}
	if !strings.HasPrefix(cfg.WorkloadIdentityProvider, "projects/") || !strings.Contains(cfg.WorkloadIdentityProvider, "/workloadIdentityPools/") || !strings.Contains(cfg.WorkloadIdentityProvider, "/providers/") {
		return errors.New("Workload identity provider resource is invalid")
	}
	return nil
}

func (cfg BigQueryConfig) activityTable() string {
	if cfg.AccessMode == "views" {
		return "aperio_activity"
	}
	return "activity"
}

func (cfg BigQueryConfig) partitionTimeExpression(alias string) string {
	if cfg.AccessMode == "views" {
		return alias + ".aperio_partition_time"
	}
	return alias + "._PARTITIONTIME"
}

func (cfg BigQueryConfig) activityQuery(recordType string, limit int) (string, error) {
	if !bigQueryIdentifierPattern.MatchString(recordType) {
		return "", errors.New("record type is invalid")
	}
	if limit <= 0 {
		limit = defaultBigQueryPageSize
	}
	return fmt.Sprintf(`WITH candidate AS (
SELECT
  TO_JSON_STRING(t) AS row_json,
  TO_HEX(SHA256(TO_JSON_STRING(t))) AS row_hash,
  CAST(t.time_usec AS INT64) AS time_usec_int,
  CAST(t.time_usec AS STRING) AS time_usec,
  CAST(t.record_type AS STRING) AS record_type,
  CAST(t.event_name AS STRING) AS event_name,
  CAST(t.event_type AS STRING) AS event_type,
  CAST(t.email AS STRING) AS email,
  CAST(t.ip_address AS STRING) AS ip_address
FROM `+"`%s.%s.%s`"+` AS t
WHERE t.record_type = @record_type
  AND %s >= TIMESTAMP_TRUNC(@from_partition, DAY)
  AND t.time_usec >= @from_usec
)
SELECT row_json, row_hash, time_usec, record_type, event_name, event_type, email, ip_address
FROM candidate
ORDER BY CASE
  WHEN @cursor_usec = 0
    OR time_usec_int > @cursor_usec
    OR (time_usec_int = @cursor_usec AND row_hash > @cursor_hash)
  THEN 0
  ELSE 1
END, time_usec_int ASC, row_hash ASC
LIMIT %d`, cfg.ProjectID, cfg.DatasetID, cfg.activityTable(), cfg.partitionTimeExpression("t"), limit), nil
}

type wifTokenSource struct {
	httpClient        *http.Client
	subjectTokenValue string
	subjectTokenFile  string
	stsTokenURL       string
	iamCredentialsURL string
}

func newWIFTokenSourceFromEnv() *wifTokenSource {
	return &wifTokenSource{
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		subjectTokenValue: strings.TrimSpace(os.Getenv("APERIO_GOOGLE_WORKSPACE_WIF_SUBJECT_TOKEN")),
		subjectTokenFile:  strings.TrimSpace(os.Getenv("APERIO_GOOGLE_WORKSPACE_WIF_SUBJECT_TOKEN_FILE")),
		stsTokenURL:       envDefault("APERIO_GOOGLE_STS_TOKEN_URL", defaultGoogleSTSTokenURL),
		iamCredentialsURL: envDefault("APERIO_GOOGLE_IAM_CREDENTIALS_BASE_URL", defaultGoogleIAMCredentialsURL),
	}
}

func (s *wifTokenSource) subjectToken() (string, error) {
	if strings.TrimSpace(s.subjectTokenValue) != "" {
		return strings.TrimSpace(s.subjectTokenValue), nil
	}
	if strings.TrimSpace(s.subjectTokenFile) != "" {
		raw, err := os.ReadFile(s.subjectTokenFile)
		if err != nil {
			return "", fmt.Errorf("read WIF subject token file: %w", err)
		}
		if strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw)), nil
		}
	}
	return "", errors.New("runtime WIF subject token is not configured")
}

func (s *wifTokenSource) accessToken(ctx context.Context, cfg BigQueryConfig, subjectToken string) (string, error) {
	stsToken, err := s.exchangeSubjectToken(ctx, cfg.WorkloadIdentityProvider, subjectToken)
	if err != nil {
		return "", err
	}
	return s.impersonateServiceAccount(ctx, cfg.ServiceAccountEmail, stsToken)
}

func (s *wifTokenSource) exchangeSubjectToken(ctx context.Context, provider, subjectToken string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("audience", "//iam.googleapis.com/"+provider)
	form.Set("scope", defaultBigQueryTokenScope)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	form.Set("subject_token", subjectToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.stsTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("sts token exchange %d: %s", resp.StatusCode, truncate(body, 240))
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("STS response missing access_token")
	}
	return decoded.AccessToken, nil
}

func (s *wifTokenSource) impersonateServiceAccount(ctx context.Context, serviceAccountEmail, stsToken string) (string, error) {
	body, _ := json.Marshal(map[string]any{"scope": []string{defaultBigQueryTokenScope}})
	endpoint := strings.TrimRight(s.iamCredentialsURL, "/") + "/projects/-/serviceAccounts/" + url.PathEscape(serviceAccountEmail) + ":generateAccessToken"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+stsToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("service account impersonation %d: %s", resp.StatusCode, truncate(raw, 240))
	}
	var decoded struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("IAMCredentials response missing accessToken")
	}
	return decoded.AccessToken, nil
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return strings.TrimRight(value, "/")
	}
	return fallback
}

func truncate(raw []byte, max int) string {
	text := string(raw)
	if len(text) > max {
		return text[:max]
	}
	return text
}
