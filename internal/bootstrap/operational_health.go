package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/telemetry"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	operatorHealthPath      = "/api/v1/operator/health"
	operatorHealthRuleLimit = 20
)

type operationalConnectorHealth struct {
	IntegrationID     string     `json:"integrationId"`
	Provider          string     `json:"provider"`
	DisplayName       string     `json:"displayName"`
	IntegrationStatus string     `json:"integrationStatus"`
	Source            string     `json:"source,omitempty"`
	RunStatus         string     `json:"runStatus,omitempty"`
	LastStartedAt     *time.Time `json:"lastStartedAt,omitempty"`
	LastCompletedAt   *time.Time `json:"lastCompletedAt,omitempty"`
	Error             string     `json:"error,omitempty"`
	AgeSeconds        int64      `json:"ageSeconds"`
}

type operationalQueueHealth struct {
	Queued              int64 `json:"queued"`
	Running             int64 `json:"running"`
	Failed              int64 `json:"failed"`
	DeadLetter          int64 `json:"deadLetter"`
	Succeeded           int64 `json:"succeeded"`
	OldestQueuedAgeSecs int64 `json:"oldestQueuedAgeSeconds"`
}

type operationalSiemHealth struct {
	Pending          int64 `json:"pending"`
	Processing       int64 `json:"processing"`
	Failed           int64 `json:"failed"`
	DeadLetter       int64 `json:"deadLetter"`
	Delivered        int64 `json:"delivered"`
	DestinationError int64 `json:"destinationErrors"`
}

type operationalRuleRun struct {
	Provider       string     `json:"provider"`
	RuleKey        string     `json:"ruleKey"`
	RuleVersion    string     `json:"ruleVersion"`
	Status         string     `json:"status"`
	RulesEvaluated int32      `json:"rulesEvaluated"`
	FindingsCount  int32      `json:"findingsCount"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	Error          string     `json:"error,omitempty"`
}

type operationalHealth struct {
	Status         string                       `json:"status"`
	CheckedAt      time.Time                    `json:"checkedAt"`
	Connectors     []operationalConnectorHealth `json:"connectors"`
	IngestionQueue operationalQueueHealth       `json:"ingestionQueue"`
	SIEM           operationalSiemHealth        `json:"siem"`
	RecentRuleRuns []operationalRuleRun         `json:"recentRuleRuns"`
}

// GetOperationalHealth returns tenant-scoped connector, queue, SIEM, and rule
// receipts. Unlike /readyz and CheckHealth, this endpoint is deliberately
// authenticated because its state is an operator view rather than a process
// liveness signal.
func (a *App) GetOperationalHealth(ctx context.Context, req *connect.Request[aperiov1.GetOperationalHealthRequest]) (*connect.Response[aperiov1.GetOperationalHealthResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	health, err := a.operationalHealth(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("operational health unavailable"))
	}
	return connect.NewResponse(&aperiov1.GetOperationalHealthResponse{Data: health.toProto()}), nil
}

func (a *App) handleOperatorHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if a.db == nil {
		writeError(w, http.StatusServiceUnavailable, "authentication store unavailable")
		return
	}
	organizationID, err := a.organizationIDFromSession(r.Context(), r.Header)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errInvalidSession) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "authentication store unavailable")
		return
	}
	health, err := a.operationalHealth(r.Context(), organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "operational health unavailable")
		return
	}
	writeJSON(w, http.StatusOK, health)
}

// handleMetrics exposes process and aggregate queue metrics in the standard
// Prometheus text format. It intentionally carries no tenant labels; tenant
// detail belongs behind the authenticated operator endpoint above. The
// aggregate counts are still operational data, so the endpoint is disabled
// until a dedicated scrape credential is configured.
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if a.cfg.MetricsToken == "" {
		http.NotFound(w, r)
		return
	}
	const bearerPrefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	providedDigest := sha256.Sum256([]byte(strings.TrimPrefix(authorization, bearerPrefix)))
	expectedDigest := sha256.Sum256([]byte(a.cfg.MetricsToken))
	if !strings.HasPrefix(authorization, bearerPrefix) || subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="aperio-metrics"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	metricsCtx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	a.refreshOperationalMetrics(metricsCtx)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(telemetry.RenderPrometheus()))
}

func (a *App) operationalHealth(ctx context.Context, organizationID string) (operationalHealth, error) {
	health := operationalHealth{
		Status: "ok", CheckedAt: time.Now().UTC(),
		Connectors: []operationalConnectorHealth{}, RecentRuleRuns: []operationalRuleRun{},
	}
	connectors, err := a.operationalConnectors(ctx, organizationID)
	if err != nil {
		return health, err
	}
	health.Connectors = connectors
	queue, err := a.operationalIngestionQueue(ctx, organizationID)
	if err != nil {
		return health, err
	}
	health.IngestionQueue = queue
	siem, err := a.operationalSiemQueue(ctx, organizationID)
	if err != nil {
		return health, err
	}
	health.SIEM = siem
	runs, err := a.operationalRuleRuns(ctx, organizationID)
	if err != nil {
		return health, err
	}
	health.RecentRuleRuns = runs
	for _, connector := range connectors {
		if connector.RunStatus == "FAILED" || connector.RunStatus == "" && connector.IntegrationStatus == "ERROR" {
			health.Status = "degraded"
			break
		}
	}
	if queue.DeadLetter > 0 || siem.DeadLetter > 0 || siem.DestinationError > 0 {
		health.Status = "degraded"
	}
	return health, nil
}

func (a *App) operationalConnectors(ctx context.Context, organizationID string) ([]operationalConnectorHealth, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT ic.id, ic.provider::text, ic.display_name, ic.status::text,
		       COALESCE(latest.source, ''), COALESCE(latest.status::text, ''),
		       latest.started_at, latest.completed_at, COALESCE(latest.error_message, '')
		FROM integration_connections ic
		LEFT JOIN LATERAL (
			SELECT DISTINCT ON (csr.source)
			       csr.source, csr.status, csr.started_at, csr.completed_at, csr.error_message
			FROM connector_sync_runs csr
			WHERE csr.organization_id = ic.organization_id AND csr.integration_id = ic.id
			ORDER BY csr.source, csr.started_at DESC, csr.id DESC
		) latest ON TRUE
		WHERE ic.organization_id = $1
		ORDER BY ic.created_at ASC, ic.id ASC, COALESCE(latest.source, '') ASC
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	result := make([]operationalConnectorHealth, 0)
	for rows.Next() {
		var item operationalConnectorHealth
		var startedAt, completedAt sql.NullTime
		if err := rows.Scan(&item.IntegrationID, &item.Provider, &item.DisplayName, &item.IntegrationStatus, &item.Source, &item.RunStatus, &startedAt, &completedAt, &item.Error); err != nil {
			return nil, err
		}
		if startedAt.Valid {
			value := startedAt.Time.UTC()
			item.LastStartedAt = &value
			item.AgeSeconds = maxAgeSeconds(now, value)
		}
		if completedAt.Valid {
			value := completedAt.Time.UTC()
			item.LastCompletedAt = &value
			item.AgeSeconds = maxAgeSeconds(now, value)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (a *App) operationalIngestionQueue(ctx context.Context, organizationID string) (operationalQueueHealth, error) {
	var queue operationalQueueHealth
	rows, err := a.db.QueryContext(ctx, `
		SELECT status::text, COUNT(*)
		FROM ingestion_jobs
		WHERE organization_id = $1
		GROUP BY status::text
	`, organizationID)
	if err != nil {
		return queue, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return queue, err
		}
		switch status {
		case "QUEUED":
			queue.Queued = count
		case "RUNNING":
			queue.Running = count
		case "FAILED":
			queue.Failed = count
		case "DEAD_LETTER":
			queue.DeadLetter = count
		case "SUCCEEDED":
			queue.Succeeded = count
		}
	}
	if err := rows.Err(); err != nil {
		return queue, err
	}
	if err := a.db.QueryRowContext(ctx, `
		SELECT COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at))::bigint, 0)
		FROM ingestion_jobs
		WHERE organization_id = $1 AND status = 'QUEUED'
	`, organizationID).Scan(&queue.OldestQueuedAgeSecs); err != nil {
		return queue, err
	}
	return queue, nil
}

func (a *App) operationalSiemQueue(ctx context.Context, organizationID string) (operationalSiemHealth, error) {
	var health operationalSiemHealth
	rows, err := a.db.QueryContext(ctx, `
		SELECT status::text, COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1
		GROUP BY status::text
	`, organizationID)
	if err != nil {
		return health, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return health, err
		}
		switch status {
		case "PENDING":
			health.Pending = count
		case "PROCESSING":
			health.Processing = count
		case "FAILED":
			health.Failed = count
		case "DEAD_LETTER":
			health.DeadLetter = count
		case "DELIVERED":
			health.Delivered = count
		}
	}
	if err := rows.Err(); err != nil {
		return health, err
	}
	if err := a.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM siem_destinations
		WHERE organization_id = $1 AND status = 'ERROR'
	`, organizationID).Scan(&health.DestinationError); err != nil {
		return health, err
	}
	return health, nil
}

func (a *App) operationalRuleRuns(ctx context.Context, organizationID string) ([]operationalRuleRun, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT provider::text, rule_key, rule_version, status::text,
		       rules_evaluated, findings_count, started_at, completed_at, COALESCE(error_message, '')
		FROM rule_runs
		WHERE organization_id = $1
		ORDER BY started_at DESC
		LIMIT $2
	`, organizationID, operatorHealthRuleLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := make([]operationalRuleRun, 0, operatorHealthRuleLimit)
	for rows.Next() {
		var run operationalRuleRun
		var completedAt sql.NullTime
		if err := rows.Scan(&run.Provider, &run.RuleKey, &run.RuleVersion, &run.Status, &run.RulesEvaluated, &run.FindingsCount, &run.StartedAt, &completedAt, &run.Error); err != nil {
			return nil, err
		}
		run.StartedAt = run.StartedAt.UTC()
		if completedAt.Valid {
			value := completedAt.Time.UTC()
			run.CompletedAt = &value
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (health operationalHealth) toProto() *aperiov1.OperationalHealth {
	result := &aperiov1.OperationalHealth{Status: health.Status, CheckedAt: timestamppb.New(health.CheckedAt), IngestionQueue: &aperiov1.IngestionQueueHealth{
		Queued: health.IngestionQueue.Queued, Running: health.IngestionQueue.Running, Failed: health.IngestionQueue.Failed,
		DeadLetter: health.IngestionQueue.DeadLetter, Succeeded: health.IngestionQueue.Succeeded,
		OldestQueuedAgeSeconds: health.IngestionQueue.OldestQueuedAgeSecs,
	}, Siem: &aperiov1.SiemQueueHealth{
		Pending: health.SIEM.Pending, Processing: health.SIEM.Processing, Failed: health.SIEM.Failed,
		DeadLetter: health.SIEM.DeadLetter, Delivered: health.SIEM.Delivered, DestinationErrors: health.SIEM.DestinationError,
	}}
	for _, connector := range health.Connectors {
		item := &aperiov1.ConnectorHealth{IntegrationId: connector.IntegrationID, Provider: connector.Provider, DisplayName: connector.DisplayName, IntegrationStatus: connector.IntegrationStatus, Source: connector.Source, RunStatus: connector.RunStatus, Error: connector.Error, AgeSeconds: connector.AgeSeconds}
		if connector.LastStartedAt != nil {
			item.LastStartedAt = timestamppb.New(*connector.LastStartedAt)
		}
		if connector.LastCompletedAt != nil {
			item.LastCompletedAt = timestamppb.New(*connector.LastCompletedAt)
		}
		result.Connectors = append(result.Connectors, item)
	}
	for _, run := range health.RecentRuleRuns {
		item := &aperiov1.RuleRunHealth{Provider: run.Provider, RuleKey: run.RuleKey, RuleVersion: run.RuleVersion, Status: run.Status, RulesEvaluated: run.RulesEvaluated, FindingsCount: run.FindingsCount, Error: run.Error, StartedAt: timestamppb.New(run.StartedAt)}
		if run.CompletedAt != nil {
			item.CompletedAt = timestamppb.New(*run.CompletedAt)
		}
		result.RecentRuleRuns = append(result.RecentRuleRuns, item)
	}
	return result
}

func maxAgeSeconds(now, at time.Time) int64 {
	if at.IsZero() || at.After(now) {
		return 0
	}
	return int64(now.Sub(at) / time.Second)
}

func (a *App) refreshOperationalMetrics(ctx context.Context) {
	if a.db == nil {
		return
	}
	setGroupedMetrics(ctx, a.db, `SELECT status::text, COUNT(*) FROM ingestion_jobs GROUP BY status::text`, "aperio_ingestion_queue_jobs", "status")
	setGroupedMetrics(ctx, a.db, `SELECT status::text, COUNT(*) FROM siem_deliveries GROUP BY status::text`, "aperio_siem_delivery_jobs", "status")
	setGroupedMetrics(ctx, a.db, `SELECT status::text, COUNT(*) FROM connector_sync_runs GROUP BY status::text`, "aperio_connector_sync_runs", "status")
	setGroupedMetrics(ctx, a.db, `SELECT status::text, COUNT(*) FROM rule_runs GROUP BY status::text`, "aperio_rule_runs", "status")
}

func setGroupedMetrics(ctx context.Context, db *sql.DB, query, metricName, labelName string) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return
	}
	defer rows.Close()
	values := map[string]float64{}
	for rows.Next() {
		var status string
		var count float64
		if err := rows.Scan(&status, &count); err != nil {
			return
		}
		values[status] += count
	}
	if rows.Err() == nil {
		telemetry.ReplaceGaugeSnapshot(metricName, labelName, values)
	}
}
