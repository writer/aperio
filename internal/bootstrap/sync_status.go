package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/googleworkspacepoller"
	"github.com/writer/aperio/internal/syncstate"
	"github.com/writer/aperio/internal/syncwake"
)

const (
	sourceGoogleReports   = "google_reports"
	sourceGoogleBigQuery  = "google_bigquery"
	sourceGoogleDirectory = "google_directory"
	sourceGoogleOAuth     = "google_oauth"
	sourceIngestionQueue  = "ingestion_queue"
	backfillQueuedPrefix  = syncstate.BackfillQueuedPrefix
)

type integrationSyncContext struct {
	ID              string
	Provider        string
	Status          string
	BigQueryEnabled bool
}

type queueCounts struct {
	Queued     int64
	Running    int64
	Failed     int64
	DeadLetter int64
	Succeeded  int64
}

func (a *App) getIntegrationSyncStatus(ctx context.Context, integrationID string, auth compatAuth) (*aperiov1.IntegrationSyncStatus, error) {
	integ, err := a.integrationSyncContext(ctx, integrationID, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	status := &aperiov1.IntegrationSyncStatus{
		IntegrationId: integ.ID,
		Provider:      integ.Provider,
		GeneratedAt:   now.Format(time.RFC3339Nano),
		Sources:       []*aperiov1.IntegrationSourceSyncState{},
	}
	queues, err := a.integrationQueueCounts(ctx, integ.ID, auth.OrganizationID)
	if err != nil {
		return nil, internalServerError("get integration sync queue counts", err)
	}
	if integ.Provider == "GOOGLE_WORKSPACE" {
		reports, err := a.googleReportsSyncStates(ctx, integ.ID, queues, now)
		if err != nil {
			return nil, internalServerError("get Google Reports sync status", err)
		}
		status.Sources = append(status.Sources, reports...)
		if integ.BigQueryEnabled {
			bigQuery, err := a.googleBigQuerySyncStates(ctx, integ.ID, queues, now)
			if err != nil {
				return nil, internalServerError("get Google BigQuery sync status", err)
			}
			status.Sources = append(status.Sources, bigQuery...)
		}
		directory, err := a.googleDirectorySyncState(ctx, integ.ID, now)
		if err != nil {
			return nil, internalServerError("get Google Directory sync status", err)
		}
		oauth, err := a.googleOAuthSyncState(ctx, integ.ID, now)
		if err != nil {
			return nil, internalServerError("get Google OAuth sync status", err)
		}
		status.Sources = append(status.Sources, directory, oauth)
	}
	status.Sources = append(status.Sources, ingestionQueueSyncStates(queues)...)
	if integ.Status != "CONNECTED" {
		for _, source := range status.Sources {
			if source.SourceKind == sourceIngestionQueue {
				continue
			}
			source.SyncNowSupported = false
			source.BackfillSupported = false
		}
	}
	return status, nil
}

func (a *App) runIntegrationSourceSync(ctx context.Context, integrationID, sourceKind, streamName string, auth compatAuth) (*aperiov1.IntegrationSourceSyncAction, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	integ, err := a.integrationSyncContext(ctx, integrationID, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	if integ.Provider != "GOOGLE_WORKSPACE" {
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("source sync is not implemented for %s yet", strings.ReplaceAll(integ.Provider, "_", " ")))
	}
	if integ.Status != "CONNECTED" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("integration is not connected"))
	}
	kind := normalizeSourceKind(sourceKind)
	stream := strings.ToLower(strings.TrimSpace(streamName))
	if err := validateSourceStream(kind, stream, integ.BigQueryEnabled); err != nil {
		return nil, err
	}
	channels, err := syncWakeChannelsForSource(kind, integ.BigQueryEnabled)
	if err != nil {
		return nil, err
	}
	for _, channel := range channels {
		payload := integ.ID
		if stream != "" && (kind == sourceGoogleReports || kind == sourceGoogleBigQuery) {
			payload = syncwake.Encode(integ.ID, stream)
		} else if kind == "all" && channel == GoogleWorkspaceDirectorySyncWakeChannel {
			payload = syncwake.Encode(integ.ID, syncwake.ModeOAuthAfterDirectorySync)
		}
		if _, err := a.db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, channel, payload); err != nil {
			return nil, internalServerError("run integration source sync", err)
		}
	}
	audit := map[string]any{
		"sourceKind": kind,
		"streamName": stream,
		"channels":   channels,
	}
	if kind == "all" {
		audit["chainedChannels"] = []string{GoogleWorkspaceOAuthSyncWakeChannel}
	}
	a.writeCompatAudit(ctx, auth, "integration.source_sync.requested", "integration_connection", integ.ID, audit)
	return &aperiov1.IntegrationSourceSyncAction{
		IntegrationId: integ.ID,
		SourceKind:    kind,
		StreamName:    stream,
		Queued:        true,
		Message:       "Source sync queued",
		RequestedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (a *App) backfillIntegrationSource(ctx context.Context, integrationID, sourceKind, streamName, fromTime string, auth compatAuth) (*aperiov1.IntegrationSourceSyncAction, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	integ, err := a.integrationSyncContext(ctx, integrationID, auth.OrganizationID)
	if err != nil {
		return nil, err
	}
	if integ.Provider != "GOOGLE_WORKSPACE" {
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("backfill is not implemented for %s yet", strings.ReplaceAll(integ.Provider, "_", " ")))
	}
	if integ.Status != "CONNECTED" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("integration is not connected"))
	}
	kind := normalizeSourceKind(sourceKind)
	stream := strings.ToLower(strings.TrimSpace(streamName))
	if stream == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("stream name is required"))
	}
	from, err := parseBackfillTime(fromTime)
	if err != nil {
		return nil, err
	}
	switch kind {
	case sourceGoogleReports:
		if !slices.Contains(googleworkspacepoller.DefaultApplications, stream) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported Google Reports stream"))
		}
		if _, err := a.db.ExecContext(ctx, `
			INSERT INTO google_workspace_sync_cursors
				(integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
			VALUES ($1, $2, $3, '', NOW(), $4)
			ON CONFLICT (integration_id, application) DO UPDATE SET
				last_event_time = EXCLUDED.last_event_time,
				last_unique_qualifier = '',
				last_polled_at = NOW(),
				last_error = EXCLUDED.last_error
		`, integ.ID, stream, from.UTC(), queuedBackfillMessage(from)); err != nil {
			return nil, internalServerError("backfill Google Reports source", err)
		}
		if _, err := a.db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, GoogleWorkspaceSyncWakeChannel, syncwake.Encode(integ.ID, stream)); err != nil {
			return nil, internalServerError("notify Google Reports backfill", err)
		}
	case sourceGoogleBigQuery:
		if !integ.BigQueryEnabled {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("BigQuery ingestion is not configured"))
		}
		if !slices.Contains(googleworkspacepoller.DefaultApplications, stream) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported BigQuery stream"))
		}
		if _, err := a.db.ExecContext(ctx, `
			INSERT INTO google_workspace_bigquery_sync_cursors
				(integration_id, record_type, last_event_time, last_row_hash, last_polled_at, last_row_count, last_error)
			VALUES ($1, $2, $3, '', NOW(), 0, $4)
			ON CONFLICT (integration_id, record_type) DO UPDATE SET
				last_event_time = EXCLUDED.last_event_time,
				last_row_hash = '',
				last_polled_at = NOW(),
				last_row_count = 0,
				last_error = EXCLUDED.last_error
		`, integ.ID, stream, from.UTC(), queuedBackfillMessage(from)); err != nil {
			return nil, internalServerError("backfill Google BigQuery source", err)
		}
		if _, err := a.db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, GoogleWorkspaceBigQuerySyncWakeChannel, syncwake.Encode(integ.ID, stream)); err != nil {
			return nil, internalServerError("notify Google BigQuery backfill", err)
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("backfill is only supported for cursor-based Google Reports and BigQuery streams"))
	}
	a.writeCompatAudit(ctx, auth, "integration.source_backfill.requested", "integration_connection", integ.ID, map[string]any{
		"sourceKind": kind,
		"streamName": stream,
		"fromTime":   from.UTC().Format(time.RFC3339Nano),
	})
	return &aperiov1.IntegrationSourceSyncAction{
		IntegrationId: integ.ID,
		SourceKind:    kind,
		StreamName:    stream,
		Queued:        true,
		Message:       "Backfill cursor updated and source sync queued",
		RequestedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (a *App) integrationSyncContext(ctx context.Context, integrationID, organizationID string) (integrationSyncContext, error) {
	id := strings.TrimSpace(integrationID)
	if id == "" {
		return integrationSyncContext{}, connect.NewError(connect.CodeInvalidArgument, errors.New("integration id is required"))
	}
	var out integrationSyncContext
	err := a.db.QueryRowContext(ctx, `
		SELECT id, provider::text, status::text,
		       google_workspace_bigquery_project_id IS NOT NULL
		       AND google_workspace_bigquery_dataset_id IS NOT NULL
		       AND google_workspace_bigquery_location IS NOT NULL
		       AND google_workspace_bigquery_service_account_email IS NOT NULL
		       AND google_workspace_bigquery_wif_provider IS NOT NULL
		       AND google_workspace_bigquery_access_mode IS NOT NULL
		FROM integration_connections
		WHERE id = $1 AND organization_id = $2
	`, id, organizationID).Scan(&out.ID, &out.Provider, &out.Status, &out.BigQueryEnabled)
	if err == sql.ErrNoRows {
		return integrationSyncContext{}, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
	}
	if err != nil {
		return integrationSyncContext{}, internalServerError("load integration sync context", err)
	}
	return out, nil
}

func (a *App) integrationQueueCounts(ctx context.Context, integrationID, organizationID string) (map[string]queueCounts, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT source,
		       COUNT(*) FILTER (WHERE status = 'QUEUED') AS queued,
		       COUNT(*) FILTER (WHERE status = 'RUNNING') AS running,
		       COUNT(*) FILTER (WHERE status = 'FAILED') AS failed,
		       COUNT(*) FILTER (WHERE status = 'DEAD_LETTER') AS dead_letter,
		       COUNT(*) FILTER (WHERE status = 'SUCCEEDED') AS succeeded
		FROM ingestion_jobs
		WHERE integration_id = $1 AND organization_id = $2
		GROUP BY source
	`, integrationID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]queueCounts{}
	for rows.Next() {
		var source string
		var counts queueCounts
		if err := rows.Scan(&source, &counts.Queued, &counts.Running, &counts.Failed, &counts.DeadLetter, &counts.Succeeded); err != nil {
			return nil, err
		}
		out[source] = counts
	}
	return out, rows.Err()
}

func (a *App) googleReportsSyncStates(ctx context.Context, integrationID string, queues map[string]queueCounts, now time.Time) ([]*aperiov1.IntegrationSourceSyncState, error) {
	states := make(map[string]*aperiov1.IntegrationSourceSyncState, len(googleworkspacepoller.DefaultApplications))
	for _, app := range googleworkspacepoller.DefaultApplications {
		queueSource := "google.reports." + app
		states[app] = newSyncState(sourceGoogleReports, app, "Reports API: "+app, queueSource, queues[queueSource], true, true)
	}
	rows, err := a.db.QueryContext(ctx, `
		SELECT application, last_event_time, last_polled_at, COALESCE(last_error, '')
		FROM google_workspace_sync_cursors
		WHERE integration_id = $1
	`, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var app, lastErr string
		var cursor, attempt time.Time
		if err := rows.Scan(&app, &cursor, &attempt, &lastErr); err != nil {
			return nil, err
		}
		state, ok := states[app]
		if !ok {
			queueSource := "google.reports." + app
			state = newSyncState(sourceGoogleReports, app, "Reports API: "+app, queueSource, queues[queueSource], true, true)
			states[app] = state
		}
		applyCursorState(state, cursor, attempt, lastErr, 0, now)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mapValues(states), nil
}

func (a *App) googleBigQuerySyncStates(ctx context.Context, integrationID string, queues map[string]queueCounts, now time.Time) ([]*aperiov1.IntegrationSourceSyncState, error) {
	states := make(map[string]*aperiov1.IntegrationSourceSyncState, len(googleworkspacepoller.DefaultApplications))
	for _, recordType := range googleworkspacepoller.DefaultApplications {
		queueSource := "google.bigquery." + recordType
		states[recordType] = newSyncState(sourceGoogleBigQuery, recordType, "BigQuery export: "+recordType, queueSource, queues[queueSource], true, true)
	}
	rows, err := a.db.QueryContext(ctx, `
		SELECT record_type, last_event_time, last_polled_at, last_row_count, COALESCE(last_error, '')
		FROM google_workspace_bigquery_sync_cursors
		WHERE integration_id = $1
	`, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var recordType, lastErr string
		var cursor, attempt time.Time
		var rowCount int64
		if err := rows.Scan(&recordType, &cursor, &attempt, &rowCount, &lastErr); err != nil {
			return nil, err
		}
		state, ok := states[recordType]
		if !ok {
			queueSource := "google.bigquery." + recordType
			state = newSyncState(sourceGoogleBigQuery, recordType, "BigQuery export: "+recordType, queueSource, queues[queueSource], true, true)
			states[recordType] = state
		}
		applyCursorState(state, cursor, attempt, lastErr, rowCount, now)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mapValues(states), nil
}

func (a *App) googleDirectorySyncState(ctx context.Context, integrationID string, now time.Time) (*aperiov1.IntegrationSourceSyncState, error) {
	state := newSyncState(sourceGoogleDirectory, "users", "Directory users", "", queueCounts{}, true, false)
	var syncedAt time.Time
	var userCount int64
	var lastErr string
	err := a.db.QueryRowContext(ctx, `
		SELECT last_synced_at, last_user_count, COALESCE(last_error, '')
		FROM google_workspace_directory_sync_cursors
		WHERE integration_id = $1
	`, integrationID).Scan(&syncedAt, &userCount, &lastErr)
	if err == nil {
		cursor := syncedAt
		if strings.TrimSpace(lastErr) != "" && userCount == 0 {
			cursor = time.Time{}
		}
		applyCursorState(state, cursor, syncedAt, lastErr, userCount, now)
		return state, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	return nil, err
}

func (a *App) googleOAuthSyncState(ctx context.Context, integrationID string, now time.Time) (*aperiov1.IntegrationSourceSyncState, error) {
	state := newSyncState(sourceGoogleOAuth, "grants", "OAuth app grants", "", queueCounts{}, true, false)
	var syncedAt time.Time
	var appCount, grantCount int64
	var lastErr string
	err := a.db.QueryRowContext(ctx, `
		SELECT last_synced_at, last_app_count, last_grant_count, COALESCE(last_error, '')
		FROM google_workspace_oauth_sync_cursors
		WHERE integration_id = $1
	`, integrationID).Scan(&syncedAt, &appCount, &grantCount, &lastErr)
	if err == nil {
		cursor := syncedAt
		if strings.TrimSpace(lastErr) != "" && appCount == 0 && grantCount == 0 {
			cursor = time.Time{}
		}
		applyCursorState(state, cursor, syncedAt, lastErr, grantCount, now)
		return state, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	return nil, err
}

func ingestionQueueSyncStates(queues map[string]queueCounts) []*aperiov1.IntegrationSourceSyncState {
	out := make([]*aperiov1.IntegrationSourceSyncState, 0, len(queues))
	for source, counts := range queues {
		state := newSyncState(sourceIngestionQueue, source, "Ingestion queue: "+source, source, counts, false, false)
		state.Status = queueStatus(counts)
		out = append(out, state)
	}
	return out
}

func newSyncState(kind, stream, display, queueSource string, counts queueCounts, syncNow, backfill bool) *aperiov1.IntegrationSourceSyncState {
	return &aperiov1.IntegrationSourceSyncState{
		SourceKind:        kind,
		StreamName:        stream,
		DisplayName:       display,
		Status:            "pending",
		QueueSource:       queueSource,
		RowsEnqueued:      counts.Queued + counts.Running + counts.Failed + counts.DeadLetter + counts.Succeeded,
		QueueQueued:       counts.Queued,
		QueueRunning:      counts.Running,
		QueueFailed:       counts.Failed,
		QueueDeadLetter:   counts.DeadLetter,
		QueueSucceeded:    counts.Succeeded,
		SyncNowSupported:  syncNow,
		BackfillSupported: backfill,
	}
}

func applyCursorState(state *aperiov1.IntegrationSourceSyncState, cursor, attempt time.Time, lastErr string, rowsSeen int64, now time.Time) {
	if !cursor.IsZero() {
		state.CursorTime = cursor.UTC().Format(time.RFC3339Nano)
		state.LagSeconds = int64(now.Sub(cursor.UTC()).Seconds())
		if state.LagSeconds < 0 {
			state.LagSeconds = 0
		}
	}
	if !attempt.IsZero() {
		state.LastAttemptAt = attempt.UTC().Format(time.RFC3339Nano)
	}
	state.RowsSeen = rowsSeen
	if isQueuedBackfill(lastErr) {
		state.Status = "queued"
		return
	}
	if strings.TrimSpace(lastErr) != "" {
		state.Status = "error"
		state.LastError = lastErr
		return
	}
	if !attempt.IsZero() {
		state.Status = "healthy"
		state.LastSuccessAt = attempt.UTC().Format(time.RFC3339Nano)
	}
}

func mapValues(values map[string]*aperiov1.IntegrationSourceSyncState) []*aperiov1.IntegrationSourceSyncState {
	out := make([]*aperiov1.IntegrationSourceSyncState, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b *aperiov1.IntegrationSourceSyncState) int {
		if a.SourceKind != b.SourceKind {
			return strings.Compare(a.SourceKind, b.SourceKind)
		}
		return strings.Compare(a.StreamName, b.StreamName)
	})
	return out
}

func queueStatus(counts queueCounts) string {
	if counts.DeadLetter > 0 || counts.Failed > 0 {
		return "error"
	}
	if counts.Running > 0 {
		return "running"
	}
	if counts.Queued > 0 {
		return "queued"
	}
	return "healthy"
}

func normalizeSourceKind(sourceKind string) string {
	kind := strings.ToLower(strings.TrimSpace(sourceKind))
	if kind == "" || kind == "all" {
		return "all"
	}
	return kind
}

func validateSourceStream(kind, stream string, bigQueryEnabled bool) error {
	if stream == "" {
		return nil
	}
	switch kind {
	case "all":
		return connect.NewError(connect.CodeInvalidArgument, errors.New("stream name is not supported for all sources"))
	case sourceGoogleReports:
		if !slices.Contains(googleworkspacepoller.DefaultApplications, stream) {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported Google Reports stream"))
		}
	case sourceGoogleBigQuery:
		if !bigQueryEnabled {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("BigQuery ingestion is not configured"))
		}
		if !slices.Contains(googleworkspacepoller.DefaultApplications, stream) {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported BigQuery stream"))
		}
	case sourceGoogleDirectory:
		if stream != "users" {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported Google Directory stream"))
		}
	case sourceGoogleOAuth:
		if stream != "grants" {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported Google OAuth stream"))
		}
	}
	return nil
}

func queuedBackfillMessage(from time.Time) string {
	return syncstate.BackfillQueuedMessage(from)
}

func isQueuedBackfill(lastErr string) bool {
	return syncstate.IsBackfillQueued(lastErr)
}

func syncWakeChannelsForSource(kind string, bigQueryEnabled bool) ([]string, error) {
	switch kind {
	case "all":
		channels := []string{
			GoogleWorkspaceSyncWakeChannel,
			GoogleWorkspaceDirectorySyncWakeChannel,
		}
		if bigQueryEnabled {
			channels = append(channels, GoogleWorkspaceBigQuerySyncWakeChannel)
		}
		return channels, nil
	case sourceGoogleReports:
		return []string{GoogleWorkspaceSyncWakeChannel}, nil
	case sourceGoogleBigQuery:
		if !bigQueryEnabled {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("BigQuery ingestion is not configured"))
		}
		return []string{GoogleWorkspaceBigQuerySyncWakeChannel}, nil
	case sourceGoogleDirectory:
		return []string{GoogleWorkspaceDirectorySyncWakeChannel}, nil
	case sourceGoogleOAuth:
		return []string{GoogleWorkspaceOAuthSyncWakeChannel}, nil
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported source kind"))
	}
}

func parseBackfillTime(value string) (time.Time, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return time.Time{}, connect.NewError(connect.CodeInvalidArgument, errors.New("from time is required"))
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return time.Time{}, connect.NewError(connect.CodeInvalidArgument, errors.New("from time must be RFC3339"))
	}
	if parsed.After(time.Now().Add(1 * time.Minute)) {
		return time.Time{}, connect.NewError(connect.CodeInvalidArgument, errors.New("from time cannot be in the future"))
	}
	return parsed.UTC(), nil
}

func (a *App) rateLimitSourceSync(ctx context.Context, header http.Header, peerAddr, integrationID, action string, auth compatAuth) error {
	path := "/api/v1/integrations/" + url.PathEscape(integrationID) + "/" + action
	return a.compatRateLimit(ctx, header, peerAddr, http.MethodPost, path, typedRateLimitSubjectBody(auth))
}
