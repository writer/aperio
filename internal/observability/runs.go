// Package observability owns the small durable receipts used by operators to
// distinguish a healthy empty sweep from a worker that never reached a
// terminal state. The helpers are deliberately best-effort: a telemetry write
// must not turn a provider outage into a second outage in the data plane.
package observability

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"

	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/telemetry"
)

const (
	ConnectorSourceGoogleWorkspaceReports   = "google_workspace_reports"
	ConnectorSourceGoogleWorkspaceBigQuery  = "google_workspace_bigquery"
	ConnectorSourceGoogleWorkspaceDirectory = "google_workspace_directory"
	ConnectorSourceGoogleWorkspaceOAuth     = "google_workspace_oauth"
	RulePackBuiltIn                         = "builtin"
	RulePackCustom                          = "custom"
)

// ConnectorSyncRun is a handle for one connector source sweep. A nil handle
// means the receipt could not be inserted; Finish remains safe in that case.
type ConnectorSyncRun struct {
	db             *sql.DB
	id             string
	organizationID string
	integrationID  string
	provider       string
	source         string
	startedAt      time.Time
}

// StartConnectorSyncRun persists a RUNNING receipt before provider work starts.
func StartConnectorSyncRun(ctx context.Context, db *sql.DB, organizationID, integrationID, provider, source string) *ConnectorSyncRun {
	startedAt := time.Now().UTC()
	id, err := prefixedID("csr")
	if err != nil {
		log.Printf("observability: generate connector sync run id failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "connector_sync"})
		return nil
	}
	run := &ConnectorSyncRun{
		db: db, id: id, organizationID: organizationID,
		integrationID: integrationID, provider: provider, source: source,
		startedAt: startedAt,
	}
	if db == nil {
		return nil
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO connector_sync_runs
			(id, organization_id, integration_id, provider, source, status, started_at, created_at)
		VALUES ($1, $2, $3, $4::"SaaSProvider", $5, 'RUNNING'::"ConnectorSyncRunStatus", $6, $6)
	`, run.id, organizationID, integrationID, provider, boundedSource(source), startedAt)
	if err != nil {
		log.Printf("observability: start connector sync run failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "connector_sync"})
		return nil
	}
	telemetry.IncCounter("aperio_connector_sync_runs_total", map[string]string{"provider": provider, "source": boundedSource(source), "outcome": "started"})
	return run
}

// Finish records a terminal connector state. The organization and integration
// predicates make an accidental cross-tenant update impossible.
func (r *ConnectorSyncRun) Finish(ctx context.Context, status string, recordsSeen, recordsQueued int, runErr error) {
	if r == nil || r.db == nil || r.id == "" {
		return
	}
	status = normalizeStatus(status)
	completedAt := time.Now().UTC()
	finishCtx, cancel := terminalContext(ctx)
	defer cancel()
	_, err := r.db.ExecContext(finishCtx, `
		UPDATE connector_sync_runs
		SET status = $1::"ConnectorSyncRunStatus",
			records_seen = $2,
			records_queued = $3,
			error_message = $4,
			completed_at = $5,
			duration_ms = $6
		WHERE id = $7 AND organization_id = $8 AND integration_id = $9
	`, status, nonNegative(recordsSeen), nonNegative(recordsQueued), errorMessage(runErr), completedAt,
		completedAt.Sub(r.startedAt).Milliseconds(), r.id, r.organizationID, r.integrationID)
	if err != nil {
		log.Printf("observability: finish connector sync run failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "connector_sync"})
		return
	}
	telemetry.IncCounter("aperio_connector_sync_runs_total", map[string]string{"provider": r.provider, "source": boundedSource(r.source), "outcome": strings.ToLower(status)})
}

// RuleRun is a handle for one deterministic rule-pack evaluation.
type RuleRun struct {
	db             *sql.DB
	id             string
	organizationID string
	integrationID  string
	provider       string
	ruleKey        string
	rulesEvaluated int
	startedAt      time.Time
}

// StartRuleRun persists a RUNNING receipt before a rule pack is evaluated.
func StartRuleRun(ctx context.Context, db *sql.DB, organizationID, integrationID, provider, ingestionJobID, ruleKey, ruleVersion string, rulesEvaluated int) *RuleRun {
	startedAt := time.Now().UTC()
	id, err := prefixedID("rrun")
	if err != nil {
		log.Printf("observability: generate rule run id failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "rule_run"})
		return nil
	}
	run := &RuleRun{
		db: db, id: id, organizationID: organizationID,
		integrationID: integrationID, provider: provider, ruleKey: boundedRuleKey(ruleKey),
		rulesEvaluated: nonNegative(rulesEvaluated), startedAt: startedAt,
	}
	if db == nil {
		return nil
	}
	if strings.TrimSpace(ruleVersion) == "" {
		ruleVersion = "v1"
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO rule_runs
			(id, organization_id, integration_id, ingestion_job_id, provider, rule_key, rule_version, status, rules_evaluated, started_at, created_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5::"SaaSProvider", $6, $7, 'RUNNING'::"RuleRunStatus", $8, $9, $9)
	`, run.id, organizationID, integrationID, ingestionJobID, provider, run.ruleKey, ruleVersion, run.rulesEvaluated, startedAt)
	if err != nil {
		log.Printf("observability: start rule run failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "rule_run"})
		return nil
	}
	telemetry.IncCounter("aperio_rule_runs_total", map[string]string{"provider": provider, "outcome": "started"})
	return run
}

// SetRulesEvaluated updates the count captured on the run handle. Finish writes
// the value with the terminal state, keeping the pre-load failure path able to
// create a receipt before custom rules are fetched.
func (r *RuleRun) SetRulesEvaluated(rulesEvaluated int) {
	if r == nil {
		return
	}
	r.rulesEvaluated = nonNegative(rulesEvaluated)
}

// Finish records a terminal rule-pack evaluation.
func (r *RuleRun) Finish(ctx context.Context, status string, findingsCount int, runErr error) {
	if r == nil || r.db == nil || r.id == "" {
		return
	}
	status = normalizeStatus(status)
	completedAt := time.Now().UTC()
	finishCtx, cancel := terminalContext(ctx)
	defer cancel()
	_, err := r.db.ExecContext(finishCtx, `
		UPDATE rule_runs
		SET status = $1::"RuleRunStatus",
			rules_evaluated = $2,
			findings_count = $3,
			error_message = $4,
			completed_at = $5,
			duration_ms = $6
		WHERE id = $7 AND organization_id = $8 AND integration_id = $9
	`, status, r.rulesEvaluated, nonNegative(findingsCount), errorMessage(runErr), completedAt,
		completedAt.Sub(r.startedAt).Milliseconds(), r.id, r.organizationID, r.integrationID)
	if err != nil {
		log.Printf("observability: finish rule run failed: %v", err)
		telemetry.IncCounter("aperio_observability_receipt_errors_total", map[string]string{"kind": "rule_run"})
		return
	}
	telemetry.IncCounter("aperio_rule_runs_total", map[string]string{"provider": r.provider, "outcome": strings.ToLower(status)})
}

func prefixedID(prefix string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

func terminalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func boundedSource(source string) string {
	switch strings.TrimSpace(source) {
	case ConnectorSourceGoogleWorkspaceReports, ConnectorSourceGoogleWorkspaceBigQuery,
		ConnectorSourceGoogleWorkspaceDirectory, ConnectorSourceGoogleWorkspaceOAuth:
		return strings.TrimSpace(source)
	default:
		return "other"
	}
}

func boundedRuleKey(ruleKey string) string {
	switch strings.TrimSpace(ruleKey) {
	case RulePackBuiltIn, RulePackCustom:
		return strings.TrimSpace(ruleKey)
	default:
		return "other"
	}
}

func normalizeStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "SUCCEEDED":
		return "SUCCEEDED"
	case "FAILED":
		return "FAILED"
	default:
		return "FAILED"
	}
}

func errorMessage(err error) any {
	if err == nil {
		return nil
	}
	message := runtimeutil.RedactText(
		strings.Join(strings.Fields(err.Error()), " "),
		os.Getenv("APERIO_ENCRYPTION_KEY"),
		os.Getenv("DATABASE_URL"),
		os.Getenv("APERIO_TEST_DATABASE_URL"),
		os.Getenv("APERIO_NATS_URL"),
	)
	if message == "" {
		return nil
	}
	if len(message) > 500 {
		message = message[:500]
	}
	return message
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
