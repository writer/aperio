package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/telemetry"
)

func TestOperationalHealthJSONRequiresAuthentication(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(http.MethodGet, operatorHealthPath, nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("operator health without database status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestMetricsEndpointReturnsPrometheusText(t *testing.T) {
	telemetry.IncCounter("aperio_test_operator_health_total", map[string]string{"kind": "other"})
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000", MetricsToken: "metrics-secret"}, nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-secret")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain; version=0.0.4") {
		t.Fatalf("metrics content type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "aperio_test_operator_health_total") {
		t.Fatalf("metrics body missing test counter: %q", rec.Body.String())
	}
}

func TestMetricsEndpointRequiresDedicatedToken(t *testing.T) {
	t.Run("disabled when unconfigured", func(t *testing.T) {
		app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("metrics status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("rejects wrong token", func(t *testing.T) {
		app := NewApp(config.Config{WebOrigin: "http://localhost:3000", MetricsToken: "metrics-secret"}, nil)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer wrong-secret")
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("metrics status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestOperationalHealthRPCRequiresAuthentication(t *testing.T) {
	app, _ := newTestDBApp(t)
	_, err := app.GetOperationalHealth(context.Background(), connect.NewRequest(&aperiov1.GetOperationalHealthRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("operational health RPC without session = %v, want unauthenticated", err)
	}
}

func TestOperationalHealthProtoIncludesQueueAndRuleReceipts(t *testing.T) {
	completed := time.Now().UTC()
	health := operationalHealth{
		Status:    "degraded",
		CheckedAt: completed,
		Connectors: []operationalConnectorHealth{{
			IntegrationID: "int-a", Provider: "SLACK", DisplayName: "Slack", IntegrationStatus: "CONNECTED",
			Source: "google_workspace_reports", RunStatus: "FAILED", LastCompletedAt: &completed, AgeSeconds: 4,
		}},
		IngestionQueue: operationalQueueHealth{Queued: 2, DeadLetter: 1, OldestQueuedAgeSecs: 17},
		SIEM:           operationalSiemHealth{Failed: 3, DeadLetter: 1, DestinationError: 1},
		RecentRuleRuns: []operationalRuleRun{{Provider: "SLACK", RuleKey: "builtin", RuleVersion: "v1", Status: "SUCCEEDED", FindingsCount: 2, StartedAt: completed, CompletedAt: &completed}},
	}
	proto := health.toProto()
	if proto.GetStatus() != "degraded" || proto.GetIngestionQueue().GetDeadLetter() != 1 || proto.GetSiem().GetFailed() != 3 {
		t.Fatalf("unexpected operational health proto: %v", proto)
	}
	if len(proto.GetConnectors()) != 1 || proto.GetConnectors()[0].GetRunStatus() != "FAILED" {
		t.Fatalf("connector receipt missing: %v", proto.GetConnectors())
	}
	if len(proto.GetRecentRuleRuns()) != 1 || proto.GetRecentRuleRuns()[0].GetRuleKey() != "builtin" {
		t.Fatalf("rule receipt missing: %v", proto.GetRecentRuleRuns())
	}
	encoded, err := json.Marshal(health)
	if err != nil || !strings.Contains(string(encoded), "deadLetter") {
		t.Fatalf("operator JSON shape invalid: %s (%v)", encoded, err)
	}
}

func TestOperationalHealthTenantIsolation(t *testing.T) {
	app, tenantA := newTestDBApp(t)
	tenantB := seedIsolationOrg(t, app)
	ctx := context.Background()

	createdA, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider": "SLACK", "displayName": "Tenant A Slack", "externalAccountId": "tenant-a-health",
		"mode": "READ_ONLY", "credentials": map[string]any{"accessToken": "test-token-a"},
	}, tenantA)
	if err != nil {
		t.Fatalf("create tenant A integration: %v", err)
	}
	integrationA := dataMap(t, createdA)["id"].(string)
	createdB, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider": "SLACK", "displayName": "Tenant B Slack", "externalAccountId": "tenant-b-health",
		"mode": "READ_ONLY", "credentials": map[string]any{"accessToken": "test-token-b"},
	}, tenantB)
	if err != nil {
		t.Fatalf("create tenant B integration: %v", err)
	}
	integrationB := dataMap(t, createdB)["id"].(string)

	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO connector_sync_runs (id, organization_id, integration_id, provider, source, status, started_at, completed_at, created_at)
		VALUES ($1,$2,$3,'SLACK','google_workspace_reports','FAILED',NOW()-INTERVAL '1 minute',NOW(),NOW())
	`, compatID("csr"), tenantB.OrganizationID, integrationB); err != nil {
		t.Fatalf("seed tenant B connector run: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO connector_sync_runs (id, organization_id, integration_id, provider, source, status, started_at, completed_at, created_at)
		VALUES ($1,$2,$3,'SLACK','google_workspace_directory','SUCCEEDED',NOW()-INTERVAL '2 minutes',NOW()-INTERVAL '1 minute',NOW()-INTERVAL '1 minute')
	`, compatID("csr"), tenantB.OrganizationID, integrationB); err != nil {
		t.Fatalf("seed tenant B second connector source: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO ingestion_jobs (id, organization_id, integration_id, provider, event_type, source, occurred_at, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at)
		VALUES ($1,$2,$3,'SLACK','MFA_DISABLED','test',NOW(),'{}'::jsonb,'DEAD_LETTER',3,3,NOW(),NOW(),NOW())
	`, compatID("job"), tenantB.OrganizationID, integrationB); err != nil {
		t.Fatalf("seed tenant B ingestion receipt: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO siem_deliveries (id, organization_id, stream, payload, status, attempts, max_attempts, next_attempt_at, created_at, updated_at)
		VALUES ($1,$2,'FINDINGS','{}'::jsonb,'DEAD_LETTER',5,5,NOW(),NOW(),NOW())
	`, compatID("sdel"), tenantB.OrganizationID); err != nil {
		t.Fatalf("seed tenant B SIEM receipt: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO rule_runs (id, organization_id, integration_id, provider, rule_key, rule_version, status, findings_count, started_at, completed_at, created_at)
		VALUES ($1,$2,$3,'SLACK','builtin','v1','FAILED',1,NOW()-INTERVAL '1 minute',NOW(),NOW())
	`, compatID("rrun"), tenantB.OrganizationID, integrationB); err != nil {
		t.Fatalf("seed tenant B rule receipt: %v", err)
	}

	healthA, err := app.operationalHealth(ctx, tenantA.OrganizationID)
	if err != nil {
		t.Fatalf("tenant A health: %v", err)
	}
	if len(healthA.Connectors) != 1 || healthA.Connectors[0].IntegrationID != integrationA || healthA.IngestionQueue.DeadLetter != 0 || healthA.SIEM.DeadLetter != 0 || len(healthA.RecentRuleRuns) != 0 {
		t.Fatalf("tenant A observed tenant B state: %#v", healthA)
	}

	healthB, err := app.operationalHealth(ctx, tenantB.OrganizationID)
	if err != nil {
		t.Fatalf("tenant B health: %v", err)
	}
	if healthB.Status != "degraded" || healthB.IngestionQueue.DeadLetter != 1 || healthB.SIEM.DeadLetter != 1 || len(healthB.RecentRuleRuns) != 1 || len(healthB.Connectors) != 2 {
		t.Fatalf("tenant B health did not include own receipts: %#v", healthB)
	}
	connectorSources := map[string]string{}
	for _, connector := range healthB.Connectors {
		connectorSources[connector.Source] = connector.RunStatus
	}
	if connectorSources["google_workspace_reports"] != "FAILED" || connectorSources["google_workspace_directory"] != "SUCCEEDED" {
		t.Fatalf("tenant B source-specific connector state missing: %#v", connectorSources)
	}
}
