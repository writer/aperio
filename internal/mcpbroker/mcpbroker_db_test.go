package mcpbroker

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDBBackedInitializeAndCatalogHaveNoSideEffects(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("APERIO_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	orgID := prefixedID("org")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, "MCP Protocol Test", "mcp-protocol-"+strings.ToLower(randomID())); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	defer db.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)

	before := mcpSideEffectCount(t, db, orgID)
	input := joinFrames(t,
		map[string]any{"jsonrpc": "2.0", "id": "init", "method": "initialize"},
		map[string]any{"jsonrpc": "2.0", "id": "ping", "method": "ping"},
		map[string]any{"jsonrpc": "2.0", "id": "catalog", "method": "tools/list"},
	)
	stdout := runServer(t, NewServer(NewToolService(db)), strings.NewReader(input))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3", len(frames))
	}
	after := mcpSideEffectCount(t, db, orgID)
	if after != before {
		t.Fatalf("initialize/ping/tools-list side effects changed count from %d to %d", before, after)
	}
}

func mcpSideEffectCount(t *testing.T, db *sql.DB, orgID string) int {
	t.Helper()
	var count int
	err := db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM agents WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM agent_tasks WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM agent_messages WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM agent_proposals WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM saas_response_actions WHERE organization_id = $1) +
			(SELECT COUNT(*) FROM saas_incident_timeline_events WHERE organization_id = $1)
	`, orgID).Scan(&count)
	if err != nil {
		t.Fatalf("count MCP side effects: %v", err)
	}
	return count
}
