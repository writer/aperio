package bootstrap

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	_ "github.com/jackc/pgx/v5/stdlib"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/config"
	"github.com/writer/aperio/internal/siemdispatcher"
)

// newTestDBApp wires an App against a real Postgres instance. The tests are
// skipped unless APERIO_TEST_DATABASE_URL points at a migrated database, so the
// default `go test ./...` run stays hermetic while CI can exercise the full
// SQL-backed compatibility routes.
func newTestDBApp(t *testing.T) (*App, compatAuth) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed route tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))

	orgID := compatID("org")
	slug := "test-" + strings.ToLower(randomBase36(12))
	if _, err := db.ExecContext(context.Background(), `INSERT INTO organizations (id, name, slug, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, orgID, "Test Org", slug); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
		_ = db.Close()
	})

	app := NewApp(config.Config{WebOrigin: "http://localhost:3000", SessionIdleMinutes: 120}, db)
	auth := compatAuth{OrganizationID: orgID, UserID: compatID("usr"), Email: "admin@example.com", Role: "ADMIN"}
	return app, auth
}

func dataMap(t *testing.T, result any) map[string]any {
	t.Helper()
	envelope, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data map, got %T", envelope["data"])
	}
	return data
}

type dbRouteCaptureTransport struct {
	t        *testing.T
	calls    []dbRouteCapturedRequest
	failOnDo bool
}

type dbRouteCapturedRequest struct {
	method string
	url    string
	header http.Header
	body   []byte
}

func (transport *dbRouteCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if transport.failOnDo {
		transport.t.Fatalf("unexpected outbound SIEM request after destination deletion: %s %s", req.Method, req.URL.String())
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	transport.calls = append(transport.calls, dbRouteCapturedRequest{
		method: req.Method,
		url:    req.URL.String(),
		header: req.Header.Clone(),
		body:   append([]byte(nil), body...),
	})
	status := http.StatusOK
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func seedSessionHeader(t *testing.T, app *App, auth compatAuth) http.Header {
	t.Helper()
	rawToken := randomURL(32)
	sessionID := compatID("ses")
	if _, err := app.db.ExecContext(context.Background(), `INSERT INTO user_sessions (id, organization_id, user_id, token_hash, expires_at, last_seen_at, mfa_verified_at, created_at, updated_at) VALUES ($1,$2,$3,$4,NOW() + INTERVAL '1 hour',NOW(),NOW(),NOW(),NOW())`, sessionID, auth.OrganizationID, auth.UserID, hashOpaqueToken(rawToken)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+sessionID+"."+rawToken)
	return header
}

func seedOrgUserWithRole(t *testing.T, app *App, orgID, roleName string) compatAuth {
	t.Helper()
	ctx := context.Background()
	roleID, err := app.ensureCompatRole(ctx, orgID, roleName)
	if err != nil {
		t.Fatalf("seed %s role: %v", roleName, err)
	}
	userID := compatID("usr")
	email := strings.ToLower(roleName) + "-" + randomBase36(10) + "@example.com"
	if _, err := app.db.ExecContext(ctx, `INSERT INTO users (id, organization_id, role_id, email, display_name, is_active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,TRUE,NOW(),NOW())`, userID, orgID, roleID, email, roleName+" User"); err != nil {
		t.Fatalf("seed %s user: %v", roleName, err)
	}
	return compatAuth{OrganizationID: orgID, UserID: userID, Email: email, Role: roleName}
}

func seedRemediationFixture(t *testing.T, app *App, auth compatAuth, provider string) (string, string) {
	t.Helper()
	ctx := context.Background()
	externalAccountID := remediationExternalAccountID(provider)
	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          provider,
		"displayName":       provider + " Remediation",
		"externalAccountId": externalAccountID,
		"mode":              "REMEDIATION",
		"credentials":       map[string]any{"accessToken": "local-token-value"},
	}, auth)
	if err != nil {
		t.Fatalf("create remediation integration for %s: %v", provider, err)
	}
	integrationID := dataMap(t, created)["id"].(string)
	findingID := compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, provider+" finding", "seeded for remediation test", json.RawMessage(`{"subject":"user@example.com"}`)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return integrationID, findingID
}

func remediationExternalAccountID(provider string) string {
	switch provider {
	case "GITHUB":
		return "github-" + randomBase36(10)
	case "SLACK":
		return "T" + strings.ToUpper(randomBase36(8))
	case "GOOGLE_WORKSPACE":
		return randomBase36(8) + ".example.com"
	case "OKTA":
		return randomBase36(8) + ".okta.com"
	case "MICROSOFT_365":
		return "00000000-0000-0000-0000-" + randomBase36(12)
	case "ATLASSIAN":
		return "org-" + randomBase36(10)
	case "SALESFORCE":
		return randomBase36(8) + ".my.salesforce.com"
	default:
		return randomBase36(12)
	}
}

func TestDBDisableMFARequiresCurrentCode(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	ctx := context.Background()
	auth := seedOrgUserWithRole(t, app, baseAuth.OrganizationID, "ADMIN")
	password := strings.Join([]string{"correct", "horse", "battery", "staple"}, " ")
	const secret = "JBSWY3DPEHPK3PXP"
	if _, err := app.db.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $1, mfa_enabled = TRUE, mfa_secret_encrypted = $2, mfa_last_counter = NULL, updated_at = NOW()
		WHERE id = $3 AND organization_id = $4
	`, compatHashPassword(password), secret, auth.UserID, auth.OrganizationID); err != nil {
		t.Fatalf("enable seeded MFA: %v", err)
	}

	header := seedSessionHeader(t, app, auth)
	validCode := compatHOTP([]byte("Hello!\xde\xad\xbe\xef"), uint64(time.Now().Unix()/30))
	badCode := "000000"
	if badCode == validCode {
		badCode = "111111"
	}
	badReq := connect.NewRequest(&aperiov1.DisableMfaRequest{Password: password, Code: badCode})
	copyCompatHeaders(badReq.Header(), header)
	if _, err := app.DisableMfa(ctx, badReq); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("DisableMfa wrong code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}

	var enabled bool
	var storedSecret sql.NullString
	if err := app.db.QueryRowContext(ctx, `SELECT mfa_enabled, mfa_secret_encrypted FROM users WHERE id = $1 AND organization_id = $2`, auth.UserID, auth.OrganizationID).Scan(&enabled, &storedSecret); err != nil {
		t.Fatalf("query MFA after bad code: %v", err)
	}
	if !enabled || !storedSecret.Valid {
		t.Fatal("wrong MFA code should not disable MFA")
	}

	goodReq := connect.NewRequest(&aperiov1.DisableMfaRequest{Password: password, Code: validCode})
	copyCompatHeaders(goodReq.Header(), header)
	resp, err := app.DisableMfa(ctx, goodReq)
	if err != nil {
		t.Fatalf("DisableMfa valid code: %v", err)
	}
	if resp.Msg.Data == nil || resp.Msg.Data.User == nil || resp.Msg.Data.User.MfaEnabled {
		t.Fatalf("DisableMfa response MFA state = %#v, want disabled", resp.Msg.Data)
	}
	if err := app.db.QueryRowContext(ctx, `SELECT mfa_enabled, mfa_secret_encrypted FROM users WHERE id = $1 AND organization_id = $2`, auth.UserID, auth.OrganizationID).Scan(&enabled, &storedSecret); err != nil {
		t.Fatalf("query MFA after valid code: %v", err)
	}
	if enabled || storedSecret.Valid {
		t.Fatalf("valid MFA disable persisted enabled=%v secretValid=%v, want disabled/null", enabled, storedSecret.Valid)
	}
}

func TestDBIntegrationLifecycle(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	const plaintextToken = "xoxb-example-access-token-1234567890"
	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Prod",
		"externalAccountId": "T123456",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": plaintextToken},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	var dbProvider string
	var scopesJSON string
	var encryptedAccess string
	if err := app.db.QueryRowContext(ctx, `SELECT provider::text, array_to_json(scopes)::text, encrypted_access_token FROM integration_connections WHERE id = $1 AND organization_id = $2`, integrationID, auth.OrganizationID).Scan(&dbProvider, &scopesJSON, &encryptedAccess); err != nil {
		t.Fatalf("query integration: %v", err)
	}
	if dbProvider != "SLACK" {
		t.Fatalf("provider = %s, want SLACK", dbProvider)
	}
	var scopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
		t.Fatalf("decode scopes: %v", err)
	}
	if len(scopes) == 0 {
		t.Fatal("expected catalog scopes to be persisted")
	}
	if strings.Contains(encryptedAccess, plaintextToken) {
		t.Fatal("access token persisted in plaintext")
	}

	checks := dataMap(t, mustCall(t, func() (any, error) { return app.compatIntegrationChecks(ctx, integrationID, auth) }))
	if checks["integrationId"].(string) != integrationID {
		t.Fatalf("checks integrationId = %v", checks["integrationId"])
	}

	const disabledCheck = "slack.external_shared_channel_created"
	updated := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateIntegrationChecks(ctx, integrationID, map[string]any{
			"disabledChecks":   []any{disabledCheck},
			"disableReason":    "test suppression window",
			"disableExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		}, auth)
	}))
	disabled, _ := updated["disabledChecks"].([]string)
	if len(disabled) != 1 || disabled[0] != disabledCheck {
		t.Fatalf("disabledChecks = %v", updated["disabledChecks"])
	}
	var persistedDisabledJSON string
	if err := app.db.QueryRowContext(ctx, `SELECT array_to_json(disabled_checks)::text FROM integration_connections WHERE id = $1`, integrationID).Scan(&persistedDisabledJSON); err != nil {
		t.Fatalf("query disabled checks: %v", err)
	}
	var persistedDisabled []string
	if err := json.Unmarshal([]byte(persistedDisabledJSON), &persistedDisabled); err != nil {
		t.Fatalf("decode disabled checks: %v", err)
	}
	if len(persistedDisabled) != 1 || persistedDisabled[0] != disabledCheck {
		t.Fatalf("persisted disabled checks = %v", persistedDisabled)
	}

	if _, err := app.compatForceSync(ctx, integrationID, auth); err == nil {
		t.Fatal("expected Slack force sync to be unsupported")
	}

	if _, err := app.compatDeleteIntegration(ctx, integrationID, auth); err != nil {
		t.Fatalf("delete integration: %v", err)
	}
	var remaining int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM integration_connections WHERE id = $1`, integrationID).Scan(&remaining); err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatal("expected integration to be deleted")
	}
}

func TestDBUpdateIntegrationChecksGovernanceGuards(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Governance",
		"externalAccountId": "T999000",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "xoxp-test-token"},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	if _, err := app.compatUpdateIntegrationChecks(ctx, integrationID, map[string]any{
		"disabledChecks": []any{"slack.external_shared_channel_created"},
	}, auth); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("missing governance fields code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}

	if _, err := app.compatUpdateIntegrationChecks(ctx, integrationID, map[string]any{
		"disabledChecks":   []any{"slack.mfa_disabled"},
		"disableReason":    "temporary breakglass",
		"disableExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	}, auth); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("critical baseline disable code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}

	if _, err := app.compatDeleteIntegration(ctx, integrationID, auth); err != nil {
		t.Fatalf("delete integration: %v", err)
	}
}

func TestDBGoogleOAuthReconnectPreservesDisabledChecks(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	input := googleIntegrationUpsert{
		organizationID:    auth.OrganizationID,
		externalAccountID: "example.com",
		displayName:       "Example Workspace",
		mode:              "READ_ONLY",
		refreshToken:      "refresh-token-1",
		adminEmail:        "admin@example.com",
		requestIP:         "127.0.0.1",
	}
	if err := app.upsertGoogleWorkspaceIntegration(ctx, input); err != nil {
		t.Fatalf("initial google oauth upsert: %v", err)
	}

	var integrationID string
	if err := app.db.QueryRowContext(ctx, `
		SELECT id
		FROM integration_connections
		WHERE organization_id = $1 AND provider = 'GOOGLE_WORKSPACE' AND external_account_id = $2
	`, auth.OrganizationID, input.externalAccountID).Scan(&integrationID); err != nil {
		t.Fatalf("query google integration: %v", err)
	}

	const disabledCheck = "google_workspace.risky_oauth_grant"
	if _, err := app.db.ExecContext(ctx, `
		UPDATE integration_connections
		SET disabled_checks = ARRAY[$1]::text[]
		WHERE id = $2 AND organization_id = $3
	`, disabledCheck, integrationID, auth.OrganizationID); err != nil {
		t.Fatalf("seed disabled checks: %v", err)
	}

	input.displayName = "Example Workspace Reconnected"
	input.mode = "REMEDIATION"
	input.refreshToken = "refresh-token-2"
	if err := app.upsertGoogleWorkspaceIntegration(ctx, input); err != nil {
		t.Fatalf("reconnect google oauth upsert: %v", err)
	}

	var disabledJSON string
	var displayName string
	var mode string
	if err := app.db.QueryRowContext(ctx, `
		SELECT array_to_json(disabled_checks)::text, display_name, mode::text
		FROM integration_connections
		WHERE id = $1 AND organization_id = $2
	`, integrationID, auth.OrganizationID).Scan(&disabledJSON, &displayName, &mode); err != nil {
		t.Fatalf("query disabled checks after reconnect: %v", err)
	}
	var disabled []string
	if err := json.Unmarshal([]byte(disabledJSON), &disabled); err != nil {
		t.Fatalf("decode disabled checks after reconnect: %v", err)
	}
	if len(disabled) != 1 || disabled[0] != disabledCheck {
		t.Fatalf("disabled checks after reconnect = %v, want [%s]", disabled, disabledCheck)
	}
	if displayName != input.displayName || mode != input.mode {
		t.Fatalf("reconnect did not update metadata: displayName=%q mode=%q", displayName, mode)
	}
}

func TestDBSecurityAssetOwnerFieldsPersist(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	owner := seedOrgUserWithRole(t, app, auth.OrganizationID, "SECURITY_ANALYST")
	businessOwner := seedOrgUserWithRole(t, app, auth.OrganizationID, "VIEWER")

	created := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatCreateSecurityAsset(ctx, map[string]any{
			"ownerUserId":           owner.UserID,
			"businessOwnerUserId":   businessOwner.UserID,
			"type":                  "DATA_RESOURCE",
			"name":                  "Customer DB",
			"labels":                []any{"database"},
			"criticality":           "HIGH",
			"exposureLevel":         "INTERNAL",
			"ownershipStatus":       "ASSIGNED",
			"containsSensitiveData": true,
			"isPrivileged":          false,
			"riskScore":             65,
		}, auth)
	}))
	assetID := created["id"].(string)
	assertAssetOwners(t, app, assetID, owner.UserID, businessOwner.UserID)

	nextOwner := seedOrgUserWithRole(t, app, auth.OrganizationID, "ADMIN")
	nextBusinessOwner := seedOrgUserWithRole(t, app, auth.OrganizationID, "SECURITY_ANALYST")
	_ = dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateSecurityAsset(ctx, assetID, map[string]any{
			"ownerUserId":         nextOwner.UserID,
			"businessOwnerUserId": nextBusinessOwner.UserID,
		}, auth)
	}))
	assertAssetOwners(t, app, assetID, nextOwner.UserID, nextBusinessOwner.UserID)
}

func TestDBSiemLifecycle(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	const plaintextToken = "splunk-hec-example-token-1234567890"
	created, err := app.compatCreateSiem(ctx, map[string]any{
		"kind":        "GENERIC_WEBHOOK",
		"name":        "Webhook",
		"endpointUrl": "https://8.8.8.8/services/collector",
		"streams":     []any{"FINDINGS"},
		"token":       plaintextToken,
	}, auth)
	if err != nil {
		t.Fatalf("create siem: %v", err)
	}
	destinationID := dataMap(t, created)["id"].(string)

	var encryptedToken sql.NullString
	var kind string
	if err := app.db.QueryRowContext(ctx, `SELECT kind::text, encrypted_token FROM siem_destinations WHERE id = $1 AND organization_id = $2`, destinationID, auth.OrganizationID).Scan(&kind, &encryptedToken); err != nil {
		t.Fatalf("query siem destination: %v", err)
	}
	if kind != "GENERIC_WEBHOOK" {
		t.Fatalf("kind = %s, want GENERIC_WEBHOOK", kind)
	}
	if !encryptedToken.Valid || encryptedToken.String == "" {
		t.Fatal("expected encrypted token to be stored")
	}
	if strings.Contains(encryptedToken.String, plaintextToken) {
		t.Fatal("siem token persisted in plaintext")
	}

	if _, err := app.compatTestSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("test siem: %v", err)
	}
	var deliveryStatus string
	if err := app.db.QueryRowContext(ctx, `SELECT status::text FROM siem_deliveries WHERE destination_id = $1`, destinationID).Scan(&deliveryStatus); err != nil {
		t.Fatalf("query siem delivery: %v", err)
	}
	if deliveryStatus != "PENDING" {
		t.Fatalf("delivery status = %s, want PENDING", deliveryStatus)
	}
	if _, err := app.db.ExecContext(ctx, `DELETE FROM siem_deliveries WHERE destination_id = $1 AND organization_id = $2`, destinationID, auth.OrganizationID); err != nil {
		t.Fatalf("delete queued lifecycle test delivery: %v", err)
	}

	if _, err := app.compatDeleteSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("delete siem: %v", err)
	}
	var remaining int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM siem_destinations WHERE id = $1`, destinationID).Scan(&remaining); err != nil {
		t.Fatalf("query remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatal("expected siem destination to be deleted")
	}
}

func TestDBSiemDestinationCRUDValidatesAndRedactsAcrossSurfaces(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	const plaintextToken = "siem-redact"
	createReq := connect.NewRequest(&aperiov1.CreateSiemDestinationRequest{
		Kind:        "GENERIC_WEBHOOK",
		Name:        "Redacted webhook",
		EndpointUrl: "https://8.8.8.8/aperio",
		Streams:     []string{"FINDINGS", "FINDINGS"},
		Token:       plaintextToken,
	})
	copyCompatHeaders(createReq.Header(), header)
	createResp, err := app.CreateSiemDestination(ctx, createReq)
	if err != nil {
		t.Fatalf("typed create SIEM destination: %v", err)
	}
	destinationID := createResp.Msg.Data.Id
	if createResp.Msg.Data.Kind != "GENERIC_WEBHOOK" || createResp.Msg.Data.Name != "Redacted webhook" {
		t.Fatalf("typed create response = %#v", createResp.Msg.Data)
	}
	if len(createResp.Msg.Data.Streams) != 1 || createResp.Msg.Data.Streams[0] != "FINDINGS" {
		t.Fatalf("streams should be validated and de-duplicated, got %#v", createResp.Msg.Data.Streams)
	}
	var encryptedToken sql.NullString
	if err := app.db.QueryRowContext(ctx, `
		SELECT encrypted_token
		FROM siem_destinations
		WHERE id = $1 AND organization_id = $2
	`, destinationID, auth.OrganizationID).Scan(&encryptedToken); err != nil {
		t.Fatalf("query encrypted SIEM token: %v", err)
	}
	if !encryptedToken.Valid || encryptedToken.String == "" || strings.Contains(encryptedToken.String, plaintextToken) {
		t.Fatalf("expected encrypted token material without plaintext, got valid=%v value=%q", encryptedToken.Valid, encryptedToken.String)
	}

	listReq := connect.NewRequest(&aperiov1.ListSiemDestinationsRequest{})
	copyCompatHeaders(listReq.Header(), header)
	listResp, err := app.ListSiemDestinations(ctx, listReq)
	if err != nil {
		t.Fatalf("typed list SIEM destinations: %v", err)
	}
	var listed *aperiov1.SiemDestination
	for _, candidate := range listResp.Msg.Data {
		if candidate.Id == destinationID {
			listed = candidate
			break
		}
	}
	if listed == nil || listed.EndpointUrl != "https://8.8.8.8/aperio" || listed.FilePath != "" || listed.Index != "" {
		t.Fatalf("typed list destination = %#v", listed)
	}

	compatList, err := callCompatViaCallAPI(t, app, ctx, header, http.MethodGet, "/api/v1/siem", "")
	if err != nil {
		t.Fatalf("compat list SIEM destinations: %v", err)
	}
	serializedCompatList, err := json.Marshal(compatList)
	if err != nil {
		t.Fatalf("serialize compat list: %v", err)
	}
	if strings.Contains(string(serializedCompatList), plaintextToken) || strings.Contains(string(serializedCompatList), encryptedToken.String) || strings.Contains(string(serializedCompatList), "encryptedToken") || strings.Contains(string(serializedCompatList), `"token"`) {
		t.Fatalf("compat list leaked SIEM secret material: %s", string(serializedCompatList))
	}
	compatRows, ok := compatList["data"].([]any)
	if !ok {
		t.Fatalf("compat list data = %T", compatList["data"])
	}
	foundCompat := false
	for _, raw := range compatRows {
		row, _ := raw.(map[string]any)
		if row["id"] == destinationID {
			foundCompat = true
			if row["endpointUrl"] != "https://8.8.8.8/aperio" || row["filePath"] != nil || row["index"] != nil {
				t.Fatalf("compat list destination = %#v", row)
			}
		}
	}
	if !foundCompat {
		t.Fatalf("compat list missing destination %s in %#v", destinationID, compatRows)
	}

	invalidTyped := []struct {
		name string
		req  *aperiov1.CreateSiemDestinationRequest
	}{
		{
			name: "missing required token",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:        "SPLUNK_HEC",
				Name:        "Missing token",
				EndpointUrl: "https://8.8.8.8/services/collector",
				Streams:     []string{"FINDINGS"},
			},
		},
		{
			name: "invalid stream",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:        "GENERIC_WEBHOOK",
				Name:        "Invalid stream",
				EndpointUrl: "https://8.8.8.8/aperio",
				Streams:     []string{"FINDINGS", "BAD_STREAM"},
			},
		},
		{
			name: "unsafe endpoint",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:        "GENERIC_WEBHOOK",
				Name:        "Unsafe endpoint",
				EndpointUrl: "http://8.8.8.8/aperio",
				Streams:     []string{"FINDINGS"},
			},
		},
		{
			name: "kind-specific unsupported stream",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:        "ELASTIC",
				Name:        "Unsupported stream",
				EndpointUrl: "https://8.8.8.8/_bulk",
				Index:       "aperio-findings",
				Token:       "elastic-token",
				Streams:     []string{"EVENTS"},
			},
		},
		{
			name: "unsafe file path",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:     "JSON_FILE",
				Name:     "Unsafe file path",
				FilePath: "../escape.jsonl",
				Streams:  []string{"FINDINGS"},
			},
		},
		{
			name: "unsupported kind",
			req: &aperiov1.CreateSiemDestinationRequest{
				Kind:    "UNKNOWN_SIEM",
				Name:    "Unknown kind",
				Streams: []string{"FINDINGS"},
			},
		},
	}
	for _, testCase := range invalidTyped {
		t.Run(testCase.name, func(t *testing.T) {
			before := countSiemDestinations(t, app, auth.OrganizationID)
			req := connect.NewRequest(testCase.req)
			copyCompatHeaders(req.Header(), header)
			if _, err := app.CreateSiemDestination(ctx, req); connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("typed invalid create code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
			}
			if after := countSiemDestinations(t, app, auth.OrganizationID); after != before {
				t.Fatalf("invalid typed create changed destination count from %d to %d", before, after)
			}
		})
	}

	beforeCompatInvalid := countSiemDestinations(t, app, auth.OrganizationID)
	if _, err := callCompatViaCallAPI(t, app, ctx, header, http.MethodPost, "/api/v1/siem", `{"kind":"ELASTIC","name":"Missing index","endpointUrl":"https://8.8.8.8/_bulk","streams":["FINDINGS"],"token":"elastic-token"}`); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("compat invalid create code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}
	if after := countSiemDestinations(t, app, auth.OrganizationID); after != beforeCompatInvalid {
		t.Fatalf("invalid compat create changed destination count from %d to %d", beforeCompatInvalid, after)
	}
}

func TestDBSiemTestPingCoversEveryGoOwnedAdapter(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)

	type adapterConfig struct {
		kind                 string
		endpointURL          string
		filePath             string
		index                string
		token                string
		expectedHTTPRequests int
	}
	adapters := []adapterConfig{
		{kind: "SPLUNK_HEC", endpointURL: "https://8.8.8.8/splunk", token: "splunk-test-token", expectedHTTPRequests: 2},
		{kind: "PANTHER", endpointURL: "https://8.8.8.8/panther", token: "panther-test-token", expectedHTTPRequests: 2},
		{kind: "PANOPTICON", endpointURL: "https://8.8.8.8/panopticon", expectedHTTPRequests: 2},
		{kind: "ELASTIC", endpointURL: "https://8.8.8.8/_bulk", index: "aperio-test-ping", token: "elastic-test-token", expectedHTTPRequests: 2},
		{kind: "DATADOG", endpointURL: "https://8.8.8.8/datadog", token: "datadog-test-token", expectedHTTPRequests: 2},
		{kind: "GENERIC_WEBHOOK", endpointURL: "https://8.8.8.8/webhook", token: "webhook-test-token", expectedHTTPRequests: 2},
		{kind: "CEREBRO_CLAIMS", endpointURL: "https://8.8.8.8/cerebro", index: "runtime-test-ping", token: "cerebro-test-token", expectedHTTPRequests: 4},
		{kind: "JSON_FILE", filePath: "all-adapters-test-ping.jsonl"},
	}

	destinationIDs := map[string]string{}
	for _, adapter := range adapters {
		req := connect.NewRequest(&aperiov1.CreateSiemDestinationRequest{
			Kind:        adapter.kind,
			Name:        adapter.kind + " test ping",
			EndpointUrl: adapter.endpointURL,
			FilePath:    adapter.filePath,
			Index:       adapter.index,
			Token:       adapter.token,
			Streams:     []string{"FINDINGS"},
		})
		copyCompatHeaders(req.Header(), header)
		resp, err := app.CreateSiemDestination(ctx, req)
		if err != nil {
			t.Fatalf("create %s SIEM destination: %v", adapter.kind, err)
		}
		destinationID := resp.Msg.Data.Id
		destinationIDs[adapter.kind] = destinationID

		compatResult, err := app.compatTestSiem(ctx, destinationID, auth)
		if err != nil {
			t.Fatalf("compat test-ping %s: %v", adapter.kind, err)
		}
		if dataMap(t, compatResult)["stream"] != "FINDINGS" {
			t.Fatalf("%s compat test-ping stream = %#v", adapter.kind, dataMap(t, compatResult)["stream"])
		}
		typedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
		copyCompatHeaders(typedReq.Header(), header)
		typedResp, err := app.TestSiemDestination(ctx, typedReq)
		if err != nil {
			t.Fatalf("typed test-ping %s: %v", adapter.kind, err)
		}
		if !typedResp.Msg.Data.Ok || typedResp.Msg.Data.DestinationId != destinationID {
			t.Fatalf("%s typed test-ping response = %#v", adapter.kind, typedResp.Msg.Data)
		}

		rows, err := app.db.QueryContext(ctx, `
			SELECT id, stream::text, payload
			FROM siem_deliveries
			WHERE destination_id = $1 AND organization_id = $2
			ORDER BY created_at, id
		`, destinationID, auth.OrganizationID)
		if err != nil {
			t.Fatalf("query queued %s test-pings: %v", adapter.kind, err)
		}
		queued := 0
		for rows.Next() {
			var deliveryID, stream string
			var rawPayload json.RawMessage
			if err := rows.Scan(&deliveryID, &stream, &rawPayload); err != nil {
				t.Fatalf("scan queued %s test-ping: %v", adapter.kind, err)
			}
			var payload siemdispatcher.Payload
			if err := json.Unmarshal(rawPayload, &payload); err != nil {
				t.Fatalf("decode queued %s test-ping: %v", adapter.kind, err)
			}
			if stream != "FINDINGS" || payload.Kind != "finding" || payload.OrganizationID != auth.OrganizationID || payload.Record["test"] != true || payload.Record["id"] != deliveryID || payload.Record["sourceEventId"] == "" {
				t.Fatalf("%s queued test-ping payload = stream=%s payload=%#v", adapter.kind, stream, payload)
			}
			queued++
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate queued %s test-pings: %v", adapter.kind, err)
		}
		rows.Close()
		if queued != 2 {
			t.Fatalf("%s expected two queued test-pings, got %d", adapter.kind, queued)
		}
	}

	transport := &dbRouteCaptureTransport{t: t}
	dispatcher := siemdispatcher.New(app.db)
	dispatcher.SetOrganizationForTesting(auth.OrganizationID)
	dispatcher.SetHTTPClientForTesting(&http.Client{Transport: transport})
	dispatcher.SetEndpointSafetyCheckForTesting(func(_ context.Context, endpoint string) error {
		if !strings.HasPrefix(endpoint, "https://8.8.8.8/") {
			return fmt.Errorf("unexpected non-local SIEM test endpoint %s", endpoint)
		}
		return nil
	})
	drainResult, err := dispatcher.Drain(ctx, 100)
	if err != nil {
		t.Fatalf("drain all adapter test-pings: %v", err)
	}
	wantDeliveries := len(adapters) * 2
	if drainResult.Processed != wantDeliveries || drainResult.Delivered != wantDeliveries || drainResult.Failed != 0 {
		t.Fatalf("unexpected all-adapter test-ping drain result: %#v", drainResult)
	}

	wantHTTPRequests := 0
	for _, adapter := range adapters {
		wantHTTPRequests += adapter.expectedHTTPRequests
		assertSiemDestinationHealth(t, app, adapter.kind, destinationIDs[adapter.kind], "ACTIVE", 2, 0)
	}
	if len(transport.calls) != wantHTTPRequests {
		t.Fatalf("captured HTTP request count = %d, want %d", len(transport.calls), wantHTTPRequests)
	}
	for _, call := range transport.calls {
		for _, adapter := range adapters {
			if adapter.token != "" && strings.Contains(string(call.body), adapter.token) {
				t.Fatalf("%s request body leaked token %q: %s", adapter.kind, adapter.token, string(call.body))
			}
		}
	}
	rawJSONL, err := os.ReadFile(filepath.Join(exportRoot, "all-adapters-test-ping.jsonl"))
	if err != nil {
		t.Fatalf("read JSON_FILE test-ping output: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(string(rawJSONL)), "\n"); len(lines) != 2 {
		t.Fatalf("JSON_FILE test-ping wrote %d lines, want 2: %q", len(lines), string(rawJSONL))
	}
}

func TestDBSiemDestinationDeletionDeadLettersQueuedAndExpiredInFlightWithoutSending(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)

	createReq := connect.NewRequest(&aperiov1.CreateSiemDestinationRequest{
		Kind:     "JSON_FILE",
		Name:     "Delete safety JSON",
		FilePath: "deleted-destination.jsonl",
		Streams:  []string{"FINDINGS"},
	})
	copyCompatHeaders(createReq.Header(), header)
	createResp, err := app.CreateSiemDestination(ctx, createReq)
	if err != nil {
		t.Fatalf("create delete-safety SIEM destination: %v", err)
	}
	destinationID := createResp.Msg.Data.Id
	if _, err := app.compatTestSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("queue compat delete-safety test-ping: %v", err)
	}
	typedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
	copyCompatHeaders(typedReq.Header(), header)
	if _, err := app.TestSiemDestination(ctx, typedReq); err != nil {
		t.Fatalf("queue typed delete-safety test-ping: %v", err)
	}
	var inFlightID string
	if err := app.db.QueryRowContext(ctx, `
		SELECT id
		FROM siem_deliveries
		WHERE destination_id = $1 AND organization_id = $2
		ORDER BY created_at, id
		LIMIT 1
	`, destinationID, auth.OrganizationID).Scan(&inFlightID); err != nil {
		t.Fatalf("query queued delete-safety delivery: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'PROCESSING'::"SiemDeliveryStatus",
		    lease_owner = 'stale-delete-safety-worker',
		    lease_expires_at = NOW() - INTERVAL '1 minute',
		    updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, inFlightID, auth.OrganizationID); err != nil {
		t.Fatalf("mark delete-safety delivery in-flight: %v", err)
	}

	if _, err := app.compatDeleteSiem(ctx, destinationID, auth); err != nil {
		t.Fatalf("delete SIEM destination with queued work: %v", err)
	}
	listReq := connect.NewRequest(&aperiov1.ListSiemDestinationsRequest{})
	copyCompatHeaders(listReq.Header(), header)
	listResp, err := app.ListSiemDestinations(ctx, listReq)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	for _, destination := range listResp.Msg.Data {
		if destination.Id == destinationID {
			t.Fatalf("deleted destination remained listable: %#v", destination)
		}
	}
	if _, err := app.compatTestSiem(ctx, destinationID, auth); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted compat test-ping code = %v (%v), want CodeNotFound", connect.CodeOf(err), err)
	}
	deletedTypedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
	copyCompatHeaders(deletedTypedReq.Header(), header)
	if _, err := app.TestSiemDestination(ctx, deletedTypedReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted typed test-ping code = %v (%v), want CodeNotFound", connect.CodeOf(err), err)
	}
	var destinationReferences int
	if err := app.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2
	`, auth.OrganizationID, destinationID).Scan(&destinationReferences); err != nil {
		t.Fatalf("count post-delete destination references: %v", err)
	}
	if destinationReferences != 0 {
		t.Fatalf("delete left %d delivery references to destination %s", destinationReferences, destinationID)
	}

	transport := &dbRouteCaptureTransport{t: t, failOnDo: true}
	dispatcher := siemdispatcher.New(app.db)
	dispatcher.SetOrganizationForTesting(auth.OrganizationID)
	dispatcher.SetHTTPClientForTesting(&http.Client{Transport: transport})
	dispatcher.SetEndpointSafetyCheckForTesting(func(context.Context, string) error {
		t.Fatal("deleted destination should fail before endpoint safety")
		return nil
	})
	drainResult, err := dispatcher.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("drain deleted destination work: %v", err)
	}
	if drainResult.Processed != 2 || drainResult.Delivered != 0 || drainResult.Failed != 2 {
		t.Fatalf("unexpected deleted destination drain result: %#v", drainResult)
	}
	if _, err := os.Stat(filepath.Join(exportRoot, "deleted-destination.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("deleted destination wrote JSONL side effect, stat err=%v", err)
	}
	rows, err := app.db.QueryContext(ctx, `
		SELECT status::text, attempts, delivered_at, last_error
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id IS NULL
		  AND payload->'record'->>'title' = 'Aperio SIEM connectivity test'
		ORDER BY created_at, id
	`, auth.OrganizationID)
	if err != nil {
		t.Fatalf("query deleted destination deliveries: %v", err)
	}
	defer rows.Close()
	deadLetters := 0
	for rows.Next() {
		var status string
		var attempts int
		var deliveredAt sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&status, &attempts, &deliveredAt, &lastError); err != nil {
			t.Fatalf("scan deleted destination delivery: %v", err)
		}
		if status != "DEAD_LETTER" || attempts != 1 || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "destination not configured") {
			t.Fatalf("deleted destination delivery state = status=%s attempts=%d delivered=%v error=%v", status, attempts, deliveredAt, lastError)
		}
		deadLetters++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate deleted destination deliveries: %v", err)
	}
	if deadLetters != 2 {
		t.Fatalf("expected two deleted destination dead letters, got %d", deadLetters)
	}
}

func TestDBSiemTestPingQueuesAndDrainsThroughDispatcher(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)

	adminHeader := seedSessionHeader(t, app, auth)
	createReq := connect.NewRequest(&aperiov1.CreateSiemDestinationRequest{
		Kind:     "JSON_FILE",
		Name:     "Local JSON test ping",
		FilePath: "test-ping.jsonl",
		Streams:  []string{"FINDINGS"},
	})
	copyCompatHeaders(createReq.Header(), adminHeader)
	createResp, err := app.CreateSiemDestination(ctx, createReq)
	if err != nil {
		t.Fatalf("typed create JSON_FILE SIEM destination: %v", err)
	}
	destinationID := createResp.Msg.Data.Id

	deliveryCount := func() int {
		t.Helper()
		var count int
		if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM siem_deliveries WHERE destination_id = $1`, destinationID).Scan(&count); err != nil {
			t.Fatalf("count SIEM test deliveries: %v", err)
		}
		return count
	}
	analyst := seedOrgUserWithRole(t, app, auth.OrganizationID, "SECURITY_ANALYST")
	analystHeader := seedSessionHeader(t, app, analyst)
	deniedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
	copyCompatHeaders(deniedReq.Header(), analystHeader)
	if _, err := app.TestSiemDestination(ctx, deniedReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-owner typed test SIEM code = %v (%v), want CodePermissionDenied", connect.CodeOf(err), err)
	}
	if count := deliveryCount(); count != 0 {
		t.Fatalf("permission-denied test ping enqueued %d deliveries", count)
	}

	compatResult, err := app.compatTestSiem(ctx, destinationID, auth)
	if err != nil {
		t.Fatalf("compat test SIEM: %v", err)
	}
	compatDeliveryID := dataMap(t, compatResult)["deliveryId"].(string)
	typedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
	copyCompatHeaders(typedReq.Header(), adminHeader)
	typedResp, err := app.TestSiemDestination(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed test SIEM: %v", err)
	}
	if !typedResp.Msg.Data.Ok || typedResp.Msg.Data.DestinationId != destinationID || !strings.Contains(typedResp.Msg.Data.Message, "queued") {
		t.Fatalf("unexpected typed test response: %#v", typedResp.Msg.Data)
	}

	rows, err := app.db.QueryContext(ctx, `
		SELECT id, status::text, attempts, max_attempts, stream::text, dedupe_key, payload
		FROM siem_deliveries
		WHERE destination_id = $1 AND organization_id = $2
		ORDER BY created_at, id
	`, destinationID, auth.OrganizationID)
	if err != nil {
		t.Fatalf("query queued test deliveries: %v", err)
	}
	defer rows.Close()
	queuedIDs := []string{}
	for rows.Next() {
		var deliveryID, status, stream, dedupe string
		var attempts, maxAttempts int
		var rawPayload json.RawMessage
		if err := rows.Scan(&deliveryID, &status, &attempts, &maxAttempts, &stream, &dedupe, &rawPayload); err != nil {
			t.Fatalf("scan queued test delivery: %v", err)
		}
		var payload siemdispatcher.Payload
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			t.Fatalf("decode queued test payload: %v", err)
		}
		if status != "PENDING" || attempts != 0 || maxAttempts != 5 || stream != "FINDINGS" {
			t.Fatalf("queued test delivery state = id=%s status=%s attempts=%d max=%d stream=%s", deliveryID, status, attempts, maxAttempts, stream)
		}
		if payload.Kind != "finding" || payload.OrganizationID != auth.OrganizationID || payload.Record["test"] != true || payload.Record["id"] != deliveryID {
			t.Fatalf("queued test payload = id=%s payload=%#v", deliveryID, payload)
		}
		if payload.Record["title"] != "Aperio SIEM connectivity test" || payload.Record["severity"] != "INFO" || payload.Record["provider"] != "APERIO" {
			t.Fatalf("queued test record = %#v", payload.Record)
		}
		if want := siemdispatcher.StableDeliveryKey(payload, destinationID, "FINDINGS"); dedupe != want {
			t.Fatalf("queued test dedupe = %s, want %s", dedupe, want)
		}
		queuedIDs = append(queuedIDs, deliveryID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate queued test deliveries: %v", err)
	}
	if len(queuedIDs) != 2 {
		t.Fatalf("expected compat+typed test pings to enqueue two deliveries, got %v", queuedIDs)
	}
	if queuedIDs[0] != compatDeliveryID && queuedIDs[1] != compatDeliveryID {
		t.Fatalf("compat delivery id %s not found in queued ids %v", compatDeliveryID, queuedIDs)
	}

	dispatcher := siemdispatcher.New(app.db)
	dispatcher.SetOrganizationForTesting(auth.OrganizationID)
	drainResult, err := dispatcher.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("drain queued test pings: %v", err)
	}
	if drainResult.Processed != 2 || drainResult.Delivered != 2 || drainResult.Failed != 0 {
		t.Fatalf("unexpected test-ping drain result: %#v", drainResult)
	}
	var delivered int
	if err := app.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE destination_id = $1 AND status = 'DELIVERED'::"SiemDeliveryStatus"
	`, destinationID).Scan(&delivered); err != nil {
		t.Fatalf("count delivered test pings: %v", err)
	}
	if delivered != 2 {
		t.Fatalf("expected two delivered test pings, got %d", delivered)
	}
	raw, err := os.ReadFile(filepath.Join(exportRoot, "test-ping.jsonl"))
	if err != nil {
		t.Fatalf("read test-ping JSONL: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two dispatcher-written test envelopes, got %d lines: %q", len(lines), string(raw))
	}
	for _, line := range lines {
		var envelope siemdispatcher.Envelope
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("decode test-ping envelope: %v", err)
		}
		if envelope.SchemaVersion != "aperio.finding.v1" || envelope.DestinationID != destinationID || envelope.OrganizationID != auth.OrganizationID || envelope.Record["test"] != true {
			t.Fatalf("unexpected test-ping envelope: %#v", envelope)
		}
	}
	listReq := connect.NewRequest(&aperiov1.ListSiemDestinationsRequest{})
	copyCompatHeaders(listReq.Header(), adminHeader)
	listResp, err := app.ListSiemDestinations(ctx, listReq)
	if err != nil {
		t.Fatalf("list SIEM destinations after drain: %v", err)
	}
	var listed *aperiov1.SiemDestination
	for _, destination := range listResp.Msg.Data {
		if destination.Id == destinationID {
			listed = destination
			break
		}
	}
	if listed == nil || listed.Status != "ACTIVE" || listed.DeliveriesOk != 2 || listed.DeliveriesFail != 0 || listed.LastDeliveryAt == "" || listed.LastError != "" {
		t.Fatalf("listed SIEM health after test drain = %#v", listed)
	}
}

func TestDBSiemTestPingUsesSubscribedStreamAndRejectsUnsupportedWithoutQueue(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()

	adminHeader := seedSessionHeader(t, app, auth)
	createReq := connect.NewRequest(&aperiov1.CreateSiemDestinationRequest{
		Kind:        "PANTHER",
		Name:        "Panther event test ping",
		EndpointUrl: "https://8.8.8.8/panther-events",
		Token:       "panther-events-token",
		Streams:     []string{"EVENTS"},
	})
	copyCompatHeaders(createReq.Header(), adminHeader)
	createResp, err := app.CreateSiemDestination(ctx, createReq)
	if err != nil {
		t.Fatalf("typed create events-only PANTHER SIEM destination: %v", err)
	}
	destinationID := createResp.Msg.Data.Id

	compatResult, err := app.compatTestSiem(ctx, destinationID, auth)
	if err != nil {
		t.Fatalf("compat events-only test SIEM: %v", err)
	}
	compatData := dataMap(t, compatResult)
	if compatData["stream"] != "EVENTS" {
		t.Fatalf("compat test stream = %v, want EVENTS", compatData["stream"])
	}
	typedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: destinationID})
	copyCompatHeaders(typedReq.Header(), adminHeader)
	typedResp, err := app.TestSiemDestination(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed events-only test SIEM: %v", err)
	}
	if !typedResp.Msg.Data.Ok || typedResp.Msg.Data.DestinationId != destinationID {
		t.Fatalf("unexpected typed events-only test response: %#v", typedResp.Msg.Data)
	}

	rows, err := app.db.QueryContext(ctx, `
		SELECT id, status::text, attempts, max_attempts, stream::text, dedupe_key, payload
		FROM siem_deliveries
		WHERE destination_id = $1 AND organization_id = $2
		ORDER BY created_at, id
	`, destinationID, auth.OrganizationID)
	if err != nil {
		t.Fatalf("query events-only test deliveries: %v", err)
	}
	defer rows.Close()
	queuedIDs := []string{}
	for rows.Next() {
		var deliveryID, status, stream, dedupe string
		var attempts, maxAttempts int
		var rawPayload json.RawMessage
		if err := rows.Scan(&deliveryID, &status, &attempts, &maxAttempts, &stream, &dedupe, &rawPayload); err != nil {
			t.Fatalf("scan events-only test delivery: %v", err)
		}
		var payload siemdispatcher.Payload
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			t.Fatalf("decode events-only test payload: %v", err)
		}
		if status != "PENDING" || attempts != 0 || maxAttempts != 5 || stream != "EVENTS" {
			t.Fatalf("events-only test delivery state = id=%s status=%s attempts=%d max=%d stream=%s", deliveryID, status, attempts, maxAttempts, stream)
		}
		if payload.Kind != "event" || payload.OrganizationID != auth.OrganizationID || payload.Record["test"] != true || payload.Record["id"] != deliveryID || payload.Record["eventType"] != "aperio.siem.test" {
			t.Fatalf("events-only test payload = id=%s payload=%#v", deliveryID, payload)
		}
		if want := siemdispatcher.StableDeliveryKey(payload, destinationID, "EVENTS"); dedupe != want {
			t.Fatalf("events-only test dedupe = %s, want %s", dedupe, want)
		}
		queuedIDs = append(queuedIDs, deliveryID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events-only test deliveries: %v", err)
	}
	if len(queuedIDs) != 2 {
		t.Fatalf("expected compat+typed events-only test pings to enqueue two deliveries, got %v", queuedIDs)
	}

	transport := &dbRouteCaptureTransport{t: t}
	dispatcher := siemdispatcher.New(app.db)
	dispatcher.SetOrganizationForTesting(auth.OrganizationID)
	dispatcher.SetHTTPClientForTesting(&http.Client{Transport: transport})
	dispatcher.SetEndpointSafetyCheckForTesting(func(_ context.Context, endpoint string) error {
		if endpoint != "https://8.8.8.8/panther-events" {
			return fmt.Errorf("unexpected events-only test endpoint %s", endpoint)
		}
		return nil
	})
	drainResult, err := dispatcher.Drain(ctx, 10)
	if err != nil {
		t.Fatalf("drain events-only test pings: %v", err)
	}
	if drainResult.Processed != 2 || drainResult.Delivered != 2 || drainResult.Failed != 0 {
		t.Fatalf("unexpected events-only test-ping drain result: %#v", drainResult)
	}
	if len(transport.calls) != 2 {
		t.Fatalf("expected two Panther event test-ping HTTP requests, got %d", len(transport.calls))
	}
	for _, call := range transport.calls {
		var envelope siemdispatcher.Envelope
		if err := json.Unmarshal(call.body, &envelope); err != nil {
			t.Fatalf("decode events-only test-ping envelope: %v", err)
		}
		if envelope.SchemaVersion != "aperio.event.v1" || envelope.Kind != "event" || envelope.DestinationID != destinationID || envelope.OrganizationID != auth.OrganizationID || envelope.Record["test"] != true {
			t.Fatalf("unexpected events-only test-ping envelope: %#v", envelope)
		}
		if strings.Contains(string(call.body), "panther-events-token") {
			t.Fatalf("Panther event test-ping body leaked token: %s", string(call.body))
		}
	}

	noStreamID := compatID("siem")
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'No stream JSON test ping',
			'no-stream.jsonl', ARRAY[]::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, noStreamID, auth.OrganizationID); err != nil {
		t.Fatalf("seed no-stream SIEM destination: %v", err)
	}
	pausedID := compatID("siem")
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'Paused JSON test ping',
			'paused.jsonl', ARRAY['FINDINGS'::"SiemStreamType"], 'PAUSED'::"SiemStatus", NOW(), NOW()
		)
	`, pausedID, auth.OrganizationID); err != nil {
		t.Fatalf("seed paused SIEM destination: %v", err)
	}
	countDeliveries := func(destinationID string) int {
		t.Helper()
		var count int
		if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM siem_deliveries WHERE destination_id = $1`, destinationID).Scan(&count); err != nil {
			t.Fatalf("count SIEM deliveries for %s: %v", destinationID, err)
		}
		return count
	}
	for name, unsupportedID := range map[string]string{
		"no subscribed streams": noStreamID,
		"paused destination":    pausedID,
	} {
		t.Run(name, func(t *testing.T) {
			before := countDeliveries(unsupportedID)
			if _, err := app.compatTestSiem(ctx, unsupportedID, auth); connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("compat unsupported test SIEM code = %v (%v), want CodeFailedPrecondition", connect.CodeOf(err), err)
			}
			unsupportedTypedReq := connect.NewRequest(&aperiov1.TestSiemDestinationRequest{Id: unsupportedID})
			copyCompatHeaders(unsupportedTypedReq.Header(), adminHeader)
			if _, err := app.TestSiemDestination(ctx, unsupportedTypedReq); connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("typed unsupported test SIEM code = %v (%v), want CodeFailedPrecondition", connect.CodeOf(err), err)
			}
			if after := countDeliveries(unsupportedID); after != before {
				t.Fatalf("unsupported test ping changed delivery count from %d to %d", before, after)
			}
		})
	}
}

func TestDBSlackRemediationUsesDecryptedToken(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	auth.UserID = ""

	const plaintextToken = "xoxp-remediation-secret"
	var providerCalls int
	var findingID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		var requestedAuditRows int
		if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedAuditRows); err != nil {
			t.Fatalf("query requested audit rows before provider call: %v", err)
		}
		if requestedAuditRows != 1 {
			t.Fatalf("expected requested audit before provider call, got %d", requestedAuditRows)
		}
		if r.URL.Path != "/admin.apps.uninstall" {
			t.Fatalf("path = %s, want /admin.apps.uninstall", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+plaintextToken {
			t.Fatalf("authorization header = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("app_id"); got != "A123" {
			t.Fatalf("app_id = %q", got)
		}
		if got := r.Form.Get("team_ids"); got != "T123456" {
			t.Fatalf("team_ids = %q", got)
		}
		w.Header().Set("X-Slack-Req-Id", "slack-db-route-req")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Remediation",
		"externalAccountId": "T123456",
		"mode":              "REMEDIATION",
		"credentials":       map[string]any{"accessToken": plaintextToken},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	findingID = compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, "Suspicious Slack app", "seeded for remediation test", json.RawMessage(`{"subject":"A123"}`)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	result := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install", "targetIdentifier": "A123"}, auth)
	}))
	if result["success"] != true {
		t.Fatalf("expected remediation success, got %v", result)
	}
	if result["providerRequestId"] != "slack-db-route-req" {
		t.Fatalf("providerRequestId = %v", result["providerRequestId"])
	}
	if providerCalls != 1 {
		t.Fatalf("expected one provider call, got %d", providerCalls)
	}

	var status string
	if err := app.db.QueryRowContext(ctx, `SELECT status::text FROM security_findings WHERE id = $1`, findingID).Scan(&status); err != nil {
		t.Fatalf("query finding status: %v", err)
	}
	if status != "RESOLVED" {
		t.Fatalf("finding status = %s, want RESOLVED", status)
	}
	var auditMetadata string
	if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.success'`, auth.OrganizationID, findingID).Scan(&auditMetadata); err != nil {
		t.Fatalf("query remediation audit metadata: %v", err)
	}
	if strings.Contains(auditMetadata, plaintextToken) {
		t.Fatal("audit metadata leaked the Slack access token")
	}
	if !strings.Contains(auditMetadata, "slack-db-route-req") {
		t.Fatalf("audit metadata missing provider request id: %s", auditMetadata)
	}
	var requestedMetadata string
	if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedMetadata); err != nil {
		t.Fatalf("query requested audit metadata: %v", err)
	}
	if strings.Contains(requestedMetadata, plaintextToken) {
		t.Fatal("requested audit metadata leaked the Slack access token")
	}
}

func TestDBSlackRemediationRequiresExplicitAppID(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()
	auth.UserID = ""

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Remediation",
		"externalAccountId": "T123456",
		"mode":              "REMEDIATION",
		"credentials":       map[string]any{"accessToken": "xoxp-remediation-secret"},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	findingID := compatID("fnd")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, "Slack user finding", "seeded for remediation test", json.RawMessage(`{"subject":"user@example.com"}`)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	_, err = app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install"}, auth)
	if err == nil {
		t.Fatal("expected missing Slack app id to reject")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v (%v)", code, err)
	}
	if providerCalls != 0 {
		t.Fatalf("expected no provider calls, got %d", providerCalls)
	}
	var requestedRows int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.requested'`, auth.OrganizationID, findingID).Scan(&requestedRows); err != nil {
		t.Fatalf("count requested audit rows: %v", err)
	}
	if requestedRows != 0 {
		t.Fatalf("expected no requested audit for rejected request, got %d", requestedRows)
	}
}

func TestDBSlackRemediationProviderFailureDoesNotResolve(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("app_id"); got != "A123" {
			t.Fatalf("app_id = %q, want A123", got)
		}
		if got := r.Form.Get("team_ids"); got != "TFAIL123" {
			t.Fatalf("team_ids = %q, want TFAIL123", got)
		}
		w.Header().Set("X-Slack-Req-Id", "slack-provider-failed")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing_scope"})
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, findingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-provider-failure", "TFAIL123", `{"subject":"EVIDENCE_APP","actor":"EVIDENCE_ACTOR"}`)
	result := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install", "targetIdentifier": "A123"}, auth)
	}))
	if result["success"] != false {
		t.Fatalf("expected provider failure result, got %v", result)
	}
	if result["providerRequestId"] != "slack-provider-failed" {
		t.Fatalf("providerRequestId = %v", result["providerRequestId"])
	}
	if effects, ok := result["effects"].([]string); !ok || len(effects) != 0 {
		t.Fatalf("expected no provider effects, got %#v", result["effects"])
	}
	if !strings.Contains(result["message"].(string), "missing_scope") {
		t.Fatalf("expected Slack error in message, got %q", result["message"])
	}
	if providerCalls != 1 {
		t.Fatalf("expected one provider call, got %d", providerCalls)
	}
	assertFindingState(t, app, findingID, "OPEN", false)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 1)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 1)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
	var failureMetadata string
	if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.failure'`, auth.OrganizationID, findingID).Scan(&failureMetadata); err != nil {
		t.Fatalf("query failure audit metadata: %v", err)
	}
	if !strings.Contains(failureMetadata, "slack-provider-failed") {
		t.Fatalf("failure metadata missing provider request id: %s", failureMetadata)
	}
	if strings.Contains(failureMetadata, "effects") {
		t.Fatalf("failure metadata exposed success-shaped effects: %s", failureMetadata)
	}
}

func TestDBSlackRemediationConfigFailuresDoNotResolve(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	cases := []struct {
		name     string
		mode     string
		mutate   func(integrationID string)
		wantCode connect.Code
	}{
		{
			name:     "read only connection",
			mode:     "READ_ONLY",
			wantCode: connect.CodePermissionDenied,
		},
		{
			name: "undecryptable credential",
			mode: "REMEDIATION",
			mutate: func(integrationID string) {
				if _, err := app.db.ExecContext(ctx, `UPDATE integration_connections SET encrypted_access_token = $1 WHERE id = $2`, "not-a-valid-ciphertext", integrationID); err != nil {
					t.Fatalf("corrupt encrypted token: %v", err)
				}
			},
			wantCode: connect.CodeFailedPrecondition,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beforeCalls := providerCalls
			integrationID, findingID := seedSlackFinding(t, app, auth, tc.mode, "xoxp-config-failure", "TCFG"+strings.ToUpper(randomBase36(6)), `{"subject":"EVIDENCE_APP"}`)
			if tc.mutate != nil {
				tc.mutate(integrationID)
			}
			_, err := app.compatRemediateFinding(ctx, findingID, map[string]any{"action": "slack.revoke_app_install", "targetIdentifier": "A123"}, auth)
			if code := connect.CodeOf(err); code != tc.wantCode {
				t.Fatalf("error code = %v (%v), want %v", code, err, tc.wantCode)
			}
			if providerCalls != beforeCalls {
				t.Fatalf("expected no provider call, got %d new calls", providerCalls-beforeCalls)
			}
			assertFindingState(t, app, findingID, "OPEN", false)
			assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 0)
			assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 0)
			assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
		})
	}
}

func TestDBSlackRemediationTypedAndCallApiSuccessAgree(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	seenAppIDs := []string{}
	seenTeamIDs := []string{}
	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if r.URL.Path != "/admin.apps.uninstall" {
			t.Fatalf("path = %s, want /admin.apps.uninstall", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		seenAppIDs = append(seenAppIDs, r.Form.Get("app_id"))
		seenTeamIDs = append(seenTeamIDs, r.Form.Get("team_ids"))
		requestID := "slack-callapi-success"
		if providerCalls == 2 {
			requestID = "slack-typed-success"
		}
		w.Header().Set("X-Slack-Req-Id", requestID)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, callFindingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-success-token", "TSUCC111", `{"subject":"EVIDENCE_APP","actor":"EVIDENCE_ACTOR"}`)
	_, typedFindingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-success-token", "TSUCC222", `{"subject":"EVIDENCE_APP","actor":"EVIDENCE_ACTOR"}`)

	callData, err := callRemediationViaCallAPI(t, app, ctx, header, callFindingID, `{"action":"slack.revoke_app_install","targetIdentifier":"A123","note":"remove app"}`)
	if err != nil {
		t.Fatalf("CallApi Slack remediation: %v", err)
	}
	typedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        typedFindingID,
		Action:           "slack.revoke_app_install",
		TargetIdentifier: "A123",
		Note:             "remove app",
	})
	copyCompatHeaders(typedReq.Header(), header)
	typedResp, err := app.RemediateFinding(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed Slack remediation: %v", err)
	}
	typed := typedResp.Msg.Data

	if callData["success"] != true || !typed.Success {
		t.Fatalf("expected both surfaces to succeed, CallApi=%v typed=%v", callData, typed)
	}
	if stringFromAny(callData["action"]) != typed.Action || typed.Action != "slack.revoke_app_install" {
		t.Fatalf("action mismatch: CallApi=%v typed=%v", callData["action"], typed.Action)
	}
	if stringFromAny(callData["providerRequestId"]) == "" || typed.ProviderRequestId == "" {
		t.Fatalf("missing provider request ids: CallApi=%v typed=%v", callData["providerRequestId"], typed.ProviderRequestId)
	}
	if len(stringSlice(callData["effects"])) == 0 || len(typed.Effects) == 0 {
		t.Fatalf("expected provider effects: CallApi=%#v typed=%#v", callData["effects"], typed.Effects)
	}
	if providerCalls != 2 {
		t.Fatalf("expected two provider calls, got %d", providerCalls)
	}
	if len(seenAppIDs) != 2 || seenAppIDs[0] != "A123" || seenAppIDs[1] != "A123" {
		t.Fatalf("Slack app ids = %v, want explicit A123 for both surfaces", seenAppIDs)
	}
	if len(seenTeamIDs) != 2 || seenTeamIDs[0] != "TSUCC111" || seenTeamIDs[1] != "TSUCC222" {
		t.Fatalf("Slack team ids = %v", seenTeamIDs)
	}
	assertFindingState(t, app, callFindingID, "RESOLVED", true)
	assertFindingState(t, app, typedFindingID, "RESOLVED", true)
	for _, findingID := range []string{callFindingID, typedFindingID} {
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 1)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 1)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 0)
	}
}

func TestDBSlackRemediationTypedAndCallApiFailureAndMissingTargetAgree(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	providerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("app_id"); got != "A123" {
			t.Fatalf("app_id = %q, want A123", got)
		}
		requestID := "slack-callapi-failed"
		if providerCalls == 2 {
			requestID = "slack-typed-failed"
		}
		w.Header().Set("X-Slack-Req-Id", requestID)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing_scope"})
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, callFailureID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-failure-token", "TFAILAPI", `{"subject":"EVIDENCE_APP"}`)
	_, typedFailureID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-failure-token", "TFAILTYP", `{"subject":"EVIDENCE_APP"}`)
	callData, err := callRemediationViaCallAPI(t, app, ctx, header, callFailureID, `{"action":"slack.revoke_app_install","targetIdentifier":"A123"}`)
	if err != nil {
		t.Fatalf("CallApi Slack provider failure: %v", err)
	}
	typedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        typedFailureID,
		Action:           "slack.revoke_app_install",
		TargetIdentifier: "A123",
	})
	copyCompatHeaders(typedReq.Header(), header)
	typedResp, err := app.RemediateFinding(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed Slack provider failure: %v", err)
	}
	typed := typedResp.Msg.Data
	if callData["success"] != false || typed.Success {
		t.Fatalf("expected both surfaces to fail, CallApi=%v typed=%v", callData, typed)
	}
	if stringFromAny(callData["message"]) != typed.Message {
		t.Fatalf("message mismatch: CallApi=%q typed=%q", callData["message"], typed.Message)
	}
	if stringFromAny(callData["providerRequestId"]) == "" || typed.ProviderRequestId == "" {
		t.Fatalf("missing provider failure request ids: CallApi=%v typed=%v", callData["providerRequestId"], typed.ProviderRequestId)
	}
	if len(stringSlice(callData["effects"])) != 0 || len(typed.Effects) != 0 {
		t.Fatalf("expected no failure effects, CallApi=%#v typed=%#v", callData["effects"], typed.Effects)
	}
	assertFindingState(t, app, callFailureID, "OPEN", false)
	assertFindingState(t, app, typedFailureID, "OPEN", false)
	for _, findingID := range []string{callFailureID, typedFailureID} {
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 1)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 1)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
	}

	_, callMissingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-missing-target", "TMISSAPI", `{"subject":"EVIDENCE_SHOULD_NOT_BE_USED","actor":"ACTOR_SHOULD_NOT_BE_USED"}`)
	_, typedMissingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-missing-target", "TMISSTYP", `{"subject":"EVIDENCE_SHOULD_NOT_BE_USED","actor":"ACTOR_SHOULD_NOT_BE_USED"}`)
	beforeMissingTargetCalls := providerCalls
	if _, err := callRemediationViaCallAPI(t, app, ctx, header, callMissingID, `{"action":"slack.revoke_app_install"}`); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CallApi missing target code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}
	missingTypedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId: typedMissingID,
		Action:    "slack.revoke_app_install",
	})
	copyCompatHeaders(missingTypedReq.Header(), header)
	if _, err := app.RemediateFinding(ctx, missingTypedReq); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("typed missing target code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}
	if providerCalls != beforeMissingTargetCalls {
		t.Fatalf("expected no provider calls for missing target, got %d", providerCalls-beforeMissingTargetCalls)
	}
	for _, findingID := range []string{callMissingID, typedMissingID} {
		assertFindingState(t, app, findingID, "OPEN", false)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 0)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 0)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
	}
}

func TestDBRemediationTypedAndCallApiRBACDenialAgree(t *testing.T) {
	app, auth := newTestDBApp(t)
	admin := seedOrgAdmin(t, app, auth.OrganizationID)
	analyst := seedOrgUserWithRole(t, app, auth.OrganizationID, "SECURITY_ANALYST")
	ctx := context.Background()
	header := seedSessionHeader(t, app, analyst)
	header.Set("X-Forwarded-For", "203.0.113.41")

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, findingID := seedSlackFinding(t, app, admin, "REMEDIATION", "xoxp-rbac-token", "TRBAC123", `{"subject":"EVIDENCE_APP"}`)

	_, callErr := callRemediationViaCallAPI(t, app, ctx, header, findingID, `{"action":"slack.revoke_app_install","targetIdentifier":"A123"}`)
	if code := connect.CodeOf(callErr); code != connect.CodePermissionDenied {
		t.Fatalf("CallApi RBAC denial code = %v (%v), want CodePermissionDenied", code, callErr)
	}
	typedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        findingID,
		Action:           "slack.revoke_app_install",
		TargetIdentifier: "A123",
	})
	copyCompatHeaders(typedReq.Header(), header)
	_, typedErr := app.RemediateFinding(ctx, typedReq)
	if code := connect.CodeOf(typedErr); code != connect.CodePermissionDenied {
		t.Fatalf("typed RBAC denial code = %v (%v), want CodePermissionDenied", code, typedErr)
	}
	if callErr.Error() != typedErr.Error() {
		t.Fatalf("RBAC denial error mismatch: CallApi=%q typed=%q", callErr.Error(), typedErr.Error())
	}
	if providerCalls != 0 {
		t.Fatalf("RBAC denial must not call Slack, got %d provider calls", providerCalls)
	}
	assertFindingState(t, app, findingID, "OPEN", false)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
}

func TestDBRemediationTypedAndCallApiRateLimitExhaustionAgree(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, callFindingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-rate-call", "TRATECAL", `{"subject":"EVIDENCE_APP"}`)
	_, typedFindingID := seedSlackFinding(t, app, auth, "REMEDIATION", "xoxp-rate-typed", "TRATETYP", `{"subject":"EVIDENCE_APP"}`)

	callHeader := seedSessionHeader(t, app, auth)
	callHeader.Set("X-Forwarded-For", "198.51.100.91")
	callPath := "/api/v1/findings/" + callFindingID + "/remediate"
	seedExhaustedRateLimitBucket(t, app, callHeader, http.MethodPost, callPath)
	_, callErr := callRemediationViaCallAPI(t, app, ctx, callHeader, callFindingID, `{"action":"slack.revoke_app_install","targetIdentifier":"A123"}`)
	if code := connect.CodeOf(callErr); code != connect.CodeResourceExhausted {
		t.Fatalf("CallApi rate limit code = %v (%v), want CodeResourceExhausted", code, callErr)
	}

	typedHeader := seedSessionHeader(t, app, auth)
	typedHeader.Set("X-Forwarded-For", "198.51.100.92")
	typedPath := "/api/v1/findings/" + typedFindingID + "/remediate"
	seedExhaustedRateLimitBucket(t, app, typedHeader, http.MethodPost, typedPath)
	typedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        typedFindingID,
		Action:           "slack.revoke_app_install",
		TargetIdentifier: "A123",
	})
	copyCompatHeaders(typedReq.Header(), typedHeader)
	_, typedErr := app.RemediateFinding(ctx, typedReq)
	if code := connect.CodeOf(typedErr); code != connect.CodeResourceExhausted {
		t.Fatalf("typed rate limit code = %v (%v), want CodeResourceExhausted", code, typedErr)
	}
	if callErr.Error() != typedErr.Error() {
		t.Fatalf("rate limit error mismatch: CallApi=%q typed=%q", callErr.Error(), typedErr.Error())
	}
	if providerCalls != 0 {
		t.Fatalf("rate-limited remediation must not call Slack, got %d provider calls", providerCalls)
	}
	for _, findingID := range []string{callFindingID, typedFindingID} {
		assertFindingState(t, app, findingID, "OPEN", false)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.requested", 0)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.failure", 0)
		assertAuditActionCount(t, app, auth.OrganizationID, findingID, "finding.remediate.success", 0)
	}
}

func TestDBManualFindingStatusActionsRemainLocal(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	var providerCalls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		providerCalls++
	}))
	defer server.Close()
	app.remediationHTTPClient = server.Client()
	app.slackAPIBaseURL = server.URL

	_, resolvedFindingID := seedRemediationFixture(t, app, auth, "SLACK")
	resolveReq := connect.NewRequest(&aperiov1.UpdateFindingStatusRequest{
		Id:             resolvedFindingID,
		Status:         "RESOLVED",
		ResolutionNote: "operator verified the fix",
	})
	copyCompatHeaders(resolveReq.Header(), header)
	resolveResp, err := app.UpdateFindingStatus(ctx, resolveReq)
	if err != nil {
		t.Fatalf("typed mark resolved: %v", err)
	}
	if resolveResp.Msg.Data.GetStatus() != "RESOLVED" {
		t.Fatalf("typed status = %s, want RESOLVED", resolveResp.Msg.Data.GetStatus())
	}
	assertFindingState(t, app, resolvedFindingID, "RESOLVED", true)
	assertAuditActionCount(t, app, auth.OrganizationID, resolvedFindingID, "finding.status.update", 1)
	assertAuditActionCount(t, app, auth.OrganizationID, resolvedFindingID, "finding.remediate.requested", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, resolvedFindingID, "finding.remediate.success", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, resolvedFindingID, "finding.remediate.failure", 0)

	_, mutedFindingID := seedRemediationFixture(t, app, auth, "SLACK")
	patchReq := connect.NewRequest(&aperiov1.CallApiRequest{
		Method:   http.MethodPatch,
		Path:     "/api/v1/findings/" + mutedFindingID,
		BodyJson: `{"status":"MUTED","resolutionNote":"accepted risk locally"}`,
	})
	copyCompatHeaders(patchReq.Header(), header)
	patchResp, err := app.CallApi(ctx, patchReq)
	if err != nil {
		t.Fatalf("CallApi accept risk status update: %v", err)
	}
	var patchEnvelope map[string]any
	if err := json.Unmarshal([]byte(patchResp.Msg.BodyJson), &patchEnvelope); err != nil {
		t.Fatalf("decode status update response: %v", err)
	}
	patchData := dataMap(t, patchEnvelope)
	if patchData["status"] != "MUTED" {
		t.Fatalf("CallApi status = %v, want MUTED", patchData["status"])
	}
	assertFindingState(t, app, mutedFindingID, "MUTED", true)
	assertAuditActionCount(t, app, auth.OrganizationID, mutedFindingID, "finding.status.update", 1)
	assertAuditActionCount(t, app, auth.OrganizationID, mutedFindingID, "finding.remediate.requested", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, mutedFindingID, "finding.remediate.success", 0)
	assertAuditActionCount(t, app, auth.OrganizationID, mutedFindingID, "finding.remediate.failure", 0)
	if providerCalls != 0 {
		t.Fatalf("manual status updates must not call Slack, got %d provider calls", providerCalls)
	}
}

func TestDBUnsupportedRemediationsRemainUnresolved(t *testing.T) {
	t.Setenv("APERIO_ALLOW_PREVIEW_CONNECTORS", "true")
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()

	for _, definition := range remediationActionDefinitions {
		if definition.Class != remediationActionUnsupported {
			continue
		}
		t.Run(definition.Action, func(t *testing.T) {
			_, findingID := seedRemediationFixture(t, app, auth, definition.Provider)
			result := dataMap(t, mustCall(t, func() (any, error) {
				return app.compatRemediateFinding(ctx, findingID, map[string]any{"action": definition.Action, "targetIdentifier": "user@example.com"}, auth)
			}))
			if result["success"] != false {
				t.Fatalf("expected unsupported remediation failure, got %v", result)
			}
			if result["providerRequestId"] != "" {
				t.Fatalf("unsupported remediation returned provider request id %q", result["providerRequestId"])
			}
			if effects, ok := result["effects"].([]string); !ok || len(effects) != 0 {
				t.Fatalf("expected no provider effects, got %#v", result["effects"])
			}
			if !strings.Contains(strings.ToLower(result["message"].(string)), "unavailable") {
				t.Fatalf("expected unavailable message, got %q", result["message"])
			}

			var status string
			var resolvedAt sql.NullTime
			if err := app.db.QueryRowContext(ctx, `SELECT status::text, resolved_at FROM security_findings WHERE id = $1`, findingID).Scan(&status, &resolvedAt); err != nil {
				t.Fatalf("query finding state: %v", err)
			}
			if status != "OPEN" || resolvedAt.Valid {
				t.Fatalf("finding state = (%s,%v), want OPEN with null resolved_at", status, resolvedAt.Valid)
			}
			var successAuditRows int
			if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.success'`, auth.OrganizationID, findingID).Scan(&successAuditRows); err != nil {
				t.Fatalf("count success audits: %v", err)
			}
			if successAuditRows != 0 {
				t.Fatalf("expected no success audit rows, got %d", successAuditRows)
			}
			var failureMetadata string
			if err := app.db.QueryRowContext(ctx, `SELECT metadata::text FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = 'finding.remediate.failure'`, auth.OrganizationID, findingID).Scan(&failureMetadata); err != nil {
				t.Fatalf("query failure audit metadata: %v", err)
			}
			if strings.Contains(failureMetadata, "providerRequestId") || strings.Contains(failureMetadata, "effects") {
				t.Fatalf("failure audit metadata exposed provider-looking fields: %s", failureMetadata)
			}
		})
	}
}

func TestDBUnsupportedRemediationTypedAndCallApiAgree(t *testing.T) {
	t.Setenv("APERIO_ALLOW_PREVIEW_CONNECTORS", "true")
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)
	_, findingID := seedRemediationFixture(t, app, auth, "OKTA")

	callReq := connect.NewRequest(&aperiov1.CallApiRequest{
		Method:   http.MethodPost,
		Path:     "/api/v1/findings/" + findingID + "/remediate",
		BodyJson: `{"action":"okta.suspend_user","targetIdentifier":"user@example.com"}`,
	})
	for key, values := range header {
		for _, value := range values {
			callReq.Header().Add(key, value)
		}
	}
	callResp, err := app.CallApi(ctx, callReq)
	if err != nil {
		t.Fatalf("CallApi remediation: %v", err)
	}
	var callEnvelope map[string]any
	if err := json.Unmarshal([]byte(callResp.Msg.BodyJson), &callEnvelope); err != nil {
		t.Fatalf("decode CallApi response: %v", err)
	}
	callData := dataMap(t, callEnvelope)

	typedReq := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        findingID,
		Action:           "okta.suspend_user",
		TargetIdentifier: "user@example.com",
	})
	for key, values := range header {
		for _, value := range values {
			typedReq.Header().Add(key, value)
		}
	}
	typedResp, err := app.RemediateFinding(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed remediation: %v", err)
	}
	typed := typedResp.Msg.Data
	if callData["success"] != false || typed.Success {
		t.Fatalf("expected both surfaces to fail, CallApi=%v typed=%v", callData, typed)
	}
	if callData["message"] != typed.Message {
		t.Fatalf("message mismatch: CallApi=%q typed=%q", callData["message"], typed.Message)
	}
	if callData["providerRequestId"] != "" || typed.ProviderRequestId != "" {
		t.Fatalf("unexpected provider request ids: CallApi=%q typed=%q", callData["providerRequestId"], typed.ProviderRequestId)
	}
	if effects, ok := callData["effects"].([]any); !ok || len(effects) != 0 || len(typed.Effects) != 0 {
		t.Fatalf("expected no effects, CallApi=%#v typed=%#v", callData["effects"], typed.Effects)
	}

	var status string
	if err := app.db.QueryRowContext(ctx, `SELECT status::text FROM security_findings WHERE id = $1`, findingID).Scan(&status); err != nil {
		t.Fatalf("query finding status: %v", err)
	}
	if status != "OPEN" {
		t.Fatalf("finding status = %s, want OPEN", status)
	}

	unknownCall := connect.NewRequest(&aperiov1.CallApiRequest{
		Method:   http.MethodPost,
		Path:     "/api/v1/findings/" + findingID + "/remediate",
		BodyJson: `{"action":"okta.unknown_action","targetIdentifier":"user@example.com"}`,
	})
	for key, values := range header {
		for _, value := range values {
			unknownCall.Header().Add(key, value)
		}
	}
	if _, err := app.CallApi(ctx, unknownCall); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CallApi unknown action code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}
	unknownTyped := connect.NewRequest(&aperiov1.RemediateFindingRequest{
		FindingId:        findingID,
		Action:           "okta.unknown_action",
		TargetIdentifier: "user@example.com",
	})
	for key, values := range header {
		for _, value := range values {
			unknownTyped.Header().Add(key, value)
		}
	}
	if _, err := app.RemediateFinding(ctx, unknownTyped); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("typed unknown action code = %v (%v), want CodeInvalidArgument", connect.CodeOf(err), err)
	}
}

func TestDBGoogleMailboxScanConfig(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "GOOGLE_WORKSPACE",
		"displayName":       "Google Workspace",
		"externalAccountId": "example.com",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "google-example-access-token-1234567890"},
	}, auth)
	if err != nil {
		t.Fatalf("create google integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	auditAuth := auth
	auditAuth.UserID = ""
	const clientEmail = "mailbox-scanner@example.com"
	const privateKey = "example-google-mailbox-private-key-value-1234567890"
	enabled := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
			"enabled":                   true,
			"serviceAccountClientEmail": clientEmail,
			"privateKey":                privateKey,
		}, auditAuth)
	}))
	if enabled["enabled"] != true || enabled["serviceAccountClientEmail"] != clientEmail {
		t.Fatalf("unexpected enabled config: %v", enabled)
	}

	var encryptedKey string
	if err := app.db.QueryRowContext(ctx, `SELECT encrypted_google_mailbox_scan_private_key FROM integration_connections WHERE id = $1`, integrationID).Scan(&encryptedKey); err != nil {
		t.Fatalf("query mailbox key: %v", err)
	}
	plaintext, err := compatDecryptString(encryptedKey, compatIntegrationSecretAAD(auth.OrganizationID, "GOOGLE_WORKSPACE", "example.com", "gmail_scan_private_key"))
	if err != nil {
		t.Fatalf("decrypt mailbox key with canonical AAD: %v", err)
	}
	if plaintext != privateKey {
		t.Fatalf("decrypted mailbox key mismatch")
	}
	if _, err := compatDecryptString(encryptedKey, auth.OrganizationID+":"+integrationID+":google_mailbox_private_key"); err == nil {
		t.Fatal("expected legacy ad-hoc AAD to fail")
	}

	legacyEncryptedKey, err := compatEncryptString(privateKey, compatLegacyIntegrationSecretAAD(auth.OrganizationID, integrationID, "google_mailbox_private_key"))
	if err != nil {
		t.Fatalf("encrypt legacy mailbox key: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE integration_connections SET encrypted_google_mailbox_scan_private_key = $1 WHERE id = $2`, legacyEncryptedKey, integrationID); err != nil {
		t.Fatalf("seed legacy mailbox key: %v", err)
	}
	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": clientEmail,
	}, auditAuth); err != nil {
		t.Fatalf("reuse legacy mailbox key: %v", err)
	}

	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": clientEmail,
	}, auditAuth); err != nil {
		t.Fatalf("reuse existing mailbox key: %v", err)
	}
	if _, err := app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{
		"enabled":                   true,
		"serviceAccountClientEmail": "other-scanner@example.com",
	}, auditAuth); err == nil {
		t.Fatal("expected changing client email without a new key to fail")
	}

	disabled := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleMailboxConfig(ctx, integrationID, map[string]any{"enabled": false}, auditAuth)
	}))
	if disabled["enabled"] != false || disabled["serviceAccountClientEmail"] != nil {
		t.Fatalf("unexpected disabled config: %v", disabled)
	}

	var auditRows int
	if err := app.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action IN ('integration.google_mailbox_scan.enable','integration.google_mailbox_scan.disable')`, auth.OrganizationID, integrationID).Scan(&auditRows); err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	if auditRows != 4 {
		t.Fatalf("expected 4 mailbox audit rows, got %d", auditRows)
	}
}

func TestDBGoogleWorkspaceBigQueryConfig(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "GOOGLE_WORKSPACE",
		"displayName":       "Google Workspace",
		"externalAccountId": "bigquery.example.com",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "google-workspace-token"},
	}, auth)
	if err != nil {
		t.Fatalf("create google integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	config := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleWorkspaceBigQueryConfig(ctx, integrationID, map[string]any{
			"enabled":                  true,
			"projectId":                "example-project",
			"rawDatasetId":             "workspace_logs",
			"datasetId":                "aperio_workspace_views",
			"location":                 "US",
			"serviceAccountEmail":      "aperio-bq-reader@example-project.iam.gserviceaccount.com",
			"workloadIdentityProvider": "projects/123456789/locations/global/workloadIdentityPools/aperio-workloads/providers/aperio-oidc",
			"accessMode":               "views",
		}, auth)
	}))
	if config["enabled"] != true || optionalStringFromAny(config["datasetId"]) != "aperio_workspace_views" || optionalStringFromAny(config["accessMode"]) != "views" {
		t.Fatalf("unexpected BigQuery config: %v", config)
	}

	if _, err := app.compatUpdateGoogleWorkspaceBigQueryConfig(ctx, integrationID, map[string]any{
		"enabled":                  true,
		"projectId":                "example-project",
		"rawDatasetId":             "workspace_logs",
		"datasetId":                "workspace_logs",
		"location":                 "US",
		"serviceAccountEmail":      "aperio-bq-reader@example-project.iam.gserviceaccount.com",
		"workloadIdentityProvider": "projects/123456789/locations/global/workloadIdentityPools/aperio-workloads/providers/aperio-oidc",
		"accessMode":               "views",
	}, auth); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("same raw/read dataset code = %v (%v), want invalid argument", connect.CodeOf(err), err)
	}

	typedReq := connect.NewRequest(&aperiov1.GetGoogleWorkspaceBigQueryConfigRequest{IntegrationId: integrationID})
	copyCompatHeaders(typedReq.Header(), header)
	typed, err := app.GetGoogleWorkspaceBigQueryConfig(ctx, typedReq)
	if err != nil {
		t.Fatalf("typed get BigQuery config: %v", err)
	}
	if !typed.Msg.Data.Enabled || typed.Msg.Data.WorkloadIdentityProvider == "" {
		t.Fatalf("unexpected typed BigQuery config: %v", typed.Msg.Data)
	}

	cleared := dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleWorkspaceBigQueryConfig(ctx, integrationID, map[string]any{"enabled": false}, auth)
	}))
	if cleared["enabled"] != false || optionalStringFromAny(cleared["projectId"]) != "" {
		t.Fatalf("unexpected cleared BigQuery config: %v", cleared)
	}
}

func TestDBIntegrationSyncStatusAndBackfill(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()
	header := seedSessionHeader(t, app, auth)

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "GOOGLE_WORKSPACE",
		"displayName":       "Google Workspace",
		"externalAccountId": "sync-status.example.com",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "google-workspace-token"},
	}, auth)
	if err != nil {
		t.Fatalf("create google integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)
	_ = dataMap(t, mustCall(t, func() (any, error) {
		return app.compatUpdateGoogleWorkspaceBigQueryConfig(ctx, integrationID, map[string]any{
			"enabled":                  true,
			"projectId":                "sync-status-project",
			"rawDatasetId":             "workspace_logs",
			"datasetId":                "aperio_workspace_views",
			"location":                 "US",
			"serviceAccountEmail":      "aperio-bq-reader@sync-status-project.iam.gserviceaccount.com",
			"workloadIdentityProvider": "projects/123456789/locations/global/workloadIdentityPools/aperio-workloads/providers/aperio-oidc",
			"accessMode":               "views",
		}, auth)
	}))

	now := time.Now().UTC()
	cursorAt := now.Add(-5 * time.Minute)
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO google_workspace_sync_cursors (integration_id, application, last_event_time, last_unique_qualifier, last_polled_at, last_error)
		VALUES ($1, 'admin', $2, 'q1', $3, NULL)
		ON CONFLICT (integration_id, application) DO NOTHING
	`, integrationID, cursorAt, now); err != nil {
		t.Fatalf("seed reports cursor: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO google_workspace_bigquery_sync_cursors (integration_id, record_type, last_event_time, last_row_hash, last_polled_at, last_row_count, last_error)
		VALUES ($1, 'drive', $2, 'hash1', $3, 7, NULL)
		ON CONFLICT (integration_id, record_type) DO NOTHING
	`, integrationID, cursorAt.Add(-time.Minute), now); err != nil {
		t.Fatalf("seed BigQuery cursor: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO google_workspace_directory_sync_cursors (integration_id, last_synced_at, last_user_count, last_error)
		VALUES ($1, $2, 42, NULL)
		ON CONFLICT (integration_id) DO NOTHING
	`, integrationID, now); err != nil {
		t.Fatalf("seed directory cursor: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO google_workspace_oauth_sync_cursors (integration_id, last_synced_at, last_app_count, last_grant_count, last_error)
		VALUES ($1, $2, 3, 9, NULL)
		ON CONFLICT (integration_id) DO NOTHING
	`, integrationID, now); err != nil {
		t.Fatalf("seed oauth cursor: %v", err)
	}
	for index, status := range []string{"QUEUED", "FAILED", "SUCCEEDED"} {
		if _, err := app.db.ExecContext(ctx, `
			INSERT INTO ingestion_jobs (id, organization_id, integration_id, provider, event_type, source, occurred_at, payload, status, next_attempt_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'GOOGLE_WORKSPACE', 'GOOGLE_DRIVE_EXTERNAL_SHARING', 'google.reports.admin', $4, '{"ok":true}'::jsonb, $5::"IngestionJobStatus", NOW() + INTERVAL '1 hour', NOW(), NOW())
		`, compatID("ijb"), auth.OrganizationID, integrationID, now.Add(time.Duration(index)*time.Second), status); err != nil {
			t.Fatalf("seed ingestion job %s: %v", status, err)
		}
	}

	req := connect.NewRequest(&aperiov1.GetIntegrationSyncStatusRequest{IntegrationId: integrationID})
	copyCompatHeaders(req.Header(), header)
	resp, err := app.GetIntegrationSyncStatus(ctx, req)
	if err != nil {
		t.Fatalf("get sync status: %v", err)
	}
	findSource := func(kind, stream string) *aperiov1.IntegrationSourceSyncState {
		t.Helper()
		for _, source := range resp.Msg.Data.Sources {
			if source.SourceKind == kind && source.StreamName == stream {
				return source
			}
		}
		t.Fatalf("missing source %s/%s in %#v", kind, stream, resp.Msg.Data.Sources)
		return nil
	}
	reports := findSource("google_reports", "admin")
	if reports.Status != "healthy" || reports.QueueQueued != 1 || reports.QueueFailed != 1 || reports.QueueSucceeded != 1 {
		t.Fatalf("unexpected reports source status: %#v", reports)
	}
	bigQuery := findSource("google_bigquery", "drive")
	if bigQuery.RowsSeen != 7 || !bigQuery.BackfillSupported {
		t.Fatalf("unexpected BigQuery source status: %#v", bigQuery)
	}
	if directory := findSource("google_directory", "users"); directory.RowsSeen != 42 || directory.BackfillSupported {
		t.Fatalf("unexpected directory source status: %#v", directory)
	}
	if oauth := findSource("google_oauth", "grants"); oauth.RowsSeen != 9 || oauth.BackfillSupported || oauth.SyncNowSupported {
		t.Fatalf("unexpected OAuth source status: %#v", oauth)
	}
	oauthSyncReq := connect.NewRequest(&aperiov1.RunIntegrationSourceSyncRequest{
		IntegrationId: integrationID,
		SourceKind:    "google_oauth",
		StreamName:    "grants",
	})
	copyCompatHeaders(oauthSyncReq.Header(), header)
	if _, err := app.RunIntegrationSourceSync(ctx, oauthSyncReq); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("OAuth source sync before identities code = %v (%v), want failed precondition", connect.CodeOf(err), err)
	}
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO saas_identities
			(id, organization_id, integration_id, provider, external_id, display_name, kind, status, linked_asset_ids, is_privileged, is_external, mfa_enabled, risk_score, created_at, updated_at)
		VALUES ($1, $2, $3, 'GOOGLE_WORKSPACE', 'user-1', 'Workspace Admin', 'USER', 'ACTIVE', $4, true, false, true, 0, NOW(), NOW())
	`, compatID("sid"), auth.OrganizationID, integrationID, []string{"google-user-asset"}); err != nil {
		t.Fatalf("seed Google identity: %v", err)
	}
	resp, err = app.GetIntegrationSyncStatus(ctx, req)
	if err != nil {
		t.Fatalf("get sync status after identity seed: %v", err)
	}
	if oauth := findSource("google_oauth", "grants"); !oauth.SyncNowSupported {
		t.Fatalf("OAuth source sync should be enabled after identity seed: %#v", oauth)
	}

	backfillFrom := now.Add(-2 * time.Hour).UTC().Truncate(time.Second)
	backfillReq := connect.NewRequest(&aperiov1.BackfillIntegrationSourceRequest{
		IntegrationId: integrationID,
		SourceKind:    "google_bigquery",
		StreamName:    "drive",
		FromTime:      backfillFrom.Format(time.RFC3339Nano),
	})
	copyCompatHeaders(backfillReq.Header(), header)
	backfillResp, err := app.BackfillIntegrationSource(ctx, backfillReq)
	if err != nil {
		t.Fatalf("backfill BigQuery source: %v", err)
	}
	if !backfillResp.Msg.Data.Queued || backfillResp.Msg.Data.SourceKind != "google_bigquery" {
		t.Fatalf("unexpected backfill response: %#v", backfillResp.Msg.Data)
	}
	var persisted time.Time
	var backfillMarker string
	if err := app.db.QueryRowContext(ctx, `SELECT last_event_time, COALESCE(last_error, '') FROM google_workspace_bigquery_sync_cursors WHERE integration_id = $1 AND record_type = 'drive'`, integrationID).Scan(&persisted, &backfillMarker); err != nil {
		t.Fatalf("query backfill cursor: %v", err)
	}
	if !persisted.UTC().Equal(backfillFrom) {
		t.Fatalf("backfill cursor = %s, want %s", persisted.UTC(), backfillFrom)
	}
	if !strings.HasPrefix(backfillMarker, backfillQueuedPrefix) {
		t.Fatalf("backfill marker = %q, want queued marker", backfillMarker)
	}
	resp, err = app.GetIntegrationSyncStatus(ctx, req)
	if err != nil {
		t.Fatalf("get sync status after backfill: %v", err)
	}
	bigQuery = findSource("google_bigquery", "drive")
	if bigQuery.Status != "queued" || bigQuery.LastSuccessAt != "" {
		t.Fatalf("BigQuery backfill should remain queued until worker confirms completion: %#v", bigQuery)
	}
}

func TestDBSecurityOverview(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Prod",
		"externalAccountId": "T999000",
		"mode":              "READ_ONLY",
		"credentials":       map[string]any{"accessToken": "xoxb-overview-token-123456"},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)

	assetID := compatID("ast")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_assets (id, organization_id, integration_id, type, name, labels, criticality, exposure_level, ownership_status, contains_sensitive_data, is_privileged, risk_score, created_at, updated_at) VALUES ($1,$2,$3,'DATA_RESOURCE',$4,ARRAY[]::text[],'HIGH','PUBLIC','UNASSIGNED',true,true,70,NOW(),NOW())`, assetID, auth.OrganizationID, integrationID, "Customer DB"); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	identityID := compatID("idn")
	if _, err := app.db.ExecContext(ctx, `INSERT INTO saas_identities (id, organization_id, integration_id, provider, external_id, display_name, kind, status, linked_asset_ids, is_privileged, is_external, mfa_enabled, risk_score, created_at, updated_at) VALUES ($1,$2,$3,'SLACK',$4,$5,'USER','ACTIVE',$6,true,false,false,0,NOW(),NOW())`, identityID, auth.OrganizationID, integrationID, "admin@example.com", "Admin User", []string{assetID}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	overview, err := app.compatSecurityOverview(ctx, auth)
	if err != nil {
		t.Fatalf("security overview: %v", err)
	}
	data := dataMap(t, overview)
	identities, ok := data["identities"].([]any)
	if !ok || len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %v", data["identities"])
	}
	identity := identities[0].(map[string]any)
	if count := identity["linkedAssetCount"].(int); count < 1 {
		t.Fatalf("expected linkedAssetCount >= 1, got %d", count)
	}
	summary := data["summary"].(map[string]any)
	if summary["privilegedIdentities"].(int) != 1 {
		t.Fatalf("expected 1 privileged identity, got %v", summary["privilegedIdentities"])
	}
}

func mustCall(t *testing.T, fn func() (any, error)) any {
	t.Helper()
	result, err := fn()
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	return result
}

func seedSlackFinding(t *testing.T, app *App, auth compatAuth, mode, accessToken, externalAccountID, evidence string) (string, string) {
	t.Helper()
	ctx := context.Background()
	created, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "SLACK",
		"displayName":       "Slack Remediation " + randomBase36(6),
		"externalAccountId": externalAccountID,
		"mode":              mode,
		"credentials":       map[string]any{"accessToken": accessToken},
	}, auth)
	if err != nil {
		t.Fatalf("create Slack integration: %v", err)
	}
	integrationID := dataMap(t, created)["id"].(string)
	findingID := compatID("fnd")
	if strings.TrimSpace(evidence) == "" {
		evidence = `{}`
	}
	if _, err := app.db.ExecContext(ctx, `INSERT INTO security_findings (id, organization_id, integration_id, dedupe_key, title, description, severity, status, risk_score, remediation_steps, evidence, detected_at) VALUES ($1,$2,$3,$4,$5,$6,'HIGH','OPEN',70,ARRAY[]::text[],$7,NOW())`, findingID, auth.OrganizationID, integrationID, "dk-"+findingID, "Suspicious Slack app", "seeded for remediation test", json.RawMessage(evidence)); err != nil {
		t.Fatalf("seed Slack finding: %v", err)
	}
	return integrationID, findingID
}

func callRemediationViaCallAPI(t *testing.T, app *App, ctx context.Context, header http.Header, findingID string, bodyJSON string) (map[string]any, error) {
	t.Helper()
	req := connect.NewRequest(&aperiov1.CallApiRequest{
		Method:   http.MethodPost,
		Path:     "/api/v1/findings/" + findingID + "/remediate",
		BodyJson: bodyJSON,
	})
	copyCompatHeaders(req.Header(), header)
	resp, err := app.CallApi(ctx, req)
	if err != nil {
		return nil, err
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(resp.Msg.BodyJson), &envelope); err != nil {
		t.Fatalf("decode CallApi remediation response: %v", err)
	}
	return dataMap(t, envelope), nil
}

func callCompatViaCallAPI(t *testing.T, app *App, ctx context.Context, header http.Header, method string, path string, bodyJSON string) (map[string]any, error) {
	t.Helper()
	req := connect.NewRequest(&aperiov1.CallApiRequest{
		Method:   method,
		Path:     path,
		BodyJson: bodyJSON,
	})
	copyCompatHeaders(req.Header(), header)
	resp, err := app.CallApi(ctx, req)
	if err != nil {
		return nil, err
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(resp.Msg.BodyJson), &envelope); err != nil {
		t.Fatalf("decode CallApi %s %s response: %v", method, path, err)
	}
	return envelope, nil
}

func countSiemDestinations(t *testing.T, app *App, organizationID string) int {
	t.Helper()
	var count int
	if err := app.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM siem_destinations
		WHERE organization_id = $1
	`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count SIEM destinations: %v", err)
	}
	return count
}

func assertSiemDestinationHealth(t *testing.T, app *App, kind string, destinationID string, wantStatus string, wantOK int, wantFail int) {
	t.Helper()
	var status string
	var deliveriesOK, deliveriesFail int
	var lastDeliveryAt sql.NullTime
	var lastError sql.NullString
	if err := app.db.QueryRowContext(context.Background(), `
		SELECT status::text, deliveries_ok, deliveries_fail, last_delivery_at, last_error
		FROM siem_destinations
		WHERE id = $1
	`, destinationID).Scan(&status, &deliveriesOK, &deliveriesFail, &lastDeliveryAt, &lastError); err != nil {
		t.Fatalf("query %s SIEM destination health: %v", kind, err)
	}
	if status != wantStatus || deliveriesOK != wantOK || deliveriesFail != wantFail || !lastDeliveryAt.Valid || lastError.Valid {
		t.Fatalf("%s destination health = status=%s ok=%d fail=%d last=%v error=%v, want status=%s ok=%d fail=%d with last delivery and no error", kind, status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError, wantStatus, wantOK, wantFail)
	}
}

func seedExhaustedRateLimitBucket(t *testing.T, app *App, header http.Header, method, path string) {
	t.Helper()
	max, window, ok := compatRateLimitPolicy(path)
	if !ok {
		t.Fatalf("no rate limit policy for %s %s", method, path)
	}
	key := compatRateLimitKey(method, path, compatClientIdentity(header, ""), "")
	_, err := app.db.ExecContext(context.Background(), `
		INSERT INTO rate_limit_buckets (key, count, reset_at, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (key) DO UPDATE SET count = EXCLUDED.count, reset_at = EXCLUDED.reset_at, updated_at = NOW()
	`, key, max, time.Now().Add(window))
	if err != nil {
		t.Fatalf("seed rate limit bucket: %v", err)
	}
}

func assertFindingState(t *testing.T, app *App, findingID, wantStatus string, wantResolvedAt bool) {
	t.Helper()
	var status string
	var resolvedAt sql.NullTime
	if err := app.db.QueryRowContext(context.Background(), `SELECT status::text, resolved_at FROM security_findings WHERE id = $1`, findingID).Scan(&status, &resolvedAt); err != nil {
		t.Fatalf("query finding state: %v", err)
	}
	if status != wantStatus || resolvedAt.Valid != wantResolvedAt {
		t.Fatalf("finding state = (%s,resolved_at:%v), want (%s,resolved_at:%v)", status, resolvedAt.Valid, wantStatus, wantResolvedAt)
	}
}

func assertAssetOwners(t *testing.T, app *App, assetID, wantOwnerID, wantBusinessOwnerID string) {
	t.Helper()
	var ownerID sql.NullString
	var businessOwnerID sql.NullString
	if err := app.db.QueryRowContext(context.Background(), `
		SELECT owner_user_id, business_owner_user_id
		FROM security_assets
		WHERE id = $1
	`, assetID).Scan(&ownerID, &businessOwnerID); err != nil {
		t.Fatalf("query asset owners: %v", err)
	}
	if !ownerID.Valid || ownerID.String != wantOwnerID {
		t.Fatalf("owner_user_id = %v, want %s", ownerID, wantOwnerID)
	}
	if !businessOwnerID.Valid || businessOwnerID.String != wantBusinessOwnerID {
		t.Fatalf("business_owner_user_id = %v, want %s", businessOwnerID, wantBusinessOwnerID)
	}
}

func assertAuditActionCount(t *testing.T, app *App, organizationID, targetID, action string, want int) {
	t.Helper()
	var got int
	if err := app.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1 AND target_id = $2 AND action = $3`, organizationID, targetID, action).Scan(&got); err != nil {
		t.Fatalf("count audit action %s: %v", action, err)
	}
	if got != want {
		t.Fatalf("audit action %s count = %d, want %d", action, got, want)
	}
}
