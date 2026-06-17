package bootstrap

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/gen/aperio/v1/aperiov1connect"
	"github.com/writer/aperio/internal/config"
	"golang.org/x/crypto/scrypt"
)

// TestCheckHealthConnectEndpoint exercises the generated Go Connect client
// against the in-process server. This catches handler registration drift without
// requiring Postgres.
func TestCheckHealthConnectEndpoint(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := aperiov1connect.NewAperioServiceClient(server.Client(), server.URL)

	resp, err := client.CheckHealth(
		context.Background(),
		connect.NewRequest(&aperiov1.CheckHealthRequest{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Status != "degraded" {
		t.Fatalf("expected degraded without database, got %s", resp.Msg.Status)
	}
	if resp.Msg.CheckedAt == nil {
		t.Fatal("expected checked_at timestamp")
	}
	if len(resp.Msg.Components) == 0 {
		t.Fatal("expected component health details")
	}
}

func TestTypedCatalogConnectEndpointIsRegistered(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	client := aperiov1connect.NewAperioServiceClient(server.Client(), server.URL)

	_, err := client.ListConnectorCatalog(
		context.Background(),
		connect.NewRequest(&aperiov1.ListConnectorCatalogRequest{}),
	)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("expected unavailable without database, got %v", err)
	}
}

func TestReadyzReportsDependencyHealth(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected degraded readiness status, got %d", rec.Code)
	}
}

func TestAggregateRiskScoreMatchesClampedPostureShape(t *testing.T) {
	score := aggregateRiskScore([]riskFinding{
		{
			RiskScore:  95,
			Severity:   "CRITICAL",
			DetectedAt: nowMinus(t, time.Hour),
			Evidence:   map[string]any{"visibility": "public"},
			Provider:   "GITHUB",
		},
		{
			RiskScore:  90,
			Severity:   "HIGH",
			DetectedAt: nowMinus(t, 2*time.Hour),
			Provider:   "SLACK",
		},
	})

	if score < 1 || score > 100 {
		t.Fatalf("expected clamped posture score, got %d", score)
	}
	if score == 185 {
		t.Fatal("expected weighted aggregate, not raw risk score sum")
	}
}

func TestCalculateFindingRiskScoreMirrorsTypeScriptEvidenceBonuses(t *testing.T) {
	score := calculateFindingRiskScore(riskFinding{
		RiskScore:  10,
		Severity:   "LOW",
		DetectedAt: nowMinus(t, 40*24*time.Hour),
		Evidence: map[string]any{
			"mailbox":     "alice@example.com",
			"role":        "admin",
			"mfaEnrolled": false,
			"visibility":  "external",
			"riskReason":  "mailbox delegate",
			"scopeCount":  float64(3),
			"delegates":   []any{"bob@external.example"},
			"comboKinds":  []any{"oauth_scope", "mailbox_delegate"},
		},
	})

	if score != 62 {
		t.Fatalf("expected TS-compatible score 62, got %d", score)
	}
}

func TestFindingRowToProtoMatchesRestShape(t *testing.T) {
	finding := findingRow{
		ID:               "finding_1",
		AssetID:          "asset_1",
		Title:            "External delegate",
		Description:      "Mailbox has an external delegate",
		Severity:         "HIGH",
		Status:           "OPEN",
		RiskScore:        50,
		RemediationSteps: []string{"Review delegate"},
		Evidence:         map[string]any{"visibility": "external"},
		EvidenceJSON:     `{"visibility":"external"}`,
		DetectedAt:       nowMinus(t, time.Hour),
		IntegrationID:    "integration_1",
		Provider:         "GOOGLE_WORKSPACE",
		DisplayName:      "Google Workspace",
	}

	proto := finding.toProto()

	if proto.Id != finding.ID {
		t.Fatalf("expected id %s, got %s", finding.ID, proto.Id)
	}
	if proto.RiskScore <= int32(finding.RiskScore) {
		t.Fatalf("expected calculated risk score above base, got %d", proto.RiskScore)
	}
	if proto.EvidenceJson != finding.EvidenceJSON {
		t.Fatal("expected evidence JSON to round-trip")
	}
	if proto.Integration.Provider != "GOOGLE_WORKSPACE" {
		t.Fatalf("expected provider, got %s", proto.Integration.Provider)
	}
}

func TestValidateFindingFiltersRejectsUnknownValues(t *testing.T) {
	if err := validateFindingFilters("HIGH", "OPEN", "GITHUB"); err != nil {
		t.Fatalf("expected valid filters, got %v", err)
	}
	if err := validateFindingFilters("SEVERE", "OPEN", "GITHUB"); err == nil {
		t.Fatal("expected invalid severity to fail")
	}
}

func TestValidateFindingListRequestRejectsLimitAboveRestMax(t *testing.T) {
	if err := validateFindingListRequest(&aperiov1.ListFindingsRequest{Limit: 100}); err != nil {
		t.Fatalf("expected REST-compatible limit to pass, got %v", err)
	}
	if err := validateFindingListRequest(&aperiov1.ListFindingsRequest{Limit: 101}); err == nil {
		t.Fatal("expected limit above REST max to fail")
	}
}

func TestRPCWideEventCarriesCanonicalDebugDimensions(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	event := app.buildRPCWideEvent(rpcWideEvent{
		Method:         "ListFindings",
		OrganizationID: "org_123",
		Status:         "success",
		Started:        time.Now().Add(-25 * time.Millisecond),
		Dimensions: map[string]string{
			"http.route.query.status": "OPEN",
		},
		Measurements: map[string]int64{
			"result.count": 3,
		},
	})

	if event.Dimensions["main"] != "true" {
		t.Fatal("expected canonical main wide-event marker")
	}
	if event.Dimensions["unit_of_work"] != "connect_rpc" {
		t.Fatal("expected unit-of-work dimension")
	}
	if event.Dimensions["rpc.method"] != "ListFindings" {
		t.Fatal("expected rpc method dimension")
	}
	if event.Dimensions["user.org.id"] != "org_123" {
		t.Fatal("expected tenant dimension")
	}
	if event.Measurements["duration_ms"] < 0 {
		t.Fatal("expected non-negative duration")
	}
	if event.Measurements["result.count"] != 3 {
		t.Fatal("expected result count measurement")
	}
}

// TestConnectCORSPreflight verifies browser clients can call ConnectRPC with
// credentials. The allowed origin must match exactly because session cookies are
// cross-runtime auth material.
func TestConnectCORSPreflight(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(http.MethodOptions, "/aperio.v1.AperioService/GetDashboardMetrics", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("expected matching CORS origin")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("expected credentialed CORS")
	}
}

func TestConnectCORSPreflightAllowsCommaSeparatedOrigins(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "https://app.example.com, http://localhost:3000/"}, nil)
	req := httptest.NewRequest(http.MethodOptions, "/aperio.v1.AperioService/GetDashboardMetrics", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("expected matching CORS origin from allow-list")
	}
}

func TestCookieBackedConnectRequiresAllowedOrigin(t *testing.T) {
	app := NewApp(config.Config{WebOrigin: "http://localhost:3000"}, nil)
	req := httptest.NewRequest(
		http.MethodPost,
		"/aperio.v1.AperioService/GetDashboardMetrics",
		bytes.NewBufferString("{}"),
	)
	req.Header.Set("Cookie", "aperio_session=session.raw")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestCompatRoleEnforcementRejectsViewerAdminWrites(t *testing.T) {
	err := requireCompatRole(compatAuth{Role: "VIEWER"}, "OWNER", "ADMIN")
	if err == nil {
		t.Fatal("expected viewer to be rejected for admin-only action")
	}
}

func TestCompatSiemEndpointRejectsPrivateHosts(t *testing.T) {
	loopback := "http://127.0.0.1:9000/events"
	if err := validateCompatSiemEndpoint(&loopback); err == nil {
		t.Fatal("expected loopback SIEM endpoint to be rejected")
	}
	public := "https://8.8.8.8/events"
	if err := validateCompatSiemEndpoint(&public); err != nil {
		t.Fatalf("expected public SIEM endpoint to pass, got %v", err)
	}
}

func TestCompatOktaDomainRejectsPrivateHosts(t *testing.T) {
	if err := validateCompatOktaDomain("169.254.169.254"); err == nil {
		t.Fatal("expected metadata IP to be rejected")
	}
	if err := validateCompatOktaDomain("tenant.okta.com/path"); err == nil {
		t.Fatal("expected Okta domain with path to be rejected")
	}
	if err := validateCompatOktaDomain("tenant.okta.com"); err != nil {
		t.Fatalf("expected Okta tenant host to pass, got %v", err)
	}
}

func TestCompatRateLimitUsesSeparateIPAndSubjectBuckets(t *testing.T) {
	subject := compatRateLimitSubject([]string{"", "Acme", "owner@example.com", " "})
	if subject != "Acme:owner@example.com" {
		t.Fatalf("unexpected subject %q", subject)
	}
	ipKey := compatRateLimitKey(http.MethodPost, "/api/v1/auth/login", "203.0.113.1", "")
	subjectKey := compatRateLimitKey(http.MethodPost, "/api/v1/auth/login", "203.0.113.1", subject)
	if ipKey == subjectKey {
		t.Fatal("expected global IP bucket and per-subject bucket to differ")
	}
	rotatedSubjectKey := compatRateLimitKey(http.MethodPost, "/api/v1/auth/login", "198.51.100.44", subject)
	if subjectKey != rotatedSubjectKey {
		t.Fatal("expected per-subject bucket to ignore client address rotation")
	}
	if _, _, ok := compatRateLimitPolicy("/api/v1/auth/workspaces/switch"); !ok {
		t.Fatal("workspace switch re-auth must stay rate limited")
	}
	if _, _, ok := compatRateLimitPolicy(emailDomainHealthListRateLimitPath); !ok {
		t.Fatal("email domain list path must stay rate limited")
	}
	if _, _, ok := compatRateLimitPolicy(emailDomainHealthGetRateLimitPath); !ok {
		t.Fatal("email domain detail path must stay rate limited")
	}
	if _, _, ok := compatRateLimitPolicy(emailDomainHealthRefreshRatePath); !ok {
		t.Fatal("email domain refresh path must stay rate limited")
	}
	for _, path := range []string{
		"/api/v1/integrations/int_123/source-sync",
		"/api/v1/integrations/int_123/source-backfill",
	} {
		if _, _, ok := compatRateLimitPolicy(path); !ok {
			t.Fatalf("%s must stay rate limited", path)
		}
	}
}

func TestApplyCursorStateTreatsQueuedBackfillAsPendingWork(t *testing.T) {
	state := newSyncState(sourceGoogleReports, "drive", "Reports API: drive", "", queueCounts{}, true, true)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cursor := now.Add(-24 * time.Hour)
	attempt := now.Add(-time.Minute)

	applyCursorState(state, cursor, attempt, queuedBackfillMessage(cursor), 0, now)

	if state.Status != "queued" {
		t.Fatalf("status = %q, want queued", state.Status)
	}
	if state.LastSuccessAt != "" {
		t.Fatalf("last_success_at = %q, want empty until worker confirms completion", state.LastSuccessAt)
	}
	if state.LastError != "" {
		t.Fatalf("last_error = %q, want queued backfill marker hidden from error field", state.LastError)
	}
}

func TestApplyCursorStatePreservesRowsSeenOnError(t *testing.T) {
	state := newSyncState(sourceGoogleBigQuery, "drive", "BigQuery export: drive", "", queueCounts{}, true, true)
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	cursor := now.Add(-24 * time.Hour)
	attempt := now.Add(-time.Minute)

	applyCursorState(state, cursor, attempt, "access token failed", 42, now)

	if state.Status != "error" {
		t.Fatalf("status = %q, want error", state.Status)
	}
	if state.RowsSeen != 42 {
		t.Fatalf("rows_seen = %d, want preserved last count", state.RowsSeen)
	}
}

func TestValidateSourceStreamRejectsUnhonoredStreams(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		stream string
	}{
		{kind: "all", stream: "drive"},
		{kind: sourceGoogleDirectory, stream: "groups"},
		{kind: sourceGoogleOAuth, stream: "users"},
	} {
		if err := validateSourceStream(tc.kind, tc.stream, true); err == nil {
			t.Fatalf("validateSourceStream(%q, %q) returned nil, want error", tc.kind, tc.stream)
		}
	}
}

func TestCompatClientIdentityHonorsForwardedHeadersFromTrustedProxy(t *testing.T) {
	header := http.Header{}
	header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.20")
	header.Set("X-Real-IP", "192.0.2.30")
	if got := compatClientIdentity(header, "10.0.0.10:44321"); got != "203.0.113.20" {
		t.Fatalf("expected trusted proxy to use the appended forwarded client, got %q", got)
	}
	if got := compatClientIdentity(header, "203.0.113.99:44321"); got != "203.0.113.99" {
		t.Fatalf("expected untrusted peer address to ignore spoofable forwarded headers, got %q", got)
	}
	header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.11")
	if got := compatClientIdentity(header, "10.0.0.10:44321"); got != "198.51.100.10" {
		t.Fatalf("expected trusted proxy chain to skip private proxy hops, got %q", got)
	}
	if got := compatClientIdentity(header, ""); got != "unknown" {
		t.Fatalf("expected empty peer address to use unknown bucket, got %q", got)
	}
}

func TestTypedAuthSessionDropsCompatibilityToken(t *testing.T) {
	displayName := "User Example"
	payload := compatSessionPayload(
		"session-token-that-must-stay-cookie-only",
		compatSessionUser{
			ID:          "usr_1",
			Email:       "user@example.com",
			DisplayName: &displayName,
			MFAEnabled:  true,
			Role:        "OWNER",
		},
		compatSessionOrg{
			ID:   "org_1",
			Name: "Example Org",
			Slug: "example",
		},
	)
	session := authSessionFromMap(payload)

	if session.Token != "" {
		t.Fatalf("typed auth session exposed token %q", session.Token)
	}
	if session.User == nil || !session.User.MfaEnabled {
		t.Fatal("expected user session fields to remain populated")
	}
	if session.AuthContext == nil {
		t.Fatal("expected typed auth session to include server auth context")
	}
	if session.AuthContext.Principal != "user@example.com" || session.AuthContext.AuthMode != "human_workspace_session" {
		t.Fatalf("unexpected auth context identity: %#v", session.AuthContext)
	}
	if session.AuthContext.TokenTransport != "http_only_cookie" || session.AuthContext.CerebroResource != "cerebro-api" {
		t.Fatalf("unexpected auth context transport/resource: %#v", session.AuthContext)
	}
	if !stringSliceContains(session.AuthContext.AllowedTenants, "org_1") {
		t.Fatalf("expected allowed tenant org_1, got %#v", session.AuthContext.AllowedTenants)
	}
	for _, scope := range []string{
		"cerebro.cosmo.security.read",
		"cerebro.connector_credentials.write",
		"cerebro.runtime_response.write",
	} {
		if !stringSliceContains(session.AuthContext.CerebroScopes, scope) {
			t.Fatalf("expected scope %s, got %#v", scope, session.AuthContext.CerebroScopes)
		}
	}

	legacySession := authSessionFromMap(map[string]any{
		"token": "session-token-that-must-stay-cookie-only",
		"user": map[string]any{
			"id":          "usr_1",
			"email":       "user@example.com",
			"displayName": "User Example",
			"mfaEnabled":  true,
			"role":        "OWNER",
		},
		"organization": map[string]any{
			"id":   "org_1",
			"name": "Example Org",
			"slug": "example",
		},
	})

	if legacySession.Token != "" {
		t.Fatalf("legacy typed auth session exposed token %q", legacySession.Token)
	}
}

func TestSecurityAnalystAuthContextKeepsGRCInventoryScope(t *testing.T) {
	context := compatAuthContextForSession(
		compatSessionUser{
			Email: "analyst@example.com",
			Role:  "SECURITY_ANALYST",
		},
		compatSessionOrg{
			ID:   "org_1",
			Slug: "example",
		},
	)

	if !stringSliceContains(context.CerebroScopes, compatCerebroGRCInventoryScope) {
		t.Fatalf("expected security analyst GRC scope, got %#v", context.CerebroScopes)
	}
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestCompatPasswordHashEmitsAndVerifiesS2(t *testing.T) {
	hash := compatHashPassword("correct horse battery staple")
	if !strings.HasPrefix(hash, "s2$16384$8$1$") {
		t.Fatalf("expected s2 hash with TS-compatible params, got %q", hash)
	}
	if !compatVerifyPassword("correct horse battery staple", hash) {
		t.Fatal("expected s2 hash to verify")
	}
	if compatVerifyPassword("wrong horse battery staple", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestCompatPasswordVerifierAcceptsLegacyS1TSHash(t *testing.T) {
	password := "correct horse battery staple"
	salt := []byte("0123456789abcdef")
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Join([]string{
		"s1",
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	}, "$")
	if !compatVerifyPassword(password, hash) {
		t.Fatal("expected legacy TypeScript s1 hash to verify")
	}
}

func TestCompatEncryptStringUsesSharedEnvelope(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	nonce := []byte("123456789012")
	aad := "org_demo:GITHUB:writer:access_token"
	encrypted, err := compatEncryptStringWithNonce("demo-provider-token-GITHUB", aad, nonce)
	if err != nil {
		t.Fatal(err)
	}
	const expectedEnvelope = "eyJ2ZXJzaW9uIjoxLCJhbGdvcml0aG0iOiJhZXMtMjU2LWdjbSIsIml2IjoiTVRJek5EVTJOemc1TURFeSIsInRhZyI6Im1sUjJUS1QyMmdsMHBOOTRNa0NYX3ciLCJjaXBoZXJ0ZXh0IjoiN1Qta25Jc0lRakVsOW1XQWRNSjNfUDJQaDE5X3RVellFaDgifQ"
	if encrypted != expectedEnvelope {
		t.Fatalf("expected TS-compatible envelope\nwant %s\n got %s", expectedEnvelope, encrypted)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var envelope compatEncryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Version != 1 || envelope.Algorithm != "aes-256-gcm" {
		t.Fatalf("unexpected envelope metadata: %+v", envelope)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv, _ := base64.RawURLEncoding.DecodeString(envelope.IV)
	tag, _ := base64.RawURLEncoding.DecodeString(envelope.Tag)
	ciphertext, _ := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, []byte(aad))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "demo-provider-token-GITHUB" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
	if _, err := gcm.Open(nil, iv, sealed, []byte("wrong-aad")); err == nil {
		t.Fatal("expected wrong AAD to fail authentication")
	}
}

func TestCompatDecryptIntegrationSecretAcceptsCanonicalAndLegacyAAD(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	organizationID := "org_demo"
	integrationID := "int_demo"
	provider := "GITHUB"
	externalAccountID := "writer"
	nonce := []byte("123456789012")

	canonical, err := compatEncryptStringWithNonce(
		"canonical-token",
		compatIntegrationSecretAAD(organizationID, provider, externalAccountID, "access_token"),
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := compatDecryptIntegrationSecret(canonical, organizationID, integrationID, provider, externalAccountID, "access_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "canonical-token" {
		t.Fatalf("unexpected canonical plaintext %q", got)
	}

	legacy, err := compatEncryptStringWithNonce(
		"legacy-token",
		compatLegacyIntegrationSecretAAD(organizationID, integrationID, "access_token"),
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err = compatDecryptIntegrationSecret(legacy, organizationID, integrationID, provider, externalAccountID, "access_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "legacy-token" {
		t.Fatalf("unexpected legacy plaintext %q", got)
	}
}

func TestTypedCatalogProjectionsUseCompatDefinitions(t *testing.T) {
	connectors := connectorCatalogProto()
	if len(connectors) == 0 {
		t.Fatal("expected connector catalog entries")
	}
	var github *aperiov1.ConnectorDefinition
	for _, connector := range connectors {
		if connector.Provider == "GITHUB" {
			github = connector
			break
		}
	}
	if github == nil {
		t.Fatal("expected GitHub connector definition")
	}
	if github.Category != "Source Control" {
		t.Fatalf("expected real GitHub category, got %q", github.Category)
	}
	if len(github.ReadScopes) == 0 || len(github.Fields) == 0 || len(github.FindingChecks) == 0 {
		t.Fatal("expected real scopes, fields, and finding checks")
	}

	disabled := compatDefaultDisabledChecks("GITHUB")
	if len(disabled) == 0 {
		t.Fatal("expected at least one default-disabled GitHub check")
	}
	state := integrationCheckStateProto("integration_1", "GITHUB", disabled)
	if len(state.Checks) != len(github.FindingChecks) {
		t.Fatalf("expected %d check statuses, got %d", len(github.FindingChecks), len(state.Checks))
	}
	for _, check := range state.Checks {
		if check.Key == disabled[0] && check.Enabled {
			t.Fatalf("expected default-disabled check %q to be disabled", check.Key)
		}
	}

	siem := siemCatalogProto()
	if len(siem) == 0 || len(siem[0].Fields) == 0 || siem[0].DocsUrl == "" {
		t.Fatal("expected real SIEM catalog definitions")
	}
}

func TestCompatTOTPVerifiesGeneratedCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	counter := uint64(time.Now().Unix() / 30)
	code := compatHOTP([]byte("Hello!\xde\xad\xbe\xef"), counter)
	if !compatVerifyTOTP(secret, code) {
		t.Fatal("expected generated TOTP code to verify")
	}
	if compatVerifyTOTP(secret, "000000") && code != "000000" {
		t.Fatal("expected incorrect TOTP code to fail")
	}
}

func nowMinus(t *testing.T, duration time.Duration) time.Time {
	t.Helper()
	return time.Now().Add(-duration)
}
