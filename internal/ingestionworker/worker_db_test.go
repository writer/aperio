package ingestionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/cerebrofanout"
	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/siemdispatcher"
	"github.com/writer/aperio/internal/telemetry"
)

const (
	testIngestionWorkerEncryptionKey  = "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	testIngestionWorkerAccessToken    = "development-demo-provider-token"
	testIngestionWorkerRefreshToken   = "development-demo-refresh-token"
	testIngestionWorkerWebhookSecret  = "development-demo-webhook-secret"
	testIngestionWorkerMailboxPrivKey = "-----BEGIN EXAMPLE PRIVATE KEY-----\ndevelopment-demo-mailbox-key\n-----END EXAMPLE PRIVATE KEY-----"
)

func openDBBackedIngestionWorkerDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed ingestion worker tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func readSiemFindingDeliveryReferenceRecord(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "siem-finding-delivery.json"))
	if err != nil {
		t.Fatalf("read SIEM delivery parity fixture: %v", err)
	}
	var fixture struct {
		Payload siemdispatcher.Payload `json:"payload"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode SIEM delivery parity fixture: %v", err)
	}
	return fixture.Payload.Record
}

func testWorkerID(prefix string) string {
	return prefix + "_" + randomID()
}

func ensureIngestionWorkerTestEncryptionKey(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(os.Getenv("APERIO_ENCRYPTION_KEY")) == "" {
		t.Setenv("APERIO_ENCRYPTION_KEY", testIngestionWorkerEncryptionKey)
	}
}

func encryptIngestionWorkerSecret(t *testing.T, orgID, integrationID, provider, externalAccountID, suffix, plaintext string, legacy bool) string {
	t.Helper()
	ensureIngestionWorkerTestEncryptionKey(t)
	aad := runtimeutil.IntegrationSecretAAD(orgID, provider, externalAccountID, suffix)
	if legacy {
		aad = runtimeutil.LegacyIntegrationSecretAAD(orgID, integrationID, suffix)
	}
	encrypted, err := runtimeutil.EncryptString(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt %s credential fixture: %v", suffix, err)
	}
	return encrypted
}

func encryptIngestionWorkerMailboxKey(t *testing.T, orgID, integrationID, externalAccountID, plaintext string, legacy bool) string {
	t.Helper()
	ensureIngestionWorkerTestEncryptionKey(t)
	aad := runtimeutil.IntegrationSecretAAD(orgID, "GOOGLE_WORKSPACE", externalAccountID, "gmail_scan_private_key")
	if legacy {
		aad = runtimeutil.LegacyIntegrationSecretAAD(orgID, integrationID, "google_mailbox_private_key")
	}
	encrypted, err := runtimeutil.EncryptString(plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt Google mailbox credential fixture: %v", err)
	}
	return encrypted
}

func tamperIngestionWorkerEnvelopeTag(t *testing.T, encrypted string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("decode credential envelope: %v", err)
	}
	var envelope runtimeutil.EncryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode credential envelope JSON: %v", err)
	}
	envelope.Tag = base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode tampered credential envelope: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func seedIngestionWorkerOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	orgID := testWorkerID("org")
	slug := "go-worker-" + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, "Go Worker Test", slug); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID
}

func seedIngestionWorkerIntegration(t *testing.T, db *sql.DB, orgID, provider, status string) string {
	t.Helper()
	integrationID := testWorkerID("int")
	externalAccountID := integrationID
	encryptedAccessToken := encryptIngestionWorkerSecret(t, orgID, integrationID, provider, externalAccountID, "access_token", testIngestionWorkerAccessToken, false)
	encryptedRefreshToken := encryptIngestionWorkerSecret(t, orgID, integrationID, provider, externalAccountID, "refresh_token", testIngestionWorkerRefreshToken, false)
	encryptedWebhookSecret := encryptIngestionWorkerSecret(t, orgID, integrationID, provider, externalAccountID, "webhook_secret", testIngestionWorkerWebhookSecret, false)
	var googleMailboxClientEmail any
	var encryptedGoogleMailboxPrivateKey any
	if provider == "GOOGLE_WORKSPACE" {
		googleMailboxClientEmail = "mailbox-scanner@example.com"
		encryptedGoogleMailboxPrivateKey = encryptIngestionWorkerMailboxKey(t, orgID, integrationID, externalAccountID, testIngestionWorkerMailboxPrivKey, false)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, encrypted_refresh_token, encrypted_webhook_secret,
			google_mailbox_scan_client_email, encrypted_google_mailbox_scan_private_key,
			status, mode, created_at, updated_at
		)
		VALUES (
			$1, $2, $3::"SaaSProvider", $4, $5, ARRAY[]::text[], ARRAY[]::text[],
			$6, $7, $8, $9, $10,
			$11::"IntegrationStatus", 'READ_ONLY'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID, provider, provider+" Worker Test", externalAccountID, encryptedAccessToken, encryptedRefreshToken, encryptedWebhookSecret, googleMailboxClientEmail, encryptedGoogleMailboxPrivateKey, status); err != nil {
		t.Fatalf("seed %s integration: %v", provider, err)
	}
	return integrationID
}

func seedIngestionWorkerJob(t *testing.T, db *sql.DB, input struct {
	orgID         string
	integrationID string
	provider      string
	eventType     string
	status        string
	attempts      int
	maxAttempts   int
	leaseOwner    *string
	payload       json.RawMessage
}) string {
	t.Helper()
	jobID := testWorkerID("job")
	if input.payload == nil {
		input.payload = json.RawMessage(`{}`)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor, occurred_at,
			payload, status, attempts, max_attempts, next_attempt_at, lease_owner, lease_expires_at,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4::"SaaSProvider", $5, 'test', 'worker@example.com', $6,
			$7, $8::"IngestionJobStatus", $9, $10, NOW() - INTERVAL '1 minute', $11::text,
			CASE WHEN $11::text IS NULL THEN NULL ELSE NOW() - INTERVAL '1 minute' END,
			NOW(), NOW()
		)
	`, jobID, input.orgID, input.integrationID, input.provider, input.eventType, time.Now().UTC().Add(-time.Minute), input.payload, input.status, input.attempts, input.maxAttempts, input.leaseOwner); err != nil {
		t.Fatalf("seed ingestion job: %v", err)
	}
	return jobID
}

func ingestionJobState(t *testing.T, db *sql.DB, jobID string) (status string, attempts int, leaseOwner sql.NullString, processedAt sql.NullTime, lastError sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, attempts, lease_owner, processed_at, last_error
		FROM ingestion_jobs
		WHERE id = $1
	`, jobID).Scan(&status, &attempts, &leaseOwner, &processedAt, &lastError); err != nil {
		t.Fatalf("query ingestion job %s: %v", jobID, err)
	}
	return status, attempts, leaseOwner, processedAt, lastError
}

func ingestionJobNextAttemptAt(t *testing.T, db *sql.DB, jobID string) time.Time {
	t.Helper()
	var nextAttemptAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT next_attempt_at
		FROM ingestion_jobs
		WHERE id = $1
	`, jobID).Scan(&nextAttemptAt); err != nil {
		t.Fatalf("query ingestion job next attempt %s: %v", jobID, err)
	}
	return nextAttemptAt
}

func ingestionSideEffectCounts(t *testing.T, db *sql.DB, orgID string) (events int, findings int, deliveries int) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1`, orgID).Scan(&events); err != nil {
		t.Fatalf("count ingested events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1`, orgID).Scan(&findings); err != nil {
		t.Fatalf("count security findings: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1`, orgID).Scan(&deliveries); err != nil {
		t.Fatalf("count SIEM deliveries: %v", err)
	}
	return events, findings, deliveries
}

func assertNoIngestionSideEffects(t *testing.T, db *sql.DB, orgID string) {
	t.Helper()
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != 0 || findings != 0 || deliveries != 0 {
		t.Fatalf("expected no ingestion side effects, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func seedOktaFixtureJob(t *testing.T, db *sql.DB, orgID, integrationID string, fixturePayload oktaFixturePayload) string {
	t.Helper()
	payloadJSON, err := json.Marshal(fixturePayload.Payload)
	if err != nil {
		t.Fatalf("marshal Okta fixture payload: %v", err)
	}
	return seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "OKTA", eventType: fixturePayload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})
}

func oktaJobPayloadForDB(t *testing.T, fixturePayload oktaFixturePayload, orgID, integrationID string) JobPayload {
	t.Helper()
	payload := fixturePayload.jobPayload(t)
	payload.OrganizationID = orgID
	payload.IntegrationID = integrationID
	return payload
}

func seedGoogleFixtureJob(t *testing.T, db *sql.DB, orgID, integrationID string, fixturePayload googleFixturePayload) string {
	t.Helper()
	payloadJSON, err := json.Marshal(fixturePayload.Payload)
	if err != nil {
		t.Fatalf("marshal Google Workspace fixture payload: %v", err)
	}
	jobID := testWorkerID("job")
	var actor sql.NullString
	if strings.TrimSpace(fixturePayload.Actor) != "" {
		actor = sql.NullString{String: fixturePayload.Actor, Valid: true}
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor, occurred_at,
			payload, status, attempts, max_attempts, next_attempt_at, lease_owner, lease_expires_at,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, 'GOOGLE_WORKSPACE'::"SaaSProvider", $4, $5, $6, $7,
			$8, 'QUEUED'::"IngestionJobStatus", 0, 3, NOW() - INTERVAL '1 minute', NULL,
			NULL, NOW(), NOW()
		)
	`, jobID, orgID, integrationID, fixturePayload.EventType, fixturePayload.Source, actor, time.Now().UTC().Add(-time.Minute), payloadJSON); err != nil {
		t.Fatalf("seed Google Workspace fixture job: %v", err)
	}
	return jobID
}

func googleJobPayloadForDB(t *testing.T, fixturePayload googleFixturePayload, orgID, integrationID string) JobPayload {
	t.Helper()
	payload := fixturePayload.jobPayload(t)
	payload.OrganizationID = orgID
	payload.IntegrationID = integrationID
	return payload
}

func captureIngestionTelemetry(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var sink bytes.Buffer
	restore := telemetry.SetOutput(&sink)
	return &sink, restore
}

func decodeWideEvents(t *testing.T, sink *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	events := []map[string]any{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode telemetry line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func requireTelemetryOutcome(t *testing.T, events []map[string]any, outcome string) map[string]any {
	t.Helper()
	for _, event := range events {
		if event["event_name"] == "ingestion.job.process" && event["outcome"] == outcome {
			return event
		}
	}
	t.Fatalf("missing ingestion telemetry outcome %q in %#v", outcome, events)
	return nil
}

type recordingLifecyclePublisher struct {
	t         *testing.T
	db        *sql.DB
	seen      []FindingLifecycleEvent
	jobEvents []IngestionJobLifecycleEvent
}

type recordingCerebroFindingFanout struct {
	t    *testing.T
	db   *sql.DB
	seen []cerebrofanout.FindingPayload
	err  error
}

func (f *recordingCerebroFindingFanout) FanoutFinding(ctx context.Context, payload cerebrofanout.FindingPayload) (cerebrofanout.Result, error) {
	f.t.Helper()
	findingID, _ := payload.Record["findingId"].(string)
	var status string
	if err := f.db.QueryRowContext(ctx, `
		SELECT status::text
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, findingID, payload.OrganizationID).Scan(&status); err != nil {
		f.t.Fatalf("Cerebro fanout ran before committed finding was visible: %v", err)
	}
	if status == "" {
		f.t.Fatal("Cerebro fanout saw empty committed finding status")
	}
	f.seen = append(f.seen, payload)
	if f.err != nil {
		return cerebrofanout.Result{}, f.err
	}
	return cerebrofanout.Result{
		FindingID:     findingID,
		DedupeKey:     fmt.Sprint(payload.Record["dedupeKey"]),
		SourceEventID: fmt.Sprint(payload.Record["sourceEventId"]),
		ClaimCount:    1,
		ClaimsWritten: 1,
	}, nil
}

func (p *recordingLifecyclePublisher) PublishIngestionJobLifecycle(ctx context.Context, event IngestionJobLifecycleEvent) error {
	p.t.Helper()
	var status string
	var processedAt sql.NullTime
	if err := p.db.QueryRowContext(ctx, `
		SELECT status::text, processed_at
		FROM ingestion_jobs
		WHERE id = $1 AND organization_id = $2
	`, event.JobID, event.OrganizationID).Scan(&status, &processedAt); err != nil {
		p.t.Fatalf("ingestion job lifecycle event published before committed job was visible: %v", err)
	}
	switch event.Status {
	case "running":
		if status != "RUNNING" {
			p.t.Fatalf("running lifecycle event saw job status %s", status)
		}
	case "succeeded":
		if status != "SUCCEEDED" || !processedAt.Valid {
			p.t.Fatalf("succeeded lifecycle event saw job status=%s processedAt=%v", status, processedAt)
		}
	case "failed":
		if status != "FAILED" {
			p.t.Fatalf("failed lifecycle event saw job status %s", status)
		}
	case "dead_letter":
		if status != "DEAD_LETTER" {
			p.t.Fatalf("dead-letter lifecycle event saw job status %s", status)
		}
	}
	p.jobEvents = append(p.jobEvents, event)
	return nil
}

func (p *recordingLifecyclePublisher) PublishFindingLifecycle(ctx context.Context, event FindingLifecycleEvent) error {
	p.t.Helper()
	var status string
	if err := p.db.QueryRowContext(ctx, `
		SELECT status::text
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, event.FindingID, event.OrganizationID).Scan(&status); err != nil {
		p.t.Fatalf("lifecycle event published before committed finding was visible: %v", err)
	}
	if status != event.NextStatus {
		p.t.Fatalf("lifecycle event saw committed status %s, want %s", status, event.NextStatus)
	}
	p.seen = append(p.seen, event)
	return nil
}

func TestDrainDeadLettersUnsupportedIngestionJobsWithoutSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrations := map[string]string{
		"GITHUB":           seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED"),
		"SLACK":            seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED"),
		"OKTA":             seedIngestionWorkerIntegration(t, db, orgID, "OKTA", "CONNECTED"),
		"GOOGLE_WORKSPACE": seedIngestionWorkerIntegration(t, db, orgID, "GOOGLE_WORKSPACE", "CONNECTED"),
		"MICROSOFT_365":    seedIngestionWorkerIntegration(t, db, orgID, "MICROSOFT_365", "CONNECTED"),
	}

	type unsupportedCase struct {
		name        string
		provider    string
		eventType   string
		status      string
		attempts    int
		maxAttempts int
		payload     json.RawMessage
	}
	cases := []unsupportedCase{
		{name: "slack unsupported event", provider: "SLACK", eventType: "UNSUPPORTED_SLACK_AUDIT_EVENT", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)},
		{name: "slack failed unsupported event", provider: "SLACK", eventType: "UNSUPPORTED_SLACK_FAILED_EVENT", status: "FAILED", attempts: 1, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)},
		{name: "okta unsupported event", provider: "OKTA", eventType: "USER_LIFECYCLE_DEACTIVATE", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"actor":{"displayName":"admin@example.com"},"target":[{"type":"User","displayName":"user@example.com"}]}`)},
		{name: "google unsupported event", provider: "GOOGLE_WORKSPACE", eventType: "USER_LOGIN", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"parameters":{"forward_to":"external@example.com"}}`)},
		{name: "unknown github event", provider: "GITHUB", eventType: "UNKNOWN_EVENT", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"repository":{"full_name":"writer/private","visibility":"private"}}`)},
		{name: "unsupported provider", provider: "MICROSOFT_365", eventType: "USER_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"userPrincipalName":"user@example.com"}`)},
	}

	jobIDs := map[string]string{}
	for _, input := range cases {
		if isSupportedIngestionWork(input.provider, input.eventType) {
			t.Fatalf("%s fixture uses supported ingestion work %s/%s", input.name, input.provider, input.eventType)
		}
		jobIDs[input.name] = seedIngestionWorkerJob(t, db, struct {
			orgID         string
			integrationID string
			provider      string
			eventType     string
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
			payload       json.RawMessage
		}{orgID: orgID, integrationID: integrations[input.provider], provider: input.provider, eventType: input.eventType, status: input.status, attempts: input.attempts, maxAttempts: input.maxAttempts, payload: input.payload})
	}

	publisher := &recordingLifecyclePublisher{t: t, db: db}
	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker", eventPublisher: publisher}).Drain(context.Background(), 10)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != len(cases) || result.Succeeded != 0 || result.Failed != len(cases) {
		t.Fatalf("expected unsupported jobs to be dead-lettered without fallback, got %#v", result)
	}

	for _, input := range cases {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobIDs[input.name])
		if status != "DEAD_LETTER" || attempts != input.attempts+1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
			t.Fatalf("%s state = status=%s attempts=%d lease=%v processed=%v error=%v", input.name, status, attempts, leaseOwner, processedAt, lastError)
		}
		if !strings.Contains(lastError.String, "unsupported ingestion work") || !strings.Contains(lastError.String, "final Go ingestion matrix") {
			t.Fatalf("%s last_error = %q, want explicit final unsupported-work policy", input.name, lastError.String)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != 0 || findings != 0 || deliveries != 0 {
		t.Fatalf("unsupported work should not create event/finding/SIEM side effects, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
	wideEvents := decodeWideEvents(t, sink)
	deadLetters := 0
	for _, event := range wideEvents {
		if event["outcome"] == "dead_letter" {
			deadLetters++
			if event["error_kind"] != "unsupported" {
				t.Fatalf("unsupported telemetry missing error_kind=unsupported: %#v", event)
			}
		}
	}
	if deadLetters != len(cases) {
		t.Fatalf("expected unsupported dead-letter telemetry for every job, got %d events in %#v", deadLetters, wideEvents)
	}
	jobDeadLetters := 0
	for _, event := range publisher.jobEvents {
		if event.Status == "dead_letter" {
			jobDeadLetters++
			if event.SourceEventID != "" {
				t.Fatalf("unsupported job lifecycle should not claim a source event id: %#v", event)
			}
		}
	}
	if jobDeadLetters != len(cases) {
		t.Fatalf("expected dead-letter lifecycle events for unsupported jobs, got %#v", publisher.jobEvents)
	}
}

func TestDrainClaimsSharedFixtureEventAliases(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	githubIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	slackIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
	githubFixture := readGitHubParityFixture(t)
	slackFixture := readSlackParityFixture(t)

	githubPayloadJSON, _ := json.Marshal(githubFixture.Positive.Payload.Payload)
	slackPayloadJSON, _ := json.Marshal(slackFixture.Positive.Payload.Payload)
	slackAliasPayloadJSON, _ := json.Marshal(slackFixture.Alias.Payload.Payload)

	githubJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: githubIntegrationID, provider: "GITHUB", eventType: githubFixture.Positive.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: githubPayloadJSON})
	slackJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: slackIntegrationID, provider: "SLACK", eventType: slackFixture.Positive.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: slackPayloadJSON})
	slackAliasJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: slackIntegrationID, provider: "SLACK", eventType: slackFixture.Alias.Payload.EventType, status: "QUEUED", attempts: 0, maxAttempts: 3, payload: slackAliasPayloadJSON})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 10)
	restore()
	if err != nil {
		t.Fatalf("drain aliases: %v", err)
	}
	if result.Processed != 3 || result.Succeeded != 3 || result.Failed != 0 {
		t.Fatalf("unexpected alias drain result: %#v", result)
	}
	for _, jobID := range []string{githubJobID, slackJobID, slackAliasJobID} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("alias job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	var eventCount int
	var maxSeverity string
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*), MAX(severity::text)
		FROM ingested_events
		WHERE organization_id = $1
		  AND event_type IN ($2, $3, $4)
		  AND processing_status = 'PROCESSED'::"EventProcessingStatus"
	`, orgID, githubFixture.Positive.Payload.EventType, slackFixture.Positive.Payload.EventType, slackFixture.Alias.Payload.EventType).Scan(&eventCount, &maxSeverity); err != nil {
		t.Fatalf("query alias events: %v", err)
	}
	if eventCount != 3 || maxSeverity != "CRITICAL" {
		t.Fatalf("alias events = count=%d maxSeverity=%s", eventCount, maxSeverity)
	}

	githubPayload := githubFixture.Positive.Payload.jobPayload(t)
	githubPayload.OrganizationID = orgID
	githubPayload.IntegrationID = githubIntegrationID
	githubFinding := Evaluate(githubPayload, nil)[0]
	var githubFindingCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM security_findings
		WHERE organization_id = $1 AND integration_id = $2 AND dedupe_key = $3
	`, orgID, githubIntegrationID, DedupeKey(githubPayload, githubFinding)).Scan(&githubFindingCount); err != nil {
		t.Fatalf("count GitHub alias finding: %v", err)
	}
	if githubFindingCount != 1 {
		t.Fatalf("expected one GitHub alias finding, got %d", githubFindingCount)
	}

	events := decodeWideEvents(t, sink)
	successes := 0
	for _, event := range events {
		if event["outcome"] == "succeeded" {
			successes++
			if event["organization_id"] != orgID || event["provider"] == "" || event["event_type"] == "" || event["attempt"] != float64(1) || event["max_attempts"] != float64(3) {
				t.Fatalf("success telemetry missing required fields: %#v", event)
			}
		}
	}
	if successes != 3 || strings.Contains(sink.String(), "test-token") {
		t.Fatalf("unexpected alias telemetry successes=%d body=%s", successes, sink.String())
	}
}

func TestDrainPersistsSupportedSlackMFAJob(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")

	payloadMap := map[string]any{
		"user": map[string]any{
			"id":    "U123",
			"email": "user@example.com",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobPayload := JobPayload{
		OrganizationID: orgID,
		IntegrationID:  integrationID,
		Provider:       "SLACK",
		EventType:      "TWO_FACTOR_AUTH_DISABLED",
		Source:         "slack-audit-log",
		Actor:          "admin@example.com",
		OccurredAt:     time.Now().UTC().Add(-time.Minute),
		Payload:        payloadMap,
	}
	finding := Evaluate(jobPayload, nil)[0]
	dedupe := DedupeKey(jobPayload, finding)

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "TWO_FACTOR_AUTH_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, jobID)
		t.Fatalf("unexpected drain result: %#v lastError=%v", result, jobError)
	}

	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("supported Slack job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	successTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "succeeded")
	if successTelemetry["provider"] != "SLACK" || successTelemetry["event_type"] != "TWO_FACTOR_AUTH_DISABLED" || successTelemetry["attempt"] != float64(1) || successTelemetry["max_attempts"] != float64(3) {
		t.Fatalf("Slack success telemetry missing required fields: %#v", successTelemetry)
	}

	var eventID string
	var eventProvider, eventType string
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, provider::text, event_type
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, jobID, orgID).Scan(&eventID, &eventProvider, &eventType); err != nil {
		t.Fatalf("query Slack ingested event: %v", err)
	}
	if eventProvider != "SLACK" || eventType != "TWO_FACTOR_AUTH_DISABLED" {
		t.Fatalf("Slack event persisted as provider=%s event=%s", eventProvider, eventType)
	}

	var persistedFindingID, title, severity string
	var riskScore int
	var evidence map[string]any
	var rawEvidence json.RawMessage
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, title, severity::text, risk_score, evidence
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, dedupe).Scan(&persistedFindingID, &title, &severity, &riskScore, &rawEvidence); err != nil {
		t.Fatalf("query Slack security finding: %v", err)
	}
	if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
		t.Fatalf("decode Slack finding evidence: %v", err)
	}
	if persistedFindingID == "" || title != finding.Title || severity != finding.Severity || riskScore != finding.RiskScore {
		t.Fatalf("Slack finding fields = id=%s title=%s severity=%s risk=%d", persistedFindingID, title, severity, riskScore)
	}
	if evidence["ruleId"] != "slack.mfa_disabled" || evidence["user"] != "user@example.com" || evidence["sourceEventId"] != eventID {
		t.Fatalf("Slack finding evidence = %#v", evidence)
	}
}

func TestDrainProcessesSupportedSlackDisabledCheckWithoutFinding(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET disabled_checks = ARRAY['slack.mfa_disabled']::text[]
		WHERE id = $1
	`, integrationID); err != nil {
		t.Fatalf("disable Slack check: %v", err)
	}

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected disabled-check drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("disabled-check job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	disabledTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "succeeded")
	if disabledTelemetry["provider"] != "SLACK" || disabledTelemetry["event_type"] != "MFA_DISABLED" || disabledTelemetry["attempt"] != float64(1) {
		t.Fatalf("disabled-check telemetry missing required fields: %#v", disabledTelemetry)
	}

	var eventCount, findingCount int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1 AND ingestion_job_id = $2`, orgID, jobID).Scan(&eventCount); err != nil {
		t.Fatalf("count disabled-check events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1`, orgID).Scan(&findingCount); err != nil {
		t.Fatalf("count disabled-check findings: %v", err)
	}
	if eventCount != 1 || findingCount != 0 {
		t.Fatalf("disabled check should persist event only, got events=%d findings=%d", eventCount, findingCount)
	}
}

func TestDrainPersistsSupportedOktaRuleSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "OKTA", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'okta-rule-side-effects.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	type expectedOktaFinding struct {
		jobID   string
		payload JobPayload
		finding Finding
		dedupe  string
	}
	expected := map[string]expectedOktaFinding{}
	for _, fixture := range readOktaParityFixtures(t) {
		jobID := seedOktaFixtureJob(t, db, orgID, integrationID, fixture.Positive.Payload)
		payload := oktaJobPayloadForDB(t, fixture.Positive.Payload, orgID, integrationID)
		findings := Evaluate(payload, nil)
		if len(findings) != 1 {
			t.Fatalf("expected fixture %s to produce one finding, got %#v", fixture.Positive.ExpectedFinding.RuleID, findings)
		}
		finding := findings[0]
		expected[finding.RuleID] = expectedOktaFinding{
			jobID:   jobID,
			payload: payload,
			finding: finding,
			dedupe:  DedupeKey(payload, finding),
		}
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(expected))
	if err != nil {
		t.Fatalf("drain Okta rule jobs: %v", err)
	}
	if result.Processed != len(expected) || result.Succeeded != len(expected) || result.Failed != 0 {
		t.Fatalf("unexpected Okta rule drain result: %#v", result)
	}

	for ruleID, want := range expected {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, want.jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("%s job state = status=%s attempts=%d lease=%v processed=%v error=%v", ruleID, status, attempts, leaseOwner, processedAt, lastError)
		}

		var persistedFindingID, title, severity string
		var riskScore int
		var rawEvidence json.RawMessage
		if err := db.QueryRowContext(context.Background(), `
			SELECT id, title, severity::text, risk_score, evidence
			FROM security_findings
			WHERE organization_id = $1 AND dedupe_key = $2
		`, orgID, want.dedupe).Scan(&persistedFindingID, &title, &severity, &riskScore, &rawEvidence); err != nil {
			t.Fatalf("query %s security finding: %v", ruleID, err)
		}
		var evidence map[string]any
		if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
			t.Fatalf("decode %s security finding evidence: %v", ruleID, err)
		}
		if persistedFindingID == "" || title != want.finding.Title || severity != want.finding.Severity || riskScore != want.finding.RiskScore {
			t.Fatalf("%s finding fields = id=%s title=%s severity=%s risk=%d", ruleID, persistedFindingID, title, severity, riskScore)
		}
		if evidence["ruleId"] != ruleID || evidence["target"] != want.finding.Target || evidence["sourceEventId"] == "" {
			t.Fatalf("%s finding evidence missing required fields: %#v", ruleID, evidence)
		}
		for key, value := range want.finding.Evidence {
			assertJSONEqual(t, evidence[key], value)
		}
	}

	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != len(expected) || findings != len(expected) || deliveries != len(expected) {
		t.Fatalf("expected Okta event/finding/delivery side effects for every rule, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestDrainProcessesOktaDisabledChecksWithoutFindings(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "OKTA", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'okta-disabled-checks.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	fixtures := readOktaParityFixtures(t)
	disabledChecks := make([]string, 0, len(fixtures))
	jobIDs := []string{}
	for _, fixture := range fixtures {
		disabledChecks = append(disabledChecks, fixture.DisabledCheck)
	}
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET disabled_checks = $1::text[]
		WHERE id = $2
	`, postgresTextArray(disabledChecks), integrationID); err != nil {
		t.Fatalf("disable Okta checks: %v", err)
	}
	for _, fixture := range fixtures {
		jobIDs = append(jobIDs, seedOktaFixtureJob(t, db, orgID, integrationID, fixture.Positive.Payload))
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(jobIDs))
	if err != nil {
		t.Fatalf("drain Okta disabled checks: %v", err)
	}
	if result.Processed != len(jobIDs) || result.Succeeded != len(jobIDs) || result.Failed != 0 {
		t.Fatalf("unexpected Okta disabled-check drain result: %#v", result)
	}
	for _, jobID := range jobIDs {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("disabled-check job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != len(jobIDs) || findings != 0 || deliveries != 0 {
		t.Fatalf("disabled Okta checks should persist events only, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestDrainProcessesOktaNegativeFixturesWithoutFindings(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "OKTA", "CONNECTED")

	jobIDs := []string{}
	for _, fixture := range readOktaParityFixtures(t) {
		jobIDs = append(jobIDs, seedOktaFixtureJob(t, db, orgID, integrationID, fixture.Negative.Payload))
		for _, negative := range fixture.AdditionalNegatives {
			jobIDs = append(jobIDs, seedOktaFixtureJob(t, db, orgID, integrationID, negative.Payload))
		}
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(jobIDs))
	if err != nil {
		t.Fatalf("drain Okta negative fixtures: %v", err)
	}
	if result.Processed != len(jobIDs) || result.Succeeded != len(jobIDs) || result.Failed != 0 {
		t.Fatalf("unexpected Okta negative drain result: %#v", result)
	}
	for _, jobID := range jobIDs {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("negative fixture job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != len(jobIDs) || findings != 0 || deliveries != 0 {
		t.Fatalf("negative Okta fixtures should persist events only, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestDrainPersistsSupportedGoogleAdminOAuthRuleSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GOOGLE_WORKSPACE", "CONNECTED")
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET google_mailbox_scan_client_email = NULL,
			encrypted_google_mailbox_scan_private_key = NULL
		WHERE id = $1 AND organization_id = $2
	`, integrationID, orgID); err != nil {
		t.Fatalf("seed OAuth-only Google Workspace integration: %v", err)
	}
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'google-admin-oauth-side-effects.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	type expectedGoogleFinding struct {
		name    string
		jobID   string
		payload JobPayload
		finding Finding
		dedupe  string
	}
	expected := []expectedGoogleFinding{}
	for _, fixture := range readGoogleParityFixtures(t) {
		cases := []struct {
			name    string
			payload googleFixturePayload
		}{
			{name: fixture.Positive.ExpectedFinding.RuleID, payload: fixture.Positive.Payload},
		}
		for _, variant := range fixture.Variants {
			cases = append(cases, struct {
				name    string
				payload googleFixturePayload
			}{name: fixture.RuleID + "/" + variant.Name, payload: variant.Payload})
		}
		for _, item := range cases {
			jobID := seedGoogleFixtureJob(t, db, orgID, integrationID, item.payload)
			payload := googleJobPayloadForDB(t, item.payload, orgID, integrationID)
			findings := Evaluate(payload, nil)
			if len(findings) != 1 {
				t.Fatalf("expected fixture %s to produce one finding, got %#v", item.name, findings)
			}
			finding := findings[0]
			expected = append(expected, expectedGoogleFinding{
				name:    item.name,
				jobID:   jobID,
				payload: payload,
				finding: finding,
				dedupe:  DedupeKey(payload, finding),
			})
		}
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(expected))
	if err != nil {
		t.Fatalf("drain Google Workspace rule jobs: %v", err)
	}
	if result.Processed != len(expected) || result.Succeeded != len(expected) || result.Failed != 0 {
		t.Fatalf("unexpected Google Workspace rule drain result: %#v", result)
	}

	seenEmptyScopeEvidence := false
	for _, want := range expected {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, want.jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("%s job state = status=%s attempts=%d lease=%v processed=%v error=%v", want.name, status, attempts, leaseOwner, processedAt, lastError)
		}

		var persistedFindingID, title, severity string
		var riskScore int
		var rawEvidence json.RawMessage
		if err := db.QueryRowContext(context.Background(), `
			SELECT id, title, severity::text, risk_score, evidence
			FROM security_findings
			WHERE organization_id = $1 AND dedupe_key = $2
		`, orgID, want.dedupe).Scan(&persistedFindingID, &title, &severity, &riskScore, &rawEvidence); err != nil {
			t.Fatalf("query %s security finding: %v", want.name, err)
		}
		var evidence map[string]any
		if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
			t.Fatalf("decode %s security finding evidence: %v", want.name, err)
		}
		if persistedFindingID == "" || title != want.finding.Title || severity != want.finding.Severity || riskScore != want.finding.RiskScore {
			t.Fatalf("%s finding fields = id=%s title=%s severity=%s risk=%d", want.name, persistedFindingID, title, severity, riskScore)
		}
		if evidence["ruleId"] != want.finding.RuleID || evidence["target"] != want.finding.Target || evidence["sourceEventId"] == "" {
			t.Fatalf("%s finding evidence missing required fields: %#v", want.name, evidence)
		}
		for key, value := range want.finding.Evidence {
			assertJSONEqual(t, evidence[key], value)
		}
		if want.finding.RuleID == "google_workspace.risky_oauth_grant" && want.finding.Target == "Unknown Scope App" {
			if evidence["scopeCount"] != float64(0) || evidence["matchedScopes"] != nil {
				t.Fatalf("empty-scope risky OAuth evidence = %#v", evidence)
			}
			seenEmptyScopeEvidence = true
		}
	}
	if !seenEmptyScopeEvidence {
		t.Fatal("expected DB evidence coverage for empty-scope risky OAuth default-positive behavior")
	}

	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != len(expected) || findings != len(expected) || deliveries != len(expected) {
		t.Fatalf("expected Google Workspace event/finding/delivery side effects for every case, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestDrainProcessesGoogleAdminOAuthDisabledChecksWithoutFindings(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GOOGLE_WORKSPACE", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'google-disabled-checks.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	fixtures := readGoogleParityFixtures(t)
	disabledChecks := make([]string, 0, len(fixtures))
	jobIDs := []string{}
	for _, fixture := range fixtures {
		disabledChecks = append(disabledChecks, fixture.DisabledCheck)
	}
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET disabled_checks = $1::text[]
		WHERE id = $2
	`, postgresTextArray(disabledChecks), integrationID); err != nil {
		t.Fatalf("disable Google Workspace checks: %v", err)
	}
	for _, fixture := range fixtures {
		jobIDs = append(jobIDs, seedGoogleFixtureJob(t, db, orgID, integrationID, fixture.Positive.Payload))
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(jobIDs))
	if err != nil {
		t.Fatalf("drain Google Workspace disabled checks: %v", err)
	}
	if result.Processed != len(jobIDs) || result.Succeeded != len(jobIDs) || result.Failed != 0 {
		t.Fatalf("unexpected Google Workspace disabled-check drain result: %#v", result)
	}
	for _, jobID := range jobIDs {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("disabled-check job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != len(jobIDs) || findings != 0 || deliveries != 0 {
		t.Fatalf("disabled Google Workspace checks should persist events only, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestDrainDeadLettersUnsupportedGoogleNegativeFixturesWithoutSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GOOGLE_WORKSPACE", "CONNECTED")

	jobIDs := []string{}
	for _, fixture := range readGoogleParityFixtures(t) {
		jobIDs = append(jobIDs, seedGoogleFixtureJob(t, db, orgID, integrationID, fixture.Negative.Payload))
		for _, negative := range fixture.AdditionalNegatives {
			jobIDs = append(jobIDs, seedGoogleFixtureJob(t, db, orgID, integrationID, negative.Payload))
		}
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), len(jobIDs))
	if err != nil {
		t.Fatalf("drain Google Workspace negative fixtures: %v", err)
	}
	if result.Processed != len(jobIDs) || result.Succeeded != 0 || result.Failed != len(jobIDs) {
		t.Fatalf("unexpected Google Workspace negative drain result: %#v", result)
	}
	for _, jobID := range jobIDs {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "DEAD_LETTER" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
			t.Fatalf("negative fixture job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
		if !strings.Contains(lastError.String, "unsupported ingestion work") {
			t.Fatalf("negative fixture job %s last_error = %q", jobID, lastError.String)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != 0 || findings != 0 || deliveries != 0 {
		t.Fatalf("unsupported Google Workspace negative fixtures should have no side effects, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestSupportedIngestionCredentialGateAllowsCanonicalAndLegacyCredentials(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	canonicalIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
	legacyIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	legacyAccessToken := encryptIngestionWorkerSecret(t, orgID, legacyIntegrationID, "GITHUB", legacyIntegrationID, "access_token", testIngestionWorkerAccessToken, true)
	legacyRefreshToken := encryptIngestionWorkerSecret(t, orgID, legacyIntegrationID, "GITHUB", legacyIntegrationID, "refresh_token", testIngestionWorkerRefreshToken, true)
	legacyWebhookSecret := encryptIngestionWorkerSecret(t, orgID, legacyIntegrationID, "GITHUB", legacyIntegrationID, "webhook_secret", testIngestionWorkerWebhookSecret, true)
	if _, err := db.ExecContext(context.Background(), `
		UPDATE integration_connections
		SET encrypted_access_token = $1, encrypted_refresh_token = $2, encrypted_webhook_secret = $3
		WHERE id = $4
	`, legacyAccessToken, legacyRefreshToken, legacyWebhookSecret, legacyIntegrationID); err != nil {
		t.Fatalf("seed legacy credential envelopes: %v", err)
	}

	slackJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: canonicalIntegrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})
	githubJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: legacyIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"repository":{"full_name":"writer/aperio","visibility":"public"}}`)})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 2)
	if err != nil {
		t.Fatalf("drain canonical and legacy credential jobs: %v", err)
	}
	if result.Processed != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("unexpected credential success drain result: %#v", result)
	}
	for _, jobID := range []string{slackJobID, githubJobID} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("credential success job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}
	events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
	if events != 2 || findings != 2 || deliveries != 0 {
		t.Fatalf("expected canonical and legacy credentials to allow event/finding side effects only, got events=%d findings=%d deliveries=%d", events, findings, deliveries)
	}
}

func TestSupportedIngestionCredentialFailuresFailClosedAndRedact(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(t *testing.T, db *sql.DB, orgID, integrationID string) string
		clearKey      bool
		wantErrorText string
	}{
		{
			name: "missing encryption key",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				return testIngestionWorkerAccessToken
			},
			clearKey:      true,
			wantErrorText: "integration credential is unavailable",
		},
		{
			name: "missing credential value",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET encrypted_access_token = '' WHERE id = $1`, integrationID); err != nil {
					t.Fatalf("blank encrypted credential: %v", err)
				}
				return testIngestionWorkerAccessToken
			},
			wantErrorText: "integration credential is missing",
		},
		{
			name: "malformed credential envelope",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				const malformed = "not-an-encrypted-envelope"
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET encrypted_access_token = $1 WHERE id = $2`, malformed, integrationID); err != nil {
					t.Fatalf("malform encrypted credential: %v", err)
				}
				return malformed
			},
			wantErrorText: "integration credential is unavailable",
		},
		{
			name: "tampered credential tag",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				tampered := tamperIngestionWorkerEnvelopeTag(t, encryptIngestionWorkerSecret(t, orgID, integrationID, "SLACK", integrationID, "access_token", testIngestionWorkerAccessToken, false))
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET encrypted_access_token = $1 WHERE id = $2`, tampered, integrationID); err != nil {
					t.Fatalf("tamper encrypted credential: %v", err)
				}
				return tampered
			},
			wantErrorText: "integration credential is unavailable",
		},
		{
			name: "wrong aad credential",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET external_account_id = $1 WHERE id = $2`, integrationID+"-rotated", integrationID); err != nil {
					t.Fatalf("rotate external account id: %v", err)
				}
				return testIngestionWorkerAccessToken
			},
			wantErrorText: "integration credential is unavailable",
		},
		{
			name: "short decrypted credential",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				const shortToken = "short"
				encrypted := encryptIngestionWorkerSecret(t, orgID, integrationID, "SLACK", integrationID, "access_token", shortToken, false)
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET encrypted_access_token = $1 WHERE id = $2`, encrypted, integrationID); err != nil {
					t.Fatalf("seed short encrypted credential: %v", err)
				}
				return shortToken
			},
			wantErrorText: "integration credential failed integrity validation",
		},
		{
			name: "tampered optional webhook secret",
			mutate: func(t *testing.T, db *sql.DB, orgID, integrationID string) string {
				tampered := tamperIngestionWorkerEnvelopeTag(t, encryptIngestionWorkerSecret(t, orgID, integrationID, "SLACK", integrationID, "webhook_secret", testIngestionWorkerWebhookSecret, false))
				if _, err := db.ExecContext(context.Background(), `UPDATE integration_connections SET encrypted_webhook_secret = $1 WHERE id = $2`, tampered, integrationID); err != nil {
					t.Fatalf("tamper encrypted webhook secret: %v", err)
				}
				return tampered
			},
			wantErrorText: "integration credential is unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openDBBackedIngestionWorkerDB(t)
			orgID := seedIngestionWorkerOrg(t, db)
			integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")
			destinationID := testWorkerID("dst")
			if _, err := db.ExecContext(context.Background(), `
				INSERT INTO siem_destinations (
					id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
				)
				VALUES ($1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'credential-gate.jsonl', ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW())
			`, destinationID, orgID); err != nil {
				t.Fatalf("seed SIEM destination: %v", err)
			}
			secretToScan := tc.mutate(t, db, orgID, integrationID)
			if tc.clearKey {
				t.Setenv("APERIO_ENCRYPTION_KEY", "")
			}
			jobID := seedIngestionWorkerJob(t, db, struct {
				orgID         string
				integrationID string
				provider      string
				eventType     string
				status        string
				attempts      int
				maxAttempts   int
				leaseOwner    *string
				payload       json.RawMessage
			}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

			sink, restore := captureIngestionTelemetry(t)
			result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
			restore()
			if err != nil {
				t.Fatalf("drain credential failure case: %v", err)
			}
			if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
				t.Fatalf("unexpected credential failure drain result: %#v", result)
			}
			status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
			if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
				t.Fatalf("credential failure job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
			}
			if !strings.Contains(lastError.String, tc.wantErrorText) {
				t.Fatalf("last_error = %q, want %q", lastError.String, tc.wantErrorText)
			}
			if len(lastError.String) > 500 {
				t.Fatalf("last_error was not bounded: length=%d", len(lastError.String))
			}
			for _, leaked := range []string{testIngestionWorkerAccessToken, testIngestionWorkerRefreshToken, testIngestionWorkerWebhookSecret, testIngestionWorkerEncryptionKey, secretToScan} {
				if strings.TrimSpace(leaked) != "" && strings.Contains(lastError.String, leaked) {
					t.Fatalf("last_error leaked secret material %q in %q", leaked, lastError.String)
				}
				if strings.TrimSpace(leaked) != "" && strings.Contains(sink.String(), leaked) {
					t.Fatalf("telemetry leaked secret material %q in %s", leaked, sink.String())
				}
			}
			failureTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "failed")
			if failureTelemetry["error_kind"] != "error" || strings.Contains(fmt.Sprint(failureTelemetry), testIngestionWorkerAccessToken) {
				t.Fatalf("credential failure telemetry unsafe: %#v", failureTelemetry)
			}
			assertNoIngestionSideEffects(t, db, orgID)
		})
	}
}

func TestSupportedIngestionProviderGatesFailClosedBeforeSideEffects(t *testing.T) {
	cases := []struct {
		name         string
		setup        func(t *testing.T, db *sql.DB, orgID string) (integrationID string, provider string)
		wantErrorSub string
	}{
		{
			name: "disabled integration",
			setup: func(t *testing.T, db *sql.DB, orgID string) (string, string) {
				return seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "DISABLED"), "SLACK"
			},
			wantErrorSub: "integration not found or not connected",
		},
		{
			name: "wrong provider",
			setup: func(t *testing.T, db *sql.DB, orgID string) (string, string) {
				return seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED"), "SLACK"
			},
			wantErrorSub: "integration not found or not connected",
		},
		{
			name: "cross tenant integration",
			setup: func(t *testing.T, db *sql.DB, orgID string) (string, string) {
				otherOrgID := seedIngestionWorkerOrg(t, db)
				return seedIngestionWorkerIntegration(t, db, otherOrgID, "SLACK", "CONNECTED"), "SLACK"
			},
			wantErrorSub: "integration not found or not connected",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openDBBackedIngestionWorkerDB(t)
			orgID := seedIngestionWorkerOrg(t, db)
			integrationID, provider := tc.setup(t, db, orgID)
			jobID := seedIngestionWorkerJob(t, db, struct {
				orgID         string
				integrationID string
				provider      string
				eventType     string
				status        string
				attempts      int
				maxAttempts   int
				leaseOwner    *string
				payload       json.RawMessage
			}{orgID: orgID, integrationID: integrationID, provider: provider, eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

			result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
			if err != nil {
				t.Fatalf("drain provider gate case: %v", err)
			}
			if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
				t.Fatalf("unexpected provider gate drain result: %#v", result)
			}
			status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
			if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, tc.wantErrorSub) {
				t.Fatalf("provider gate job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
			}
			assertNoIngestionSideEffects(t, db, orgID)
		})
	}
}

func TestSupportedSlackJobRequiresMatchingConnectedIntegration(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	githubIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: githubIntegrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: json.RawMessage(`{"user":{"email":"user@example.com"}}`)})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected wrong-provider drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("wrong-provider job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	var eventCount, findingCount int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1`, orgID).Scan(&eventCount); err != nil {
		t.Fatalf("count wrong-provider events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM security_findings WHERE organization_id = $1`, orgID).Scan(&findingCount); err != nil {
		t.Fatalf("count wrong-provider findings: %v", err)
	}
	if eventCount != 0 || findingCount != 0 {
		t.Fatalf("wrong-provider integration should not persist side effects, got events=%d findings=%d", eventCount, findingCount)
	}
}

func TestDrainPersistsSupportedGitHubJobSideEffects(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'worker-side-effects.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/aperio",
			"name":       "aperio",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobPayload := JobPayload{
		OrganizationID: orgID,
		IntegrationID:  integrationID,
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "github-audit-log",
		Actor:          "admin@example.com",
		OccurredAt:     time.Now().UTC().Add(-time.Minute),
		Payload:        payloadMap,
	}
	finding := Evaluate(jobPayload, nil)[0]
	dedupe := DedupeKey(jobPayload, finding)
	findingID := testWorkerID("fnd")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at, resolved_at
		)
		VALUES (
			$1, $2, $3, $4, 'Old title', 'Old description', 'HIGH'::"Severity",
			'RESOLVED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 hour'
		)
	`, findingID, orgID, integrationID, dedupe); err != nil {
		t.Fatalf("seed resolved finding: %v", err)
	}

	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	worker := &Worker{db: db, leaseOwner: "go-test-worker"}
	result, err := worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, jobID)
		t.Fatalf("unexpected drain result: %#v lastError=%v", result, jobError)
	}

	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("supported job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}

	var eventID string
	var eventStatus string
	var persistedEventSeverity string
	var eventOccurredAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, processing_status::text, severity::text, occurred_at
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, jobID, orgID).Scan(&eventID, &eventStatus, &persistedEventSeverity, &eventOccurredAt); err != nil {
		t.Fatalf("query ingested event: %v", err)
	}
	if eventStatus != "PROCESSED" || persistedEventSeverity != finding.Severity {
		t.Fatalf("event processing status/severity = %s/%s", eventStatus, persistedEventSeverity)
	}

	var persistedFindingID string
	var findingStatus string
	var resolvedAt sql.NullTime
	var eventIDOnFinding sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, status::text, resolved_at, event_id
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, dedupe).Scan(&persistedFindingID, &findingStatus, &resolvedAt, &eventIDOnFinding); err != nil {
		t.Fatalf("query security finding: %v", err)
	}
	if persistedFindingID != findingID || findingStatus != "OPEN" || resolvedAt.Valid || !eventIDOnFinding.Valid || eventIDOnFinding.String != eventID {
		t.Fatalf("finding dedupe/reopen state = id=%s status=%s resolved=%v event=%v", persistedFindingID, findingStatus, resolvedAt, eventIDOnFinding)
	}

	var lastSyncAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT last_sync_at
		FROM integration_connections
		WHERE id = $1
	`, integrationID).Scan(&lastSyncAt); err != nil {
		t.Fatalf("query integration last sync: %v", err)
	}
	if !lastSyncAt.Valid {
		t.Fatal("expected supported Go ingestion to update integration last_sync_at")
	}

	var deliveryPayload siemdispatcher.Payload
	var deliveryStatus, deliveryDedupe, deliveryStream, deliveryDestination string
	var rawDelivery json.RawMessage
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, dedupe_key, stream::text, destination_id, payload
		FROM siem_deliveries
		WHERE organization_id = $1
	`, orgID).Scan(&deliveryStatus, &deliveryDedupe, &deliveryStream, &deliveryDestination, &rawDelivery); err != nil {
		t.Fatalf("query SIEM delivery: %v", err)
	}
	if err := json.Unmarshal(rawDelivery, &deliveryPayload); err != nil {
		t.Fatalf("decode SIEM delivery payload: %v", err)
	}
	if deliveryStatus != "PENDING" || deliveryStream != "FINDINGS" || deliveryDestination != destinationID {
		t.Fatalf("delivery routing state = status=%s stream=%s destination=%s", deliveryStatus, deliveryStream, deliveryDestination)
	}
	assertFindingDeliveryPayload(t, deliveryPayload, findingDeliveryExpectation{
		orgID:            orgID,
		occurredAt:       eventOccurredAt,
		findingID:        persistedFindingID,
		dedupeKey:        dedupe,
		sourceEventID:    eventID,
		status:           findingStatus,
		finding:          finding,
		provider:         "GITHUB",
		integrationID:    integrationID,
		source:           "test",
		eventType:        "PUBLIC_REPOSITORY_CREATED",
		actor:            "worker@example.com",
		referenceRecord:  readSiemFindingDeliveryReferenceRecord(t),
		destinationID:    destinationID,
		deliveryDedupe:   deliveryDedupe,
		deliveryDedupeOf: "first observation",
	})
	if want := siemdispatcher.StableDeliveryKey(deliveryPayload, destinationID, "FINDINGS"); deliveryDedupe != want {
		t.Fatalf("delivery dedupe key = %s, want %s", deliveryDedupe, want)
	}

	secondJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	result, err = worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, secondJobID)
		t.Fatalf("unexpected second drain result: %#v lastError=%v", result, jobError)
	}

	var secondEventID string
	var secondEventOccurredAt time.Time
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, occurred_at
		FROM ingested_events
		WHERE ingestion_job_id = $1 AND organization_id = $2
	`, secondJobID, orgID).Scan(&secondEventID, &secondEventOccurredAt); err != nil {
		t.Fatalf("query second ingested event: %v", err)
	}
	if secondEventID == eventID {
		t.Fatalf("expected distinct persisted event ids for repeated observations, got %s", secondEventID)
	}

	var deliveryCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2 AND stream = 'FINDINGS'::"SiemStreamType"
	`, orgID, destinationID).Scan(&deliveryCount); err != nil {
		t.Fatalf("count SIEM deliveries: %v", err)
	}
	if deliveryCount != 2 {
		t.Fatalf("expected repeated observations to enqueue distinct deliveries, got %d", deliveryCount)
	}

	var secondRawDelivery json.RawMessage
	var secondDeliveryDedupe string
	if err := db.QueryRowContext(context.Background(), `
		SELECT dedupe_key, payload
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2 AND payload->'record'->>'sourceEventId' = $3
	`, orgID, destinationID, secondEventID).Scan(&secondDeliveryDedupe, &secondRawDelivery); err != nil {
		t.Fatalf("query second SIEM delivery: %v", err)
	}
	var secondDeliveryPayload siemdispatcher.Payload
	if err := json.Unmarshal(secondRawDelivery, &secondDeliveryPayload); err != nil {
		t.Fatalf("decode second SIEM delivery payload: %v", err)
	}
	assertFindingDeliveryPayload(t, secondDeliveryPayload, findingDeliveryExpectation{
		orgID:            orgID,
		occurredAt:       secondEventOccurredAt,
		findingID:        persistedFindingID,
		dedupeKey:        dedupe,
		sourceEventID:    secondEventID,
		status:           "OPEN",
		finding:          finding,
		provider:         "GITHUB",
		integrationID:    integrationID,
		source:           "test",
		eventType:        "PUBLIC_REPOSITORY_CREATED",
		actor:            "worker@example.com",
		referenceRecord:  readSiemFindingDeliveryReferenceRecord(t),
		destinationID:    destinationID,
		deliveryDedupe:   secondDeliveryDedupe,
		deliveryDedupeOf: "second observation",
	})
	if secondDeliveryDedupe == deliveryDedupe {
		t.Fatal("expected repeated observations with different sourceEventId values to have distinct delivery dedupe keys")
	}
}

func TestDrainSameJobRetryReusesSourceEventFindingAndDelivery(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	destinationID := testWorkerID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'same-job-retry.jsonl',
			ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed SIEM destination: %v", err)
	}

	payloadJSON := json.RawMessage(`{"repository":{"full_name":"writer/retry","visibility":"public"}}`)
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	worker := &Worker{db: db, leaseOwner: "go-test-worker"}
	result, err := worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("initial drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected initial drain result: %#v", result)
	}

	var firstEventID, firstFindingID, firstDeliveryID, firstDeliveryDedupe string
	if err := db.QueryRowContext(context.Background(), `
		SELECT id
		FROM ingested_events
		WHERE organization_id = $1 AND ingestion_job_id = $2
	`, orgID, jobID).Scan(&firstEventID); err != nil {
		t.Fatalf("query first ingested event: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT id
		FROM security_findings
		WHERE organization_id = $1
	`, orgID).Scan(&firstFindingID); err != nil {
		t.Fatalf("query first finding: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, dedupe_key
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2
	`, orgID, destinationID).Scan(&firstDeliveryID, &firstDeliveryDedupe); err != nil {
		t.Fatalf("query first delivery: %v", err)
	}

	if _, err := db.ExecContext(context.Background(), `
		UPDATE ingestion_jobs
		SET status = 'FAILED'::"IngestionJobStatus",
			attempts = 1,
			processed_at = NULL,
			next_attempt_at = NOW() - INTERVAL '1 minute',
			lease_owner = NULL,
			lease_expires_at = NULL,
			last_error = 'transient retry probe',
			updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, jobID, orgID); err != nil {
		t.Fatalf("reset same job for retry: %v", err)
	}

	result, err = worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("retry drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected retry drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 2 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("retried same job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}

	var eventCount, findingCount, deliveryCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM ingested_events
		WHERE organization_id = $1 AND ingestion_job_id = $2 AND id = $3
	`, orgID, jobID, firstEventID).Scan(&eventCount); err != nil {
		t.Fatalf("count retried event: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM security_findings
		WHERE organization_id = $1 AND id = $2
	`, orgID, firstFindingID).Scan(&findingCount); err != nil {
		t.Fatalf("count retried finding: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1 AND destination_id = $2 AND id = $3 AND dedupe_key = $4
	`, orgID, destinationID, firstDeliveryID, firstDeliveryDedupe).Scan(&deliveryCount); err != nil {
		t.Fatalf("count retried delivery: %v", err)
	}
	if eventCount != 1 || findingCount != 1 || deliveryCount != 1 {
		t.Fatalf("same-job retry should reuse existing side effects, got events=%d findings=%d deliveries=%d", eventCount, findingCount, deliveryCount)
	}

	var sourceEventID string
	if err := db.QueryRowContext(context.Background(), `
		SELECT payload->'record'->>'sourceEventId'
		FROM siem_deliveries
		WHERE id = $1 AND organization_id = $2
	`, firstDeliveryID, orgID).Scan(&sourceEventID); err != nil {
		t.Fatalf("query retried delivery source event: %v", err)
	}
	if sourceEventID != firstEventID {
		t.Fatalf("same-job retry delivery sourceEventId = %s, want %s", sourceEventID, firstEventID)
	}
}

func TestDrainProcessesProducerStyleJobsAndRejectsMalformedPayloads(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "SLACK", "CONNECTED")

	producerJobID := testWorkerID("job")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO ingestion_jobs (
			id, organization_id, integration_id, provider, event_type, source, actor, occurred_at,
			payload, created_at, updated_at
		)
		VALUES (
			$1, $2, $3, 'SLACK'::"SaaSProvider", 'MFA_DISABLED',
			'slack-real-producer', 'producer@example.com', $4, $5::jsonb, NOW(), NOW()
		)
	`, producerJobID, orgID, integrationID, time.Now().UTC().Add(-time.Minute), `{"user":{"email":"real-user@example.com"}}`); err != nil {
		t.Fatalf("seed producer-style ingestion job: %v", err)
	}

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain producer-style job: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected producer-style drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, producerJobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("producer-style job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	var eventSource, eventActor string
	var eventPayload json.RawMessage
	if err := db.QueryRowContext(context.Background(), `
		SELECT source, actor, payload
		FROM ingested_events
		WHERE organization_id = $1 AND ingestion_job_id = $2
	`, orgID, producerJobID).Scan(&eventSource, &eventActor, &eventPayload); err != nil {
		t.Fatalf("query producer-style ingested event: %v", err)
	}
	if eventSource != "slack-real-producer" || eventActor != "producer@example.com" || !strings.Contains(string(eventPayload), "real-user@example.com") {
		t.Fatalf("producer-style event did not preserve source/actor/payload: source=%s actor=%s payload=%s", eventSource, eventActor, string(eventPayload))
	}

	malformedPayloads := []struct {
		name    string
		payload json.RawMessage
	}{
		{name: "json null", payload: json.RawMessage(`null`)},
		{name: "array", payload: json.RawMessage(`[]`)},
		{name: "string", payload: json.RawMessage(`"not an object"`)},
		{name: "number", payload: json.RawMessage(`42`)},
		{name: "boolean", payload: json.RawMessage(`true`)},
	}
	for _, malformed := range malformedPayloads {
		malformedJobID := seedIngestionWorkerJob(t, db, struct {
			orgID         string
			integrationID string
			provider      string
			eventType     string
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
			payload       json.RawMessage
		}{orgID: orgID, integrationID: integrationID, provider: "SLACK", eventType: "MFA_DISABLED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: malformed.payload})

		result, err = (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
		if err != nil {
			t.Fatalf("drain malformed %s payload job: %v", malformed.name, err)
		}
		if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
			t.Fatalf("unexpected malformed %s payload drain result: %#v", malformed.name, result)
		}
		status, attempts, leaseOwner, processedAt, lastError = ingestionJobState(t, db, malformedJobID)
		if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "parse payload") {
			t.Fatalf("malformed %s payload job state = status=%s attempts=%d lease=%v processed=%v error=%v", malformed.name, status, attempts, leaseOwner, processedAt, lastError)
		}
		events, findings, deliveries := ingestionSideEffectCounts(t, db, orgID)
		if events != 1 || findings != 1 || deliveries != 0 {
			t.Fatalf("malformed %s payload should not add side effects beyond producer job, got events=%d findings=%d deliveries=%d", malformed.name, events, findings, deliveries)
		}
	}
}

func TestDrainFansOutFindingsOnlyToSameTenantEligibleSubscribedDestinations(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgA := seedIngestionWorkerOrg(t, db)
	orgB := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgA, "GITHUB", "CONNECTED")

	seedDestination := func(orgID, kind, status, stream string) string {
		t.Helper()
		destinationID := testWorkerID("dst")
		if _, err := db.ExecContext(context.Background(), `
			INSERT INTO siem_destinations (
				id, organization_id, kind, name, endpoint_url, file_path, streams, status, created_at, updated_at
			)
			VALUES (
				$1, $2, $3::"SiemKind", $4, 'https://example.com/collector', $5,
				ARRAY[$6::"SiemStreamType"], $7::"SiemStatus", NOW(), NOW()
			)
		`, destinationID, orgID, kind, kind+" fanout", destinationID+".jsonl", stream, status); err != nil {
			t.Fatalf("seed SIEM destination %s/%s/%s: %v", orgID, kind, stream, err)
		}
		return destinationID
	}
	activeFindingsID := seedDestination(orgA, "JSON_FILE", "ACTIVE", "FINDINGS")
	errorFindingsID := seedDestination(orgA, "GENERIC_WEBHOOK", "ERROR", "FINDINGS")
	pausedFindingsID := seedDestination(orgA, "JSON_FILE", "PAUSED", "FINDINGS")
	eventsOnlyID := seedDestination(orgA, "PANTHER", "ACTIVE", "EVENTS")
	otherTenantID := seedDestination(orgB, "JSON_FILE", "ACTIVE", "FINDINGS")

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/fanout",
			"name":       "fanout",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgA, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain fanout job: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected fanout drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("fanout job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}

	rows, err := db.QueryContext(context.Background(), `
		SELECT destination_id, stream::text, payload
		FROM siem_deliveries
		WHERE organization_id = $1
	`, orgA)
	if err != nil {
		t.Fatalf("query fanout deliveries: %v", err)
	}
	defer rows.Close()
	deliveriesByDestination := map[string]int{}
	for rows.Next() {
		var destinationID, stream string
		var rawPayload json.RawMessage
		if err := rows.Scan(&destinationID, &stream, &rawPayload); err != nil {
			t.Fatalf("scan fanout delivery: %v", err)
		}
		deliveriesByDestination[destinationID]++
		var deliveryPayload siemdispatcher.Payload
		if err := json.Unmarshal(rawPayload, &deliveryPayload); err != nil {
			t.Fatalf("decode fanout payload: %v", err)
		}
		if stream != "FINDINGS" || deliveryPayload.Kind != "finding" || deliveryPayload.OrganizationID != orgA {
			t.Fatalf("fanout delivery routing = destination=%s stream=%s payload=%#v", destinationID, stream, deliveryPayload)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fanout deliveries: %v", err)
	}
	if len(deliveriesByDestination) != 2 || deliveriesByDestination[activeFindingsID] != 1 || deliveriesByDestination[errorFindingsID] != 1 {
		t.Fatalf("expected exactly active+error same-tenant FINDINGS destinations, got %#v", deliveriesByDestination)
	}
	for name, destinationID := range map[string]string{
		"paused findings": pausedFindingsID,
		"events only":     eventsOnlyID,
		"other tenant":    otherTenantID,
	} {
		if deliveriesByDestination[destinationID] != 0 {
			t.Fatalf("%s destination received a delivery: %#v", name, deliveriesByDestination)
		}
	}
}

func TestDrainFansOutCerebroFindingsAfterCommit(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/cerebro-direct",
			"name":       "cerebro-direct",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobPayload := JobPayload{
		OrganizationID: orgID,
		IntegrationID:  integrationID,
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "test",
		Actor:          "worker@example.com",
		OccurredAt:     time.Now().UTC().Add(-time.Minute),
		Payload:        payloadMap,
	}
	finding := Evaluate(jobPayload, nil)[0]
	dedupe := DedupeKey(jobPayload, finding)
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	fanout := &recordingCerebroFindingFanout{t: t, db: db}
	worker := (&Worker{db: db, leaseOwner: "go-test-worker"}).WithCerebroFanout(fanout)
	result, err := worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain with Cerebro fanout: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		_, _, _, _, jobError := ingestionJobState(t, db, jobID)
		t.Fatalf("unexpected Cerebro fanout drain result: %#v lastError=%v", result, jobError)
	}
	if len(fanout.seen) != 1 {
		t.Fatalf("Cerebro fanout payloads = %d, want 1", len(fanout.seen))
	}

	var persistedFindingID, eventID string
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, event_id
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, dedupe).Scan(&persistedFindingID, &eventID); err != nil {
		t.Fatalf("query Cerebro fanout finding: %v", err)
	}
	payload := fanout.seen[0]
	if payload.OrganizationID != orgID || payload.Kind != "finding" || payload.OccurredAt == "" {
		t.Fatalf("Cerebro fanout routing payload = %#v", payload)
	}
	requireRecordString(t, payload.Record, "schemaVersion", "aperio.finding.v1")
	requireRecordString(t, payload.Record, "findingId", persistedFindingID)
	requireRecordString(t, payload.Record, "dedupeKey", dedupe)
	requireRecordString(t, payload.Record, "sourceEventId", eventID)
	requireRecordString(t, payload.Record, "ruleId", finding.RuleID)
	requireRecordString(t, payload.Record, "title", finding.Title)
	requireRecordString(t, payload.Record, "provider", "GITHUB")
	requireRecordString(t, payload.Record, "integrationId", integrationID)
	requireRecordString(t, payload.Record, "target", finding.Target)
	requireRecordNumber(t, payload.Record, "riskScore", float64(finding.RiskScore))
}

func TestDrainPreservesMutedFindingsAndPublishesLifecycleAfterCommit(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")

	payloadForRepo := func(repo string) (json.RawMessage, JobPayload, Finding, string) {
		payloadMap := map[string]any{
			"repository": map[string]any{
				"full_name":  repo,
				"name":       repo[strings.LastIndex(repo, "/")+1:],
				"private":    false,
				"visibility": "public",
			},
		}
		payloadJSON, _ := json.Marshal(payloadMap)
		jobPayload := JobPayload{
			OrganizationID: orgID,
			IntegrationID:  integrationID,
			Provider:       "GITHUB",
			EventType:      "PUBLIC_REPOSITORY_CREATED",
			Source:         "github-audit-log",
			Actor:          "admin@example.com",
			OccurredAt:     time.Now().UTC().Add(-time.Minute),
			Payload:        payloadMap,
		}
		finding := Evaluate(jobPayload, nil)[0]
		return payloadJSON, jobPayload, finding, DedupeKey(jobPayload, finding)
	}

	resolvedPayloadJSON, _, resolvedFinding, resolvedDedupe := payloadForRepo("writer/resolved")
	mutedPayloadJSON, _, mutedFinding, mutedDedupe := payloadForRepo("writer/muted")
	createdPayloadJSON, _, createdFinding, createdDedupe := payloadForRepo("writer/created")
	resolvedFindingID := testWorkerID("fnd")
	mutedFindingID := testWorkerID("fnd")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at, resolved_at
		)
		VALUES
			($1, $2, $3, $4, $5, $6, 'HIGH'::"Severity", 'RESOLVED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 hour'),
			($7, $2, $3, $8, $9, $10, 'HIGH'::"Severity", 'MUTED'::"FindingStatus", 10, ARRAY[]::text[], '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '2 hours')
	`, resolvedFindingID, orgID, integrationID, resolvedDedupe, resolvedFinding.Title, resolvedFinding.Description, mutedFindingID, mutedDedupe, mutedFinding.Title, mutedFinding.Description); err != nil {
		t.Fatalf("seed lifecycle findings: %v", err)
	}
	resolvedJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: resolvedPayloadJSON})
	mutedJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: mutedPayloadJSON})
	createdJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: createdPayloadJSON})

	publisher := &recordingLifecyclePublisher{t: t, db: db}
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker", eventPublisher: publisher}).Drain(context.Background(), 3)
	if err != nil {
		t.Fatalf("drain lifecycle jobs: %v", err)
	}
	if result.Processed != 3 || result.Succeeded != 3 || result.Failed != 0 {
		t.Fatalf("unexpected lifecycle drain result: %#v", result)
	}
	for _, jobID := range []string{resolvedJobID, mutedJobID, createdJobID} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("lifecycle job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	var resolvedStatus string
	var resolvedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, resolved_at
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, resolvedFindingID, orgID).Scan(&resolvedStatus, &resolvedAt); err != nil {
		t.Fatalf("query resolved lifecycle finding: %v", err)
	}
	if resolvedStatus != "OPEN" || resolvedAt.Valid {
		t.Fatalf("resolved finding should reopen, got status=%s resolvedAt=%v", resolvedStatus, resolvedAt)
	}

	var mutedStatus string
	var mutedResolvedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, resolved_at
		FROM security_findings
		WHERE id = $1 AND organization_id = $2
	`, mutedFindingID, orgID).Scan(&mutedStatus, &mutedResolvedAt); err != nil {
		t.Fatalf("query muted lifecycle finding: %v", err)
	}
	if mutedStatus != "MUTED" || !mutedResolvedAt.Valid {
		t.Fatalf("muted finding should remain muted with resolved_at preserved, got status=%s resolvedAt=%v", mutedStatus, mutedResolvedAt)
	}

	var createdFindingID string
	var createdStatus string
	if err := db.QueryRowContext(context.Background(), `
		SELECT id, status::text
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, orgID, createdDedupe).Scan(&createdFindingID, &createdStatus); err != nil {
		t.Fatalf("query created lifecycle finding: %v", err)
	}
	if createdStatus != "OPEN" || createdFindingID == "" || createdFinding.RuleID == "" {
		t.Fatalf("created finding state = id=%s status=%s rule=%s", createdFindingID, createdStatus, createdFinding.RuleID)
	}

	if len(publisher.seen) != 2 {
		t.Fatalf("expected created and reopened finding lifecycle events only, got %#v", publisher.seen)
	}
	seenByFinding := map[string]FindingLifecycleEvent{}
	for _, event := range publisher.seen {
		seenByFinding[event.FindingID] = event
	}
	reopenedEvent := seenByFinding[resolvedFindingID]
	if reopenedEvent.FindingID != resolvedFindingID || reopenedEvent.OrganizationID != orgID || reopenedEvent.IntegrationID != integrationID || reopenedEvent.PreviousStatus != "RESOLVED" || reopenedEvent.NextStatus != "OPEN" || reopenedEvent.ResolutionNote != "Finding observed again during ingestion" {
		t.Fatalf("unexpected reopened lifecycle event: %#v", reopenedEvent)
	}
	createdEvent := seenByFinding[createdFindingID]
	if createdEvent.FindingID != createdFindingID || createdEvent.PreviousStatus != "NEW" || createdEvent.NextStatus != "OPEN" || createdEvent.ResolutionNote != "Finding observed during ingestion" {
		t.Fatalf("unexpected created lifecycle event: %#v", createdEvent)
	}

	refreshJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: createdPayloadJSON})
	result, err = (&Worker{db: db, leaseOwner: "go-test-worker", eventPublisher: publisher}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain lifecycle refresh job: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected lifecycle refresh result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, refreshJobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("refresh job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	if len(publisher.seen) != 2 {
		t.Fatalf("routine refresh should not duplicate finding lifecycle events, got %#v", publisher.seen)
	}
}

func TestDrainMaintainsTenantIsolationForFindingsEventsAndDeliveries(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgA := seedIngestionWorkerOrg(t, db)
	orgB := seedIngestionWorkerOrg(t, db)
	integrationA := seedIngestionWorkerIntegration(t, db, orgA, "GITHUB", "CONNECTED")
	integrationB := seedIngestionWorkerIntegration(t, db, orgB, "GITHUB", "CONNECTED")
	destinationA := testWorkerID("dst")
	destinationB := testWorkerID("dst")
	for _, row := range []struct {
		id    string
		orgID string
	}{
		{id: destinationA, orgID: orgA},
		{id: destinationB, orgID: orgB},
	} {
		if _, err := db.ExecContext(context.Background(), `
			INSERT INTO siem_destinations (
				id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
			)
			VALUES (
				$1, $2, 'JSON_FILE'::"SiemKind", 'JSON file', 'tenant-isolation.jsonl',
				ARRAY['FINDINGS']::"SiemStreamType"[], 'ACTIVE'::"SiemStatus", NOW(), NOW()
			)
		`, row.id, row.orgID); err != nil {
			t.Fatalf("seed tenant SIEM destination: %v", err)
		}
	}

	payloadMap := map[string]any{
		"repository": map[string]any{
			"full_name":  "writer/shared",
			"name":       "shared",
			"private":    false,
			"visibility": "public",
		},
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	jobA := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgA, integrationID: integrationA, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})
	jobB := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgB, integrationID: integrationB, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payloadJSON})

	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 2)
	if err != nil {
		t.Fatalf("drain tenant jobs: %v", err)
	}
	if result.Processed != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Fatalf("unexpected tenant drain result: %#v", result)
	}
	for _, jobID := range []string{jobA, jobB} {
		status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
		if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
			t.Fatalf("tenant job %s state = status=%s attempts=%d lease=%v processed=%v error=%v", jobID, status, attempts, leaseOwner, processedAt, lastError)
		}
	}

	for _, row := range []struct {
		orgID         string
		integrationID string
		destinationID string
	}{
		{orgID: orgA, integrationID: integrationA, destinationID: destinationA},
		{orgID: orgB, integrationID: integrationB, destinationID: destinationB},
	} {
		jobPayload := JobPayload{
			OrganizationID: row.orgID,
			IntegrationID:  row.integrationID,
			Provider:       "GITHUB",
			EventType:      "PUBLIC_REPOSITORY_CREATED",
			Source:         "test",
			Actor:          "worker@example.com",
			OccurredAt:     time.Now().UTC(),
			Payload:        payloadMap,
		}
		finding := Evaluate(jobPayload, nil)[0]
		dedupe := DedupeKey(jobPayload, finding)
		var findingCount, eventCount, deliveryCount, mismatchedDeliveries int
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM security_findings WHERE organization_id = $1 AND integration_id = $2 AND dedupe_key = $3
		`, row.orgID, row.integrationID, dedupe).Scan(&findingCount); err != nil {
			t.Fatalf("count tenant finding: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1 AND integration_id = $2
		`, row.orgID, row.integrationID).Scan(&eventCount); err != nil {
			t.Fatalf("count tenant event: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1 AND destination_id = $2
		`, row.orgID, row.destinationID).Scan(&deliveryCount); err != nil {
			t.Fatalf("count tenant delivery: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), `
			SELECT COUNT(*)
			FROM siem_deliveries sd
			JOIN siem_destinations dst ON dst.id = sd.destination_id
			WHERE sd.organization_id = $1 AND dst.organization_id <> sd.organization_id
		`, row.orgID).Scan(&mismatchedDeliveries); err != nil {
			t.Fatalf("count mismatched tenant deliveries: %v", err)
		}
		if findingCount != 1 || eventCount != 1 || deliveryCount != 1 || mismatchedDeliveries != 0 {
			t.Fatalf("tenant %s counts finding=%d event=%d delivery=%d mismatched=%d", row.orgID, findingCount, eventCount, deliveryCount, mismatchedDeliveries)
		}
	}
}

type findingDeliveryExpectation struct {
	orgID            string
	occurredAt       time.Time
	findingID        string
	dedupeKey        string
	sourceEventID    string
	status           string
	finding          Finding
	provider         string
	integrationID    string
	source           string
	eventType        string
	actor            string
	referenceRecord  map[string]any
	destinationID    string
	deliveryDedupe   string
	deliveryDedupeOf string
}

func assertFindingDeliveryPayload(t *testing.T, payload siemdispatcher.Payload, want findingDeliveryExpectation) {
	t.Helper()
	if payload.Kind != "finding" || payload.OrganizationID != want.orgID {
		t.Fatalf("delivery payload routing = kind=%s org=%s", payload.Kind, payload.OrganizationID)
	}
	if payload.OccurredAt != want.occurredAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("delivery occurredAt = %s, want %s", payload.OccurredAt, want.occurredAt.UTC().Format(time.RFC3339Nano))
	}
	for key := range want.referenceRecord {
		if _, ok := payload.Record[key]; !ok {
			t.Fatalf("delivery record missing shared fixture field %q in %#v", key, payload.Record)
		}
	}
	requireRecordString(t, payload.Record, "schemaVersion", "aperio.finding.v1")
	requireRecordString(t, payload.Record, "findingId", want.findingID)
	requireRecordString(t, payload.Record, "dedupeKey", want.dedupeKey)
	requireRecordString(t, payload.Record, "sourceEventId", want.sourceEventID)
	requireRecordString(t, payload.Record, "status", want.status)
	requireRecordString(t, payload.Record, "ruleId", want.finding.RuleID)
	requireRecordString(t, payload.Record, "title", want.finding.Title)
	requireRecordString(t, payload.Record, "description", want.finding.Description)
	requireRecordString(t, payload.Record, "severity", want.finding.Severity)
	requireRecordNumber(t, payload.Record, "riskScore", float64(want.finding.RiskScore))
	requireRecordStringSlice(t, payload.Record, "remediationSteps", want.finding.RemediationSteps)
	requireRecordString(t, payload.Record, "target", want.finding.Target)
	requireRecordString(t, payload.Record, "provider", want.provider)
	requireRecordString(t, payload.Record, "integrationId", want.integrationID)
	requireRecordString(t, payload.Record, "source", want.source)
	requireRecordString(t, payload.Record, "eventType", want.eventType)
	requireRecordString(t, payload.Record, "actor", want.actor)
	if got, wantKey := want.deliveryDedupe, siemdispatcher.StableDeliveryKey(payload, want.destinationID, "FINDINGS"); got != wantKey {
		t.Fatalf("%s delivery dedupe key = %s, want %s", want.deliveryDedupeOf, got, wantKey)
	}
}

func requireRecordString(t *testing.T, record map[string]any, key string, want string) {
	t.Helper()
	got, ok := record[key].(string)
	if !ok || got != want {
		t.Fatalf("delivery record[%s] = %#v, want %q", key, record[key], want)
	}
}

func requireRecordNumber(t *testing.T, record map[string]any, key string, want float64) {
	t.Helper()
	got, ok := recordNumber(record[key])
	if !ok || got != want {
		t.Fatalf("delivery record[%s] = %#v, want %v", key, record[key], want)
	}
}

func recordNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func requireRecordStringSlice(t *testing.T, record map[string]any, key string, want []string) {
	t.Helper()
	values, ok := record[key].([]any)
	if !ok || len(values) != len(want) {
		t.Fatalf("delivery record[%s] = %#v, want %#v", key, record[key], want)
	}
	for index, value := range values {
		got, ok := value.(string)
		if !ok || got != want[index] {
			t.Fatalf("delivery record[%s][%d] = %#v, want %q", key, index, value, want[index])
		}
	}
}

func TestDrainRetriesExpiredLeasesAndHonorsLimit(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	disabledIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "DISABLED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/aperio","visibility":"public"}}`)
	firstJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: disabledIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})
	secondJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: disabledIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain retryable failure: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected retryable failure result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, firstJobID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("retryable failure state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	if !ingestionJobNextAttemptAt(t, db, firstJobID).After(time.Now().UTC()) {
		t.Fatal("retryable failure should schedule a future next_attempt_at")
	}
	status, attempts, leaseOwner, processedAt, lastError = ingestionJobState(t, db, secondJobID)
	if status != "QUEUED" || attempts != 0 || leaseOwner.Valid || processedAt.Valid || lastError.Valid {
		t.Fatalf("limit should leave second job untouched, got status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	failedTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "failed")
	if failedTelemetry["provider"] != "GITHUB" || failedTelemetry["event_type"] != "PUBLIC_REPOSITORY_CREATED" || failedTelemetry["attempt"] != float64(1) || failedTelemetry["max_attempts"] != float64(3) || failedTelemetry["error_kind"] != "error" {
		t.Fatalf("retry telemetry missing required fields: %#v", failedTelemetry)
	}
	if strings.Contains(sink.String(), "test-token") {
		t.Fatalf("retry telemetry leaked integration token: %s", sink.String())
	}

	if _, err := db.ExecContext(context.Background(), `
		UPDATE ingestion_jobs SET next_attempt_at = NOW() + INTERVAL '1 hour' WHERE id = $1
	`, secondJobID); err != nil {
		t.Fatalf("defer second retry job: %v", err)
	}
	connectedIntegrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	staleOwner := "stale-worker"
	expiredJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: connectedIntegrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "RUNNING", attempts: 0, maxAttempts: 3, leaseOwner: &staleOwner, payload: payload})
	result, err = (&Worker{db: db, leaseOwner: "reclaim-worker"}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain expired lease: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("unexpected expired lease result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError = ingestionJobState(t, db, expiredJobID)
	if status != "SUCCEEDED" || attempts != 1 || leaseOwner.Valid || !processedAt.Valid || lastError.Valid {
		t.Fatalf("expired lease job state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
}

func TestDrainConcurrentWorkersDoNotDuplicateClaims(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "CONNECTED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/concurrent","visibility":"public"}}`)
	for i := 0; i < 4; i++ {
		seedIngestionWorkerJob(t, db, struct {
			orgID         string
			integrationID string
			provider      string
			eventType     string
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
			payload       json.RawMessage
		}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 0, maxAttempts: 3, payload: payload})
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan Result, 2)
	errs := make(chan error, 2)
	for _, owner := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			<-start
			result, err := (&Worker{db: db, leaseOwner: owner}).Drain(context.Background(), 3)
			results <- result
			errs <- err
		}(owner)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent drain: %v", err)
		}
	}
	totalProcessed := 0
	totalSucceeded := 0
	for result := range results {
		totalProcessed += result.Processed
		totalSucceeded += result.Succeeded
	}
	if totalProcessed != 4 || totalSucceeded != 4 {
		t.Fatalf("expected four unique jobs processed, got processed=%d succeeded=%d", totalProcessed, totalSucceeded)
	}

	var eventCount, succeededJobs int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM ingested_events WHERE organization_id = $1
	`, orgID).Scan(&eventCount); err != nil {
		t.Fatalf("count concurrent ingested events: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM ingestion_jobs WHERE organization_id = $1 AND status = 'SUCCEEDED'::"IngestionJobStatus"
	`, orgID).Scan(&succeededJobs); err != nil {
		t.Fatalf("count concurrent succeeded jobs: %v", err)
	}
	if eventCount != 4 || succeededJobs != 4 {
		t.Fatalf("concurrent workers should process each job once, events=%d succeededJobs=%d", eventCount, succeededJobs)
	}
}

func TestSupportedIngestionFailureDeadLettersAndHonorsLease(t *testing.T) {
	db := openDBBackedIngestionWorkerDB(t)
	orgID := seedIngestionWorkerOrg(t, db)
	integrationID := seedIngestionWorkerIntegration(t, db, orgID, "GITHUB", "DISABLED")
	payload := json.RawMessage(`{"repository":{"full_name":"writer/aperio","visibility":"public"}}`)
	jobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "QUEUED", attempts: 2, maxAttempts: 3, payload: payload})

	sink, restore := captureIngestionTelemetry(t)
	result, err := (&Worker{db: db, leaseOwner: "go-test-worker"}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Succeeded != 0 || result.Failed != 1 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	status, attempts, leaseOwner, processedAt, lastError := ingestionJobState(t, db, jobID)
	if status != "DEAD_LETTER" || attempts != 3 || leaseOwner.Valid || processedAt.Valid || !lastError.Valid {
		t.Fatalf("dead-letter state = status=%s attempts=%d lease=%v processed=%v error=%v", status, attempts, leaseOwner, processedAt, lastError)
	}
	deadTelemetry := requireTelemetryOutcome(t, decodeWideEvents(t, sink), "dead_letter")
	if deadTelemetry["provider"] != "GITHUB" || deadTelemetry["attempt"] != float64(3) || deadTelemetry["max_attempts"] != float64(3) || deadTelemetry["error_kind"] != "error" {
		t.Fatalf("dead-letter telemetry missing required fields: %#v", deadTelemetry)
	}

	otherOwner := "other-worker"
	lostLeaseJobID := seedIngestionWorkerJob(t, db, struct {
		orgID         string
		integrationID string
		provider      string
		eventType     string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
		payload       json.RawMessage
	}{orgID: orgID, integrationID: integrationID, provider: "GITHUB", eventType: "PUBLIC_REPOSITORY_CREATED", status: "RUNNING", attempts: 0, maxAttempts: 3, leaseOwner: &otherOwner, payload: payload})
	err = (&Worker{db: db, leaseOwner: "go-test-worker"}).finish(context.Background(), job{
		ID:          lostLeaseJobID,
		Attempts:    0,
		MaxAttempts: 3,
	}, false, "lost lease probe")
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("expected lost lease error, got %v", err)
	}
	status, attempts, leaseOwner, _, _ = ingestionJobState(t, db, lostLeaseJobID)
	if status != "RUNNING" || attempts != 0 || !leaseOwner.Valid || leaseOwner.String != otherOwner {
		t.Fatalf("lost lease job changed: status=%s attempts=%d lease=%v", status, attempts, leaseOwner)
	}
}
