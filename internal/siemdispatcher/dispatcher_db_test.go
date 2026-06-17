package siemdispatcher

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/telemetry"
)

type recordingClaimFanoutPublisher struct {
	t                 *testing.T
	db                *sql.DB
	events            []CerebroClaimsFanoutEvent
	deliveryStatuses  []string
	destinationHealth []string
	err               error
}

func (p *recordingClaimFanoutPublisher) PublishCerebroClaimsFanout(ctx context.Context, event CerebroClaimsFanoutEvent) error {
	p.t.Helper()
	var deliveryStatus string
	if err := p.db.QueryRowContext(ctx, `
		SELECT status::text
		FROM siem_deliveries
		WHERE id = $1 AND organization_id = $2
	`, event.DeliveryID, event.OrganizationID).Scan(&deliveryStatus); err != nil {
		p.t.Fatalf("query delivery status during fanout publish: %v", err)
	}
	var destinationStatus string
	if err := p.db.QueryRowContext(ctx, `
		SELECT status::text
		FROM siem_destinations
		WHERE id = $1 AND organization_id = $2
	`, event.DestinationID, event.OrganizationID).Scan(&destinationStatus); err != nil {
		p.t.Fatalf("query destination status during fanout publish: %v", err)
	}
	p.events = append(p.events, event)
	p.deliveryStatuses = append(p.deliveryStatuses, deliveryStatus)
	p.destinationHealth = append(p.destinationHealth, destinationStatus)
	return p.err
}

func openDBBackedSIEMDispatcherDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("set APERIO_TEST_DATABASE_URL to run DB-backed SIEM dispatcher tests")
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

func captureSIEMTelemetry(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var sink bytes.Buffer
	restore := telemetry.SetOutput(&sink)
	return &sink, restore
}

func decodeSIEMWideEvents(t *testing.T, sink *bytes.Buffer) []map[string]any {
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

func requireSIEMTelemetryOutcome(t *testing.T, events []map[string]any, outcome string) map[string]any {
	t.Helper()
	for _, event := range events {
		if event["event_name"] == "siem.delivery.process" && event["outcome"] == outcome {
			return event
		}
	}
	t.Fatalf("missing SIEM telemetry outcome %q in %#v", outcome, events)
	return nil
}

func testDispatcherID(prefix string) string {
	return prefix + "_" + randomID()
}

func seedDispatcherOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	orgID := testDispatcherID("org")
	slug := "go-siem-" + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, "Go SIEM Test", slug); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID
}

func seedDispatcherDestination(t *testing.T, db *sql.DB, orgID, kind, status, filePath string) string {
	t.Helper()
	return seedDispatcherDestinationForStream(t, db, orgID, kind, status, filePath, "FINDINGS")
}

func seedDispatcherDestinationForStream(t *testing.T, db *sql.DB, orgID, kind, status, filePath, stream string) string {
	t.Helper()
	destinationID := testDispatcherID("dst")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, endpoint_url, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, $3::"SiemKind", $4, 'https://example.com/collector', $5,
			ARRAY[$6::"SiemStreamType"], $7::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID, kind, kind+" destination", nullableFilePath(filePath), stream, status); err != nil {
		t.Fatalf("seed %s destination: %v", kind, err)
	}
	return destinationID
}

func updateDispatcherDestinationToken(t *testing.T, db *sql.DB, orgID, destinationID, token string) {
	t.Helper()
	dest := destination{ID: destinationID, OrganizationID: orgID}
	encrypted := encryptForDispatcherTest(t, token, destinationTokenAAD(dest))
	if _, err := db.ExecContext(context.Background(), `
		UPDATE siem_destinations
		SET encrypted_token = $1, updated_at = NOW()
		WHERE id = $2 AND organization_id = $3
	`, encrypted, destinationID, orgID); err != nil {
		t.Fatalf("update encrypted SIEM token: %v", err)
	}
}

func updateDispatcherDestinationEncryptedToken(t *testing.T, db *sql.DB, orgID, destinationID, encrypted string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE siem_destinations
		SET encrypted_token = $1, updated_at = NOW()
		WHERE id = $2 AND organization_id = $3
	`, encrypted, destinationID, orgID); err != nil {
		t.Fatalf("update encrypted SIEM token: %v", err)
	}
}

func updateDispatcherDestinationIndex(t *testing.T, db *sql.DB, orgID, destinationID, index string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE siem_destinations
		SET index = $1, updated_at = NOW()
		WHERE id = $2 AND organization_id = $3
	`, index, destinationID, orgID); err != nil {
		t.Fatalf("update SIEM destination index: %v", err)
	}
}

func updateDispatcherDestinationEndpoint(t *testing.T, db *sql.DB, orgID, destinationID, endpoint string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `
		UPDATE siem_destinations
		SET endpoint_url = $1, updated_at = NOW()
		WHERE id = $2 AND organization_id = $3
	`, endpoint, destinationID, orgID); err != nil {
		t.Fatalf("update SIEM destination endpoint: %v", err)
	}
}

func nullableFilePath(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func fixtureDeliveryPayload(t *testing.T, orgID string) Payload {
	t.Helper()
	return Payload{
		Kind:           "finding",
		OrganizationID: orgID,
		OccurredAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Record: map[string]any{
			"findingId":     testDispatcherID("fnd"),
			"dedupeKey":     testDispatcherID("dedupe"),
			"sourceEventId": testDispatcherID("evt"),
			"status":        "OPEN",
			"title":         "Public GitHub repository created",
			"severity":      "CRITICAL",
		},
	}
}

func seedDispatcherDelivery(t *testing.T, db *sql.DB, input struct {
	orgID         string
	destinationID string
	payload       Payload
	status        string
	attempts      int
	maxAttempts   int
	leaseOwner    *string
}) string {
	t.Helper()
	deliveryID := testDispatcherID("sdel")
	rawPayload, err := json.Marshal(input.payload)
	if err != nil {
		t.Fatalf("encode delivery payload: %v", err)
	}
	dedupe := StableDeliveryKey(input.payload, input.destinationID, "FINDINGS")
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_deliveries (
			id, organization_id, destination_id, stream, dedupe_key, payload, status,
			attempts, max_attempts, next_attempt_at, lease_owner, lease_expires_at,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, 'FINDINGS'::"SiemStreamType", $4, $5, $6::"SiemDeliveryStatus",
			$7, $8, NOW() - INTERVAL '1 minute', $9::text,
			CASE WHEN $9::text IS NULL THEN NULL ELSE NOW() - INTERVAL '1 minute' END,
			NOW() - INTERVAL '30 minutes', NOW()
		)
	`, deliveryID, input.orgID, input.destinationID, dedupe, json.RawMessage(rawPayload), input.status, input.attempts, input.maxAttempts, input.leaseOwner); err != nil {
		t.Fatalf("seed SIEM delivery: %v", err)
	}
	return deliveryID
}

func seedDispatcherDeliveryForStream(t *testing.T, db *sql.DB, input struct {
	orgID         string
	destinationID sql.NullString
	payload       Payload
	stream        string
	status        string
	attempts      int
	maxAttempts   int
	leaseOwner    *string
}) string {
	t.Helper()
	deliveryID := testDispatcherID("sdel")
	rawPayload, err := json.Marshal(input.payload)
	if err != nil {
		t.Fatalf("encode delivery payload: %v", err)
	}
	var dedupe sql.NullString
	if input.destinationID.Valid {
		dedupe = sql.NullString{String: StableDeliveryKey(input.payload, input.destinationID.String, input.stream), Valid: true}
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_deliveries (
			id, organization_id, destination_id, stream, dedupe_key, payload, status,
			attempts, max_attempts, next_attempt_at, lease_owner, lease_expires_at,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4::"SiemStreamType", $5, $6, $7::"SiemDeliveryStatus",
			$8, $9, NOW() - INTERVAL '1 minute', $10::text,
			CASE WHEN $10::text IS NULL THEN NULL ELSE NOW() - INTERVAL '1 minute' END,
			NOW(), NOW()
		)
	`, deliveryID, input.orgID, input.destinationID, input.stream, dedupe, json.RawMessage(rawPayload), input.status, input.attempts, input.maxAttempts, input.leaseOwner); err != nil {
		t.Fatalf("seed SIEM delivery on stream %s: %v", input.stream, err)
	}
	return deliveryID
}

func siemDeliveryState(t *testing.T, db *sql.DB, deliveryID string) (status string, attempts int, leaseOwner sql.NullString, deliveredAt sql.NullTime, nextAttemptAt time.Time, lastError sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, attempts, lease_owner, delivered_at, next_attempt_at, last_error
		FROM siem_deliveries
		WHERE id = $1
	`, deliveryID).Scan(&status, &attempts, &leaseOwner, &deliveredAt, &nextAttemptAt, &lastError); err != nil {
		t.Fatalf("query SIEM delivery %s: %v", deliveryID, err)
	}
	return status, attempts, leaseOwner, deliveredAt, nextAttemptAt, lastError
}

func siemDestinationHealth(t *testing.T, db *sql.DB, destinationID string) (status string, deliveriesOK int, deliveriesFail int, lastDeliveryAt sql.NullTime, lastError sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, deliveries_ok, deliveries_fail, last_delivery_at, last_error
		FROM siem_destinations
		WHERE id = $1
	`, destinationID).Scan(&status, &deliveriesOK, &deliveriesFail, &lastDeliveryAt, &lastError); err != nil {
		t.Fatalf("query destination health %s: %v", destinationID, err)
	}
	return status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError
}

func TestRetireExhaustedDeadLettersWithTelemetryAndReason(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "JSON_FILE", "ACTIVE", "exhausted.jsonl")
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "FAILED", attempts: 2, maxAttempts: 2})

	sink, restore := captureSIEMTelemetry(t)
	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test-exhausted", organizationID: orgID}).Drain(context.Background(), 10)
	restore()
	if err != nil {
		t.Fatalf("drain exhausted: %v", err)
	}
	if result.Processed != 0 || result.Delivered != 0 || result.Failed != 0 {
		t.Fatalf("exhausted rows should retire before claim without counting as processed, got %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "DEAD_LETTER" || attempts != 2 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "max delivery attempts exhausted") {
		t.Fatalf("exhausted delivery state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}

	event := requireSIEMTelemetryOutcome(t, decodeSIEMWideEvents(t, sink), "dead_letter")
	if event["organization_id"] != orgID ||
		event["destination_id"] != destinationID ||
		event["destination_kind"] != "JSON_FILE" ||
		event["stream"] != "FINDINGS" ||
		event["payload_kind"] != "finding" ||
		event["permanence"] != "exhausted" ||
		event["error_kind"] != "max_attempts" {
		t.Fatalf("unexpected exhausted telemetry event: %#v", event)
	}
}

func TestDispatcherFailureRedactsPersistedErrorsAndTelemetry(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "GENERIC_WEBHOOK", "ACTIVE", "")
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	secret := "siem-fixture-secret"
	destinationToken := "db-token-secret"
	endpointUser := "endpoint-user-secret"
	endpointPassword := "endpoint-password-secret"
	endpointQuerySecret := "endpoint-query-secret"
	endpoint := "https://" + endpointUser + ":" + endpointPassword + "@example.com/collector?api_key=" + endpointQuerySecret + "&tenant=local"
	updateDispatcherDestinationEndpoint(t, db, orgID, destinationID, endpoint)
	updateDispatcherDestinationToken(t, db, orgID, destinationID, destinationToken)
	secretDSN := "postgres://aperio:" + secret + "@127.0.0.1:5433/aperio?sslmode=disable&token=" + secret
	t.Setenv("DATABASE_URL", secretDSN)
	t.Setenv("APERIO_NATS_URL", "nats://aperio:"+secret+"@127.0.0.1:4222")
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 0, maxAttempts: 3})

	transportErr := errors.New("request failed with token " + secret + " stored token " + destinationToken + " endpoint " + endpoint + " dsn " + secretDSN)
	sink, restore := captureSIEMTelemetry(t)
	result, err := (&Dispatcher{
		db:                  db,
		leaseOwner:          "go-siem-test-redaction",
		organizationID:      orgID,
		httpClient:          &http.Client{Transport: &captureTransport{err: transportErr}},
		endpointSafetyCheck: func(context.Context, string) error { return nil },
	}).Drain(context.Background(), 1)
	restore()
	if err != nil {
		t.Fatalf("drain redaction failure: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
		t.Fatalf("unexpected redaction drain result: %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid {
		t.Fatalf("redacted failure delivery state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	_, _, _, _, destinationError := siemDestinationHealth(t, db, destinationID)
	for surface, value := range map[string]string{
		"delivery last_error":    lastError.String,
		"destination last_error": destinationError.String,
		"telemetry":              sink.String(),
	} {
		for _, leaked := range []string{secret, secretDSN, destinationToken, endpointUser, endpointPassword, endpointQuerySecret} {
			if strings.Contains(value, leaked) {
				t.Fatalf("%s leaked secret material", surface)
			}
		}
		if strings.Contains(value, endpoint) {
			t.Fatalf("%s leaked raw destination endpoint", surface)
		}
	}
	if !strings.Contains(lastError.String, runtimeutil.Redacted) || !strings.Contains(destinationError.String, runtimeutil.Redacted) {
		t.Fatalf("persisted errors did not contain redaction marker: delivery=%q destination=%q", lastError.String, destinationError.String)
	}
	event := requireSIEMTelemetryOutcome(t, decodeSIEMWideEvents(t, sink), "retryable_failed")
	if event["destination_kind"] != "GENERIC_WEBHOOK" || event["permanence"] != "retryable" || event["error_kind"] != "error" {
		t.Fatalf("unexpected redaction failure telemetry event: %#v", event)
	}
}

func TestDrainTelemetryClassifiesTypedFailuresThroughProcessPath(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "GENERIC_WEBHOOK", "ACTIVE", "")

	cases := []struct {
		name           string
		transport      *captureTransport
		wantOutcome    string
		wantErrorKind  string
		wantPermanence string
	}{
		{
			name:           "timeout",
			transport:      &captureTransport{err: context.DeadlineExceeded},
			wantOutcome:    "timeout",
			wantErrorKind:  "timeout",
			wantPermanence: "retryable",
		},
		{
			name:           "http 5xx",
			transport:      &captureTransport{status: http.StatusServiceUnavailable},
			wantOutcome:    "retryable_failed",
			wantErrorKind:  "http_5xx",
			wantPermanence: "retryable",
		},
		{
			name:           "http 4xx",
			transport:      &captureTransport{status: http.StatusUnauthorized},
			wantOutcome:    "dead_letter",
			wantErrorKind:  "http_4xx",
			wantPermanence: "permanent",
		},
	}

	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			casePayload := fixtureDeliveryPayload(t, orgID)
			seedDispatcherDelivery(t, db, struct {
				orgID         string
				destinationID string
				payload       Payload
				status        string
				attempts      int
				maxAttempts   int
				leaseOwner    *string
			}{orgID: orgID, destinationID: destinationID, payload: casePayload, status: "PENDING", attempts: 0, maxAttempts: 3})
			sink, restore := captureSIEMTelemetry(t)
			result, err := (&Dispatcher{
				db:                  db,
				leaseOwner:          fmt.Sprintf("go-siem-test-typed-telemetry-%d", index),
				organizationID:      orgID,
				httpClient:          &http.Client{Transport: testCase.transport},
				endpointSafetyCheck: func(context.Context, string) error { return nil },
			}).Drain(context.Background(), 1)
			restore()
			if err != nil {
				t.Fatalf("drain typed telemetry case: %v", err)
			}
			if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
				t.Fatalf("unexpected typed telemetry drain result: %#v", result)
			}
			event := requireSIEMTelemetryOutcome(t, decodeSIEMWideEvents(t, sink), testCase.wantOutcome)
			if event["destination_kind"] != "GENERIC_WEBHOOK" ||
				event["error_kind"] != testCase.wantErrorKind ||
				event["permanence"] != testCase.wantPermanence {
				t.Fatalf("unexpected typed telemetry event: %#v", event)
			}
		})
	}
}

func TestProcessLostLeaseEmitsTelemetryWithoutFinalizing(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	destinationID := seedDispatcherDestination(t, db, orgID, "JSON_FILE", "ACTIVE", "lost-lease.jsonl")
	otherOwner := "other-dispatcher"
	payload := fixtureDeliveryPayload(t, orgID)
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: payload, status: "PROCESSING", attempts: 0, maxAttempts: 2, leaseOwner: &otherOwner})
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode lost-lease payload: %v", err)
	}

	dispatcher := &Dispatcher{db: db, leaseOwner: "go-siem-test-lost-lease", organizationID: orgID}
	sink, restore := captureSIEMTelemetry(t)
	err = dispatcher.process(context.Background(), delivery{
		ID:             deliveryID,
		OrganizationID: orgID,
		DestinationID:  sql.NullString{String: destinationID, Valid: true},
		Stream:         "FINDINGS",
		Payload:        json.RawMessage(rawPayload),
		Attempts:       0,
		MaxAttempts:    2,
	})
	restore()
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("expected lost lease error, got %v", err)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "PROCESSING" || attempts != 0 || !leaseOwner.Valid || leaseOwner.String != otherOwner || deliveredAt.Valid || lastError.Valid {
		t.Fatalf("lost lease delivery changed: status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	event := requireSIEMTelemetryOutcome(t, decodeSIEMWideEvents(t, sink), "lost_lease")
	if event["destination_kind"] != "JSON_FILE" || event["destination_id"] != destinationID || event["error_kind"] != "lease_lost" {
		t.Fatalf("unexpected lost-lease telemetry event: %#v", event)
	}
}

func TestDrainClaimsAllGoOwnedDestinationKindsAndFailsMisconfiguredRowsSafely(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "SPLUNK_HEC", "ACTIVE", "")
	cerebroDestinationID := seedDispatcherDestination(t, db, orgID, "CEREBRO_CLAIMS", "ACTIVE", "")
	payload := fixtureDeliveryPayload(t, orgID)

	pendingID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: payload, status: "PENDING", attempts: 0, maxAttempts: 5})
	exhaustedID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "FAILED", attempts: 5, maxAttempts: 5})
	cerebroID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: cerebroDestinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 0, maxAttempts: 5})

	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgID}).Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 2 || result.Delivered != 0 || result.Failed != 2 {
		t.Fatalf("expected Go-owned misconfigured deliveries to be claimed and failed, got %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, pendingID)
	if status != "DEAD_LETTER" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "missing HEC token") {
		t.Fatalf("Splunk misconfigured delivery state: status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError = siemDeliveryState(t, db, exhaustedID)
	if status != "DEAD_LETTER" || attempts != 5 || leaseOwner.Valid || deliveredAt.Valid {
		t.Fatalf("exhausted Go-owned delivery state: status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError = siemDeliveryState(t, db, cerebroID)
	if status != "DEAD_LETTER" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "Cerebro source runtime ID") {
		t.Fatalf("CEREBRO_CLAIMS misconfigured delivery state: status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	healthStatus, deliveriesOK, deliveriesFail, _, lastError := siemDestinationHealth(t, db, cerebroDestinationID)
	if healthStatus != "ERROR" || deliveriesOK != 0 || deliveriesFail != 1 || !lastError.Valid || !strings.Contains(lastError.String, "Cerebro source runtime ID") {
		t.Fatalf("Cerebro destination health: status=%s ok=%d fail=%d err=%v", healthStatus, deliveriesOK, deliveriesFail, lastError)
	}
	healthStatus, deliveriesOK, deliveriesFail, _, lastError = siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ERROR" || deliveriesOK != 0 || deliveriesFail != 1 || !lastError.Valid || !strings.Contains(lastError.String, "missing HEC token") {
		t.Fatalf("Splunk destination health: status=%s ok=%d fail=%d err=%v", healthStatus, deliveriesOK, deliveriesFail, lastError)
	}
}

func TestHTTPAdapterMisconfigurationDeadLettersWithoutHTTP(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	orgID := seedDispatcherOrg(t, db)
	payload := fixtureDeliveryPayload(t, orgID)

	type misconfigurationCase struct {
		name       string
		kind       string
		token      string
		index      string
		tamper     bool
		wantError  string
		deliveryID string
		destID     string
	}
	cases := []misconfigurationCase{
		{name: "splunk missing token", kind: "SPLUNK_HEC", wantError: "missing HEC token"},
		{name: "panther missing token", kind: "PANTHER", wantError: "missing Panther API token"},
		{name: "elastic missing index", kind: "ELASTIC", token: "fixture-elastic-token", wantError: "Elasticsearch index missing"},
		{name: "elastic missing token", kind: "ELASTIC", index: "aperio-http", wantError: "missing Elasticsearch API key"},
		{name: "datadog missing token", kind: "DATADOG", wantError: "missing DD-API-KEY"},
		{name: "webhook tampered token", kind: "GENERIC_WEBHOOK", token: "fixture-webhook-token", tamper: true, wantError: "SIEM token decrypt failed"},
	}
	for index := range cases {
		destID := seedDispatcherDestination(t, db, orgID, cases[index].kind, "ACTIVE", "")
		cases[index].destID = destID
		if cases[index].token != "" {
			if cases[index].tamper {
				dest := destination{ID: destID, OrganizationID: orgID}
				updateDispatcherDestinationEncryptedToken(t, db, orgID, destID, tamperEncryptedTagForDispatcherTest(t, encryptForDispatcherTest(t, cases[index].token, destinationTokenAAD(dest))))
			} else {
				updateDispatcherDestinationToken(t, db, orgID, destID, cases[index].token)
			}
		}
		if cases[index].index != "" {
			updateDispatcherDestinationIndex(t, db, orgID, destID, cases[index].index)
		}
		cases[index].deliveryID = seedDispatcherDelivery(t, db, struct {
			orgID         string
			destinationID string
			payload       Payload
			status        string
			attempts      int
			maxAttempts   int
			leaseOwner    *string
		}{orgID: orgID, destinationID: destID, payload: payload, status: "PENDING", attempts: 0, maxAttempts: 5})
	}

	transport := &captureTransport{}
	result, err := (&Dispatcher{
		db:                  db,
		leaseOwner:          "go-siem-test-http-misconfig",
		organizationID:      orgID,
		httpClient:          &http.Client{Transport: transport},
		endpointSafetyCheck: func(context.Context, string) error { return nil },
	}).Drain(context.Background(), len(cases))
	if err != nil {
		t.Fatalf("drain HTTP misconfigurations: %v", err)
	}
	if result.Processed != len(cases) || result.Delivered != 0 || result.Failed != len(cases) {
		t.Fatalf("unexpected misconfiguration drain result: %#v", result)
	}
	if transport.calls != 0 {
		t.Fatalf("misconfigured HTTP adapters must fail before network transport, got %d calls", transport.calls)
	}
	for _, testCase := range cases {
		status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, testCase.deliveryID)
		if status != "DEAD_LETTER" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, testCase.wantError) {
			t.Fatalf("%s delivery state = status=%s attempts=%d lease=%v delivered=%v error=%v", testCase.name, status, attempts, leaseOwner, deliveredAt, lastError)
		}
		healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, testCase.destID)
		if healthStatus != "ERROR" || deliveriesOK != 0 || deliveriesFail != 1 || lastDeliveryAt.Valid || !destinationError.Valid || !strings.Contains(destinationError.String, testCase.wantError) {
			t.Fatalf("%s destination health = status=%s ok=%d fail=%d delivered=%v error=%v", testCase.name, healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
		}
	}
}

func TestDrainRespectsStreamsTenantsAndExpiredLeases(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgA := seedDispatcherOrg(t, db)
	orgB := seedDispatcherOrg(t, db)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	claimedDestinationID := seedDispatcherDestination(t, db, orgA, "JSON_FILE", "ACTIVE", "claimed.jsonl")
	eventsOnlyDestinationID := seedDispatcherDestinationForStream(t, db, orgA, "JSON_FILE", "ACTIVE", "events.jsonl", "EVENTS")
	payloadMismatchDestinationID := seedDispatcherDestination(t, db, orgA, "JSON_FILE", "ACTIVE", "payload-mismatch.jsonl")
	currentLeaseDestinationID := seedDispatcherDestination(t, db, orgA, "JSON_FILE", "ACTIVE", "current-lease.jsonl")

	claimedID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgA, destinationID: claimedDestinationID, payload: fixtureDeliveryPayload(t, orgA), status: "PENDING", attempts: 0, maxAttempts: 5})
	staleOwner := "stale-dispatcher"
	expiredProcessingID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgA, destinationID: claimedDestinationID, payload: fixtureDeliveryPayload(t, orgA), status: "PROCESSING", attempts: 0, maxAttempts: 5, leaseOwner: &staleOwner})
	streamMismatchID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgA, destinationID: eventsOnlyDestinationID, payload: fixtureDeliveryPayload(t, orgA), status: "PENDING", attempts: 0, maxAttempts: 5})
	payloadForOtherOrg := fixtureDeliveryPayload(t, orgB)
	payloadMismatchID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgA, destinationID: payloadMismatchDestinationID, payload: payloadForOtherOrg, status: "PENDING", attempts: 0, maxAttempts: 5})
	crossTenantDestinationID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgB, destinationID: claimedDestinationID, payload: fixtureDeliveryPayload(t, orgB), status: "PENDING", attempts: 0, maxAttempts: 5})
	currentOwner := "current-dispatcher"
	currentLeaseID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgA, destinationID: currentLeaseDestinationID, payload: fixtureDeliveryPayload(t, orgA), status: "PROCESSING", attempts: 0, maxAttempts: 5, leaseOwner: &currentOwner})
	if _, err := db.ExecContext(context.Background(), `
		UPDATE siem_deliveries
		SET lease_expires_at = NOW() + INTERVAL '1 hour'
		WHERE id = $1
	`, currentLeaseID); err != nil {
		t.Fatalf("extend current lease: %v", err)
	}

	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgA}).Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 2 || result.Delivered != 2 || result.Failed != 0 {
		t.Fatalf("expected only due same-tenant subscribed deliveries to drain, got %#v", result)
	}
	for _, id := range []string{claimedID, expiredProcessingID} {
		status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, id)
		if status != "DELIVERED" || attempts != 1 || leaseOwner.Valid || !deliveredAt.Valid || lastError.Valid {
			t.Fatalf("claimed delivery %s state = status=%s attempts=%d lease=%v delivered=%v error=%v", id, status, attempts, leaseOwner, deliveredAt, lastError)
		}
	}
	for name, id := range map[string]string{
		"stream mismatch":             streamMismatchID,
		"payload tenant mismatch":     payloadMismatchID,
		"destination tenant mismatch": crossTenantDestinationID,
	} {
		status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, id)
		if status != "PENDING" || attempts != 0 || leaseOwner.Valid || deliveredAt.Valid || lastError.Valid {
			t.Fatalf("%s delivery changed: status=%s attempts=%d lease=%v delivered=%v error=%v", name, status, attempts, leaseOwner, deliveredAt, lastError)
		}
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, currentLeaseID)
	if status != "PROCESSING" || attempts != 0 || !leaseOwner.Valid || leaseOwner.String != currentOwner || deliveredAt.Valid || lastError.Valid {
		t.Fatalf("current lease delivery changed: status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	for name, id := range map[string]string{
		"events-only":      eventsOnlyDestinationID,
		"payload-mismatch": payloadMismatchDestinationID,
		"current-lease":    currentLeaseDestinationID,
	} {
		healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, id)
		if healthStatus != "ACTIVE" || deliveriesOK != 0 || deliveriesFail != 0 || lastDeliveryAt.Valid || destinationError.Valid {
			t.Fatalf("%s destination health changed: status=%s ok=%d fail=%d delivered=%v error=%v", name, healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
		}
	}

	raw, err := os.ReadFile(filepath.Join(exportRoot, "claimed.jsonl"))
	if err != nil {
		t.Fatalf("read claimed JSONL: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(string(raw)), "\n"); len(lines) != 2 {
		t.Fatalf("expected two delivered JSONL envelopes, got %d lines: %q", len(lines), string(raw))
	}
	if _, err := os.Stat(filepath.Join(exportRoot, "events.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("stream-mismatched destination should not be written, stat err=%v", err)
	}
}

func TestDrainDeadLettersInvalidPayloadAndDestinationlessDeliveries(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	destinationID := seedDispatcherDestination(t, db, orgID, "JSON_FILE", "ACTIVE", "invalid.jsonl")
	streamMismatchDestinationID := seedDispatcherDestinationForStream(t, db, orgID, "JSON_FILE", "ACTIVE", "stream-mismatch.jsonl", "EVENTS")
	validPayload := fixtureDeliveryPayload(t, orgID)
	destinationlessID := seedDispatcherDeliveryForStream(t, db, struct {
		orgID         string
		destinationID sql.NullString
		payload       Payload
		stream        string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: sql.NullString{}, payload: validPayload, stream: "FINDINGS", status: "PENDING", attempts: 0, maxAttempts: 5})

	invalidPayload := validPayload
	invalidPayload.Kind = "unknown"
	invalidPayloadID := seedDispatcherDeliveryForStream(t, db, struct {
		orgID         string
		destinationID sql.NullString
		payload       Payload
		stream        string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: sql.NullString{String: destinationID, Valid: true}, payload: invalidPayload, stream: "FINDINGS", status: "PENDING", attempts: 0, maxAttempts: 5})

	streamMismatchID := seedDispatcherDeliveryForStream(t, db, struct {
		orgID         string
		destinationID sql.NullString
		payload       Payload
		stream        string
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: sql.NullString{String: streamMismatchDestinationID, Valid: true}, payload: validPayload, stream: "EVENTS", status: "PENDING", attempts: 0, maxAttempts: 5})

	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgID}).Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 3 || result.Delivered != 0 || result.Failed != 3 {
		t.Fatalf("unexpected invalid drain result: %#v", result)
	}
	for id, wantError := range map[string]string{
		destinationlessID: "destination not configured",
		invalidPayloadID:  "invalid delivery kind",
		streamMismatchID:  "delivery stream does not match payload kind",
	} {
		status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, id)
		if status != "DEAD_LETTER" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, wantError) {
			t.Fatalf("invalid delivery %s state = status=%s attempts=%d lease=%v delivered=%v error=%v", id, status, attempts, leaseOwner, deliveredAt, lastError)
		}
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ACTIVE" || deliveriesOK != 0 || deliveriesFail != 0 || lastDeliveryAt.Valid || destinationError.Valid {
		t.Fatalf("invalid payload changed destination health: status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError = siemDestinationHealth(t, db, streamMismatchDestinationID)
	if healthStatus != "ACTIVE" || deliveriesOK != 0 || deliveriesFail != 0 || lastDeliveryAt.Valid || destinationError.Valid {
		t.Fatalf("stream mismatch changed destination health: status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}
	if _, err := os.Stat(filepath.Join(exportRoot, "stream-mismatch.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("stream mismatch delivery should fail before file write, stat err=%v", err)
	}
}

func TestProcessJSONFileDeliveryMarksDeliveredAndDestinationHealthy(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	outputPath := filepath.Join(exportRoot, "aperio-findings.jsonl")
	destinationID := seedDispatcherDestination(t, db, orgID, "JSON_FILE", "ACTIVE", "aperio-findings.jsonl")
	payload := fixtureDeliveryPayload(t, orgID)
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: payload, status: "PENDING", attempts: 0, maxAttempts: 5})

	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgID}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 1 || result.Failed != 0 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "DELIVERED" || attempts != 1 || leaseOwner.Valid || !deliveredAt.Valid || lastError.Valid {
		t.Fatalf("delivered state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}

	var healthStatus string
	var deliveriesOK, deliveriesFail int
	var lastDeliveryAt sql.NullTime
	var destinationError sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, deliveries_ok, deliveries_fail, last_delivery_at, last_error
		FROM siem_destinations
		WHERE id = $1
	`, destinationID).Scan(&healthStatus, &deliveriesOK, &deliveriesFail, &lastDeliveryAt, &destinationError); err != nil {
		t.Fatalf("query destination health: %v", err)
	}
	if healthStatus != "ACTIVE" || deliveriesOK != 1 || deliveriesFail != 0 || !lastDeliveryAt.Valid || destinationError.Valid {
		t.Fatalf("destination health = status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read JSON file delivery: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one JSONL envelope, got %d lines: %q", len(lines), string(raw))
	}
	var envelope Envelope
	if err := json.Unmarshal([]byte(lines[0]), &envelope); err != nil {
		t.Fatalf("decode JSONL envelope: %v", err)
	}
	if envelope.SchemaVersion != "aperio.finding.v1" || envelope.DestinationID != destinationID || envelope.OrganizationID != orgID {
		t.Fatalf("unexpected envelope routing/schema: %#v", envelope)
	}
	if envelope.Record["title"] != payload.Record["title"] {
		t.Fatalf("envelope record title = %v, want %v", envelope.Record["title"], payload.Record["title"])
	}
}

func TestProcessGenericWebhookDeliveryCapturesRequestAndMarksDelivered(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "GENERIC_WEBHOOK", "ACTIVE", "")
	payload := fixtureDeliveryPayload(t, orgID)
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: payload, status: "PENDING", attempts: 0, maxAttempts: 5})

	transport := &captureTransport{}
	var checkedEndpoint string
	dispatcher := &Dispatcher{
		db:             db,
		leaseOwner:     "go-siem-test",
		organizationID: orgID,
		httpClient:     &http.Client{Transport: transport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			checkedEndpoint = endpoint
			return nil
		},
	}
	result, err := dispatcher.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 1 || result.Failed != 0 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	if checkedEndpoint != "https://example.com/collector" {
		t.Fatalf("endpoint safety checked %q", checkedEndpoint)
	}
	if transport.calls != 1 || transport.method != http.MethodPost || transport.url != "https://example.com/collector" {
		t.Fatalf("captured request = calls=%d method=%s url=%s", transport.calls, transport.method, transport.url)
	}
	if transport.header.Get("content-type") != "application/json" {
		t.Fatalf("content-type = %q", transport.header.Get("content-type"))
	}
	if signature := transport.header.Get("x-aperio-signature"); signature != "" {
		t.Fatalf("unexpected webhook signature without configured token: %q", signature)
	}
	var envelope Envelope
	if err := json.Unmarshal(transport.body, &envelope); err != nil {
		t.Fatalf("decode webhook body: %v", err)
	}
	if envelope.SchemaVersion != "aperio.finding.v1" || envelope.DestinationID != destinationID || envelope.OrganizationID != orgID {
		t.Fatalf("unexpected webhook envelope routing/schema: %#v", envelope)
	}
	if envelope.Record["title"] != payload.Record["title"] {
		t.Fatalf("webhook record title = %v, want %v", envelope.Record["title"], payload.Record["title"])
	}

	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "DELIVERED" || attempts != 1 || leaseOwner.Valid || !deliveredAt.Valid || lastError.Valid {
		t.Fatalf("delivered state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ACTIVE" || deliveriesOK != 1 || deliveriesFail != 0 || !lastDeliveryAt.Valid || destinationError.Valid {
		t.Fatalf("webhook destination health = status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}
}

func TestProcessCerebroClaimsDeliveryCapturesRequestsAndPublishesAfterFinalization(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "CEREBRO_CLAIMS", "ACTIVE", "")
	updateDispatcherDestinationToken(t, db, orgID, destinationID, "fixture-cerebro-db-token")
	updateDispatcherDestinationIndex(t, db, orgID, destinationID, "runtime-db")
	payload := fixtureDeliveryPayload(t, orgID)
	payload.OccurredAt = "2026-06-05T20:00:00.000Z"
	payload.Record["findingId"] = "fnd_cerebro_db"
	payload.Record["dedupeKey"] = "dedupe_cerebro_db"
	payload.Record["sourceEventId"] = "evt_cerebro_db"
	payload.Record["provider"] = "GITHUB"
	payload.Record["integrationId"] = "int_cerebro_db"
	payload.Record["target"] = "writer/cerebro-db"
	deliveryID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: payload, status: "PENDING", attempts: 0, maxAttempts: 5})

	transport := &captureTransport{}
	checkedEndpoints := []string{}
	publisher := &recordingClaimFanoutPublisher{
		t:   t,
		db:  db,
		err: errors.New("local NATS unavailable"),
	}
	dispatcher := &Dispatcher{
		db:             db,
		leaseOwner:     "go-siem-test-cerebro",
		organizationID: orgID,
		httpClient:     &http.Client{Transport: transport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			checkedEndpoints = append(checkedEndpoints, endpoint)
			return nil
		},
		claimPublisher: publisher,
	}
	result, err := dispatcher.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 1 || result.Failed != 0 {
		t.Fatalf("unexpected Cerebro drain result: %#v", result)
	}
	if len(checkedEndpoints) != 2 || transport.calls != 2 || len(transport.requests) != 2 {
		t.Fatalf("expected runtime check and claim write, endpoints=%v calls=%d requests=%d", checkedEndpoints, transport.calls, len(transport.requests))
	}
	runtimeURL := "https://example.com/collector/source-runtimes/runtime-db"
	claimsURL := runtimeURL + "/claims"
	if transport.requests[0].method != http.MethodGet || transport.requests[0].url != runtimeURL {
		t.Fatalf("runtime request = %s %s", transport.requests[0].method, transport.requests[0].url)
	}
	if transport.requests[0].header.Get("authorization") != "Bearer fixture-cerebro-db-token" || transport.requests[0].header.Get("accept") != "application/json" {
		t.Fatalf("runtime headers = %#v", transport.requests[0].header)
	}
	if transport.requests[1].method != http.MethodPost || transport.requests[1].url != claimsURL {
		t.Fatalf("claim request = %s %s", transport.requests[1].method, transport.requests[1].url)
	}
	if transport.requests[1].header.Get("authorization") != "Bearer fixture-cerebro-db-token" || transport.requests[1].header.Get("content-type") != "application/json" {
		t.Fatalf("claim headers = %#v", transport.requests[1].header)
	}
	if strings.Contains(string(transport.requests[1].body), "fixture-cerebro-db-token") {
		t.Fatal("Cerebro claim write body leaked token")
	}
	var requestBody struct {
		RuntimeID string         `json:"runtime_id"`
		Claims    []cerebroClaim `json:"claims"`
	}
	if err := json.Unmarshal(transport.requests[1].body, &requestBody); err != nil {
		t.Fatalf("decode Cerebro claim request body: %v", err)
	}
	if requestBody.RuntimeID != "runtime-db" || len(requestBody.Claims) == 0 {
		t.Fatalf("claim request body = %#v", requestBody)
	}
	if requestBody.Claims[0].SourceEventID != "evt_cerebro_db" {
		t.Fatalf("claim source_event_id = %q", requestBody.Claims[0].SourceEventID)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError := siemDeliveryState(t, db, deliveryID)
	if status != "DELIVERED" || attempts != 1 || leaseOwner.Valid || !deliveredAt.Valid || lastError.Valid {
		t.Fatalf("Cerebro delivered state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ACTIVE" || deliveriesOK != 1 || deliveriesFail != 0 || !lastDeliveryAt.Valid || destinationError.Valid {
		t.Fatalf("Cerebro destination health = status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("expected one fanout publish attempt, got %d", len(publisher.events))
	}
	if publisher.deliveryStatuses[0] != "DELIVERED" || publisher.destinationHealth[0] != "ACTIVE" {
		t.Fatalf("fanout published before finalization/health update: delivery=%v destination=%v", publisher.deliveryStatuses, publisher.destinationHealth)
	}
	event := publisher.events[0]
	if event.Status != "delivered" || event.Error != "" || event.RuntimeID != "runtime-db" || event.FindingID != "fnd_cerebro_db" || event.DedupeKey != "dedupe_cerebro_db" {
		t.Fatalf("unexpected fanout event: %#v", event)
	}
	if len(event.Claims) != len(requestBody.Claims) || event.Claims[0].GetSourceEventId() != "evt_cerebro_db" {
		t.Fatalf("fanout claims = %#v", event.Claims)
	}
}

func TestGenericWebhookFailureRetriesDeadLettersAndMarksDestinationError(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	destinationID := seedDispatcherDestination(t, db, orgID, "GENERIC_WEBHOOK", "ACTIVE", "")

	firstID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 0, maxAttempts: 2})
	_, _, _, _, previousNextAttemptAt, _ := siemDeliveryState(t, db, firstID)
	timeoutTransport := &captureTransport{err: context.DeadlineExceeded}
	var timeoutEndpoint string
	result, err := (&Dispatcher{
		db:             db,
		leaseOwner:     "go-siem-test-timeout",
		organizationID: orgID,
		httpClient:     &http.Client{Transport: timeoutTransport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			timeoutEndpoint = endpoint
			return nil
		},
	}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("timeout drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
		t.Fatalf("unexpected timeout drain result: %#v", result)
	}
	if timeoutEndpoint != "https://example.com/collector" || timeoutTransport.calls != 1 {
		t.Fatalf("timeout request/safety = endpoint=%q calls=%d", timeoutEndpoint, timeoutTransport.calls)
	}
	status, attempts, leaseOwner, deliveredAt, nextAttemptAt, lastError := siemDeliveryState(t, db, firstID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "deadline exceeded") {
		t.Fatalf("timeout retry state = status=%s attempts=%d lease=%v delivered=%v next=%v error=%v", status, attempts, leaseOwner, deliveredAt, nextAttemptAt, lastError)
	}
	if !nextAttemptAt.After(previousNextAttemptAt) {
		t.Fatalf("timeout next_attempt_at = %v, want after previous %v", nextAttemptAt, previousNextAttemptAt)
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError := siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ERROR" || deliveriesOK != 0 || deliveriesFail != 1 || lastDeliveryAt.Valid || !destinationError.Valid || !strings.Contains(destinationError.String, "deadline exceeded") {
		t.Fatalf("timeout destination health = status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}

	secondID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 1, maxAttempts: 2})
	statusTransport := &captureTransport{status: http.StatusServiceUnavailable}
	result, err = (&Dispatcher{
		db:                  db,
		leaseOwner:          "go-siem-test-http-failure",
		organizationID:      orgID,
		httpClient:          &http.Client{Transport: statusTransport},
		endpointSafetyCheck: func(context.Context, string) error { return nil },
	}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("HTTP failure drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
		t.Fatalf("unexpected HTTP failure drain result: %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError = siemDeliveryState(t, db, secondID)
	if status != "DEAD_LETTER" || attempts != 2 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "503 Service Unavailable") {
		t.Fatalf("HTTP dead-letter state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}
	healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError = siemDestinationHealth(t, db, destinationID)
	if healthStatus != "ERROR" || deliveriesOK != 0 || deliveriesFail != 2 || lastDeliveryAt.Valid || !destinationError.Valid || !strings.Contains(destinationError.String, "503 Service Unavailable") {
		t.Fatalf("HTTP failure destination health = status=%s ok=%d fail=%d delivered=%v error=%v", healthStatus, deliveriesOK, deliveriesFail, lastDeliveryAt, destinationError)
	}
}

func TestJSONFileFailureRetriesDeadLettersAndMarksDestinationError(t *testing.T) {
	db := openDBBackedSIEMDispatcherDB(t)
	orgID := seedDispatcherOrg(t, db)
	t.Setenv("APERIO_SIEM_EXPORT_DIR", t.TempDir())
	destinationID := seedDispatcherDestination(t, db, orgID, "JSON_FILE", "ACTIVE", "../unsafe.jsonl")
	firstID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 0, maxAttempts: 2})

	_, _, _, _, previousNextAttemptAt, _ := siemDeliveryState(t, db, firstID)
	result, err := (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgID}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
		t.Fatalf("unexpected first drain result: %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, nextAttemptAt, lastError := siemDeliveryState(t, db, firstID)
	if status != "FAILED" || attempts != 1 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid || !strings.Contains(lastError.String, "invalid SIEM export path") {
		t.Fatalf("retry state = status=%s attempts=%d lease=%v delivered=%v next=%v error=%v", status, attempts, leaseOwner, deliveredAt, nextAttemptAt, lastError)
	}
	if nextAttemptAt.Equal(previousNextAttemptAt) {
		t.Fatalf("next_attempt_at was not rescheduled from %v", previousNextAttemptAt)
	}

	var healthStatus string
	var deliveriesFail int
	var destinationError sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, deliveries_fail, last_error
		FROM siem_destinations
		WHERE id = $1
	`, destinationID).Scan(&healthStatus, &deliveriesFail, &destinationError); err != nil {
		t.Fatalf("query destination failure health: %v", err)
	}
	if healthStatus != "ERROR" || deliveriesFail != 1 || !destinationError.Valid || !strings.Contains(destinationError.String, "invalid SIEM export path") {
		t.Fatalf("destination failure health = status=%s fail=%d error=%v", healthStatus, deliveriesFail, destinationError)
	}

	secondID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PENDING", attempts: 1, maxAttempts: 2})
	result, err = (&Dispatcher{db: db, leaseOwner: "go-siem-test", organizationID: orgID}).Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if result.Processed != 1 || result.Delivered != 0 || result.Failed != 1 {
		t.Fatalf("unexpected second drain result: %#v", result)
	}
	status, attempts, leaseOwner, deliveredAt, _, lastError = siemDeliveryState(t, db, secondID)
	if status != "DEAD_LETTER" || attempts != 2 || leaseOwner.Valid || deliveredAt.Valid || !lastError.Valid {
		t.Fatalf("dead-letter state = status=%s attempts=%d lease=%v delivered=%v error=%v", status, attempts, leaseOwner, deliveredAt, lastError)
	}

	otherOwner := "other-dispatcher"
	lostLeaseID := seedDispatcherDelivery(t, db, struct {
		orgID         string
		destinationID string
		payload       Payload
		status        string
		attempts      int
		maxAttempts   int
		leaseOwner    *string
	}{orgID: orgID, destinationID: destinationID, payload: fixtureDeliveryPayload(t, orgID), status: "PROCESSING", attempts: 0, maxAttempts: 2, leaseOwner: &otherOwner})
	err = (&Dispatcher{db: db, leaseOwner: "go-siem-test"}).finish(context.Background(), delivery{
		ID:             lostLeaseID,
		OrganizationID: orgID,
		DestinationID:  sql.NullString{String: destinationID, Valid: true},
		Attempts:       0,
		MaxAttempts:    2,
	}, false, false, "lost lease probe")
	if err == nil || !strings.Contains(err.Error(), "lease lost") {
		t.Fatalf("expected lost lease error, got %v", err)
	}
	status, attempts, leaseOwner, _, _, _ = siemDeliveryState(t, db, lostLeaseID)
	if status != "PROCESSING" || attempts != 0 || !leaseOwner.Valid || leaseOwner.String != otherOwner {
		t.Fatalf("lost lease delivery changed: status=%s attempts=%d lease=%v", status, attempts, leaseOwner)
	}
}
