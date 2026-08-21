package siemdispatcher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/aperio/internal/cerebroclaims"
	"github.com/writer/aperio/internal/cerebroclient"
	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/telemetry"
)

const (
	leaseDuration        = 5 * time.Minute
	networkTimeout       = 4 * time.Second
	encryptionAlgorithm  = runtimeutil.CredentialAlgorithm
	encryptionNonceBytes = runtimeutil.CredentialNonceBytes
	maxAttemptsMessage   = "max delivery attempts exhausted"
)

var errDeliveryLeaseLost = errors.New("siem delivery lease lost")

type permanentSendError struct {
	message string
}

func (e permanentSendError) Error() string {
	return e.message
}

type httpStatusError struct {
	statusCode int
	statusText string
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("%d %s", e.statusCode, e.statusText)
}

type Payload struct {
	Kind           string         `json:"kind"`
	OrganizationID string         `json:"organizationId"`
	OccurredAt     string         `json:"occurredAt"`
	Record         map[string]any `json:"record"`
}

type Envelope struct {
	SchemaVersion  string         `json:"schema_version"`
	Source         string         `json:"source"`
	Producer       string         `json:"producer"`
	DestinationID  string         `json:"destination_id"`
	OrganizationID string         `json:"organization_id"`
	Kind           string         `json:"kind"`
	OccurredAt     string         `json:"occurred_at"`
	Record         map[string]any `json:"record"`
}

type Result struct {
	Processed int
	Delivered int
	Failed    int
}

type Dispatcher struct {
	db                  *sql.DB
	leaseOwner          string
	organizationID      string
	httpClient          *http.Client
	endpointSafetyCheck func(context.Context, string) error
	claimPublisher      ClaimFanoutPublisher
}

type delivery struct {
	ID             string
	OrganizationID string
	DestinationID  sql.NullString
	Stream         string
	Payload        json.RawMessage
	Attempts       int
	MaxAttempts    int
}

type destination struct {
	ID             string
	OrganizationID string
	Kind           string
	Name           string
	EndpointURL    sql.NullString
	FilePath       sql.NullString
	Index          sql.NullString
	EncryptedToken sql.NullString
}

type cerebroEntityRef = cerebroclient.EntityRef
type cerebroClaim = cerebroclient.Claim

type sendResult struct {
	CerebroClaims    []cerebroClaim
	CerebroRuntimeID string
	FindingID        string
	DedupeKey        string
}

type encryptedEnvelope = runtimeutil.EncryptedEnvelope

type endpointResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func New(db *sql.DB) *Dispatcher {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	return &Dispatcher{
		db:             db,
		leaseOwner:     fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), randomID()),
		claimPublisher: NewEnvClaimFanoutPublisher(),
	}
}

// SetOrganizationScope scopes drain queries to one organization for bounded
// local validation runs and DB-backed tests.
func (d *Dispatcher) SetOrganizationScope(organizationID string) {
	d.organizationID = organizationID
}

// SetOrganizationForTesting preserves the existing DB-backed test helper name.
func (d *Dispatcher) SetOrganizationForTesting(organizationID string) {
	d.SetOrganizationScope(organizationID)
}

// SetHTTPClientForTesting installs a deterministic local transport for DB-backed
// surface tests so adapter drains can be proven without contacting real SIEMs.
func (d *Dispatcher) SetHTTPClientForTesting(client *http.Client) {
	d.httpClient = client
}

// SetEndpointSafetyCheckForTesting injects the local harness safety gate used by
// DB-backed surface tests while keeping production endpoint safety enabled by default.
func (d *Dispatcher) SetEndpointSafetyCheckForTesting(check func(context.Context, string) error) {
	d.endpointSafetyCheck = check
}

func StableDeliveryKey(payload Payload, destinationID string, stream string) string {
	record := payload.Record
	stableRecordID := firstString(record["findingId"], record["id"], record["dedupeKey"], record["sourceEventId"])
	if stableRecordID == "" {
		encoded, _ := json.Marshal(record)
		stableRecordID = string(encoded)
	}
	key := struct {
		OrganizationID    string `json:"organizationId"`
		DestinationID     string `json:"destinationId"`
		Stream            string `json:"stream"`
		Kind              string `json:"kind"`
		StableRecordID    string `json:"stableRecordId"`
		FindingOccurrence string `json:"findingOccurrence,omitempty"`
		FindingStatus     string `json:"findingStatus,omitempty"`
	}{
		OrganizationID: payload.OrganizationID,
		DestinationID:  destinationID,
		Stream:         stream,
		Kind:           payload.Kind,
		StableRecordID: stableRecordID,
	}
	if payload.Kind == "finding" {
		key.FindingOccurrence = firstString(record["sourceEventId"], record["detectedAt"], payload.OccurredAt)
		key.FindingStatus = firstString(record["status"])
	}
	encoded, _ := json.Marshal(key)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (d *Dispatcher) Drain(ctx context.Context, limit int) (Result, error) {
	if d.db == nil {
		return Result{}, errors.New("database is required")
	}
	limit = boundedLimit(limit)
	if err := d.retireExhausted(ctx); err != nil {
		return Result{}, err
	}
	deliveries, err := d.claim(ctx, limit)
	if err != nil {
		return Result{}, err
	}
	result := Result{Processed: len(deliveries)}
	for _, delivery := range deliveries {
		if err := d.process(ctx, delivery); err != nil {
			result.Failed++
		} else {
			result.Delivered++
		}
	}
	return result, nil
}

func (d *Dispatcher) retireExhausted(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'DEAD_LETTER',
		    lease_owner = NULL,
		    lease_expires_at = NULL,
		    last_error = $2,
		    updated_at = NOW()
		WHERE attempts >= max_attempts
		  AND ($1 = '' OR organization_id = $1)
		  AND status IN ('PENDING', 'FAILED', 'PROCESSING')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
		  AND (payload->>'organizationId' IS NULL OR payload->>'organizationId' = organization_id)
		  AND (
		    destination_id IS NULL OR EXISTS (
			SELECT 1
			FROM siem_destinations dst
			WHERE dst.id = siem_deliveries.destination_id
			  AND dst.organization_id = siem_deliveries.organization_id
			  AND dst.kind IN ('SPLUNK_HEC', 'PANTHER', 'PANOPTICON', 'ELASTIC', 'DATADOG', 'GENERIC_WEBHOOK', 'CEREBRO_CLAIMS', 'JSON_FILE')
			  AND siem_deliveries.stream = ANY(dst.streams)
		    )
		  )
		RETURNING id,
		          organization_id,
		          destination_id,
		          stream::text,
		          payload,
		          attempts,
		          max_attempts,
		          (
		            SELECT dst.kind::text
		            FROM siem_destinations dst
		            WHERE dst.id = siem_deliveries.destination_id
		              AND dst.organization_id = siem_deliveries.organization_id
		          )
	`, d.organizationID, maxAttemptsMessage)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item delivery
		var destinationKind sql.NullString
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.DestinationID, &item.Stream, &item.Payload, &item.Attempts, &item.MaxAttempts, &destinationKind); err != nil {
			return err
		}
		payload, _ := parsePayload(item.Payload)
		dest := destination{}
		if item.DestinationID.Valid {
			dest.ID = item.DestinationID.String
		}
		if destinationKind.Valid {
			dest.Kind = destinationKind.String
		}
		emitSIEMDeliveryWideEventForAttempt(item, payload, dest, errors.New(maxAttemptsMessage), false, 0, item.Attempts)
	}
	return rows.Err()
}

func (d *Dispatcher) claim(ctx context.Context, limit int) ([]delivery, error) {
	rows, err := d.db.QueryContext(ctx, `
		UPDATE siem_deliveries
		SET status = 'PROCESSING', lease_owner = $1, lease_expires_at = $2, updated_at = NOW()
		WHERE id IN (
			SELECT sd.id
			FROM siem_deliveries sd
			WHERE sd.attempts < sd.max_attempts
			  AND ($4 = '' OR sd.organization_id = $4)
			  AND sd.next_attempt_at <= NOW()
			  AND (sd.payload->>'organizationId' IS NULL OR sd.payload->>'organizationId' = sd.organization_id)
			  AND (
					sd.destination_id IS NULL OR EXISTS (
						SELECT 1
						FROM siem_destinations dst
						WHERE dst.id = sd.destination_id
						AND dst.organization_id = sd.organization_id
						AND dst.status IN ('ACTIVE', 'ERROR')
						AND dst.kind IN ('SPLUNK_HEC', 'PANTHER', 'PANOPTICON', 'ELASTIC', 'DATADOG', 'GENERIC_WEBHOOK', 'CEREBRO_CLAIMS', 'JSON_FILE')
						AND sd.stream = ANY(dst.streams)
					)
			  )
			  AND (
					(sd.status IN ('PENDING', 'FAILED') AND (sd.lease_expires_at IS NULL OR sd.lease_expires_at <= NOW()))
				 OR (sd.status = 'PROCESSING' AND sd.lease_expires_at <= NOW())
			  )
			ORDER BY sd.created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, destination_id, stream::text, payload, attempts, max_attempts
	`, d.leaseOwner, time.Now().UTC().Add(leaseDuration), limit, d.organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := []delivery{}
	for rows.Next() {
		var item delivery
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.DestinationID, &item.Stream, &item.Payload, &item.Attempts, &item.MaxAttempts); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, item)
	}
	return deliveries, rows.Err()
}

func (d *Dispatcher) process(ctx context.Context, item delivery) (processErr error) {
	startedAt := time.Now()
	payload := Payload{}
	dest := destination{}
	permanentFailure := false
	var telemetryErr error
	defer func() {
		errForTelemetry := processErr
		if telemetryErr != nil {
			errForTelemetry = telemetryErr
		}
		emitSIEMDeliveryWideEvent(item, payload, dest, errForTelemetry, permanentFailure, time.Since(startedAt))
	}()

	payload, err := parsePayload(item.Payload)
	if err != nil {
		permanentFailure = true
		processErr = d.failDelivery(ctx, item, true, err.Error())
		return processErr
	}
	if payload.OrganizationID != item.OrganizationID {
		permanentFailure = true
		processErr = d.failDelivery(ctx, item, true, "delivery payload organization mismatch")
		return processErr
	}
	expectedStream, err := StreamForKind(payload.Kind)
	if err != nil {
		permanentFailure = true
		processErr = d.failDelivery(ctx, item, true, err.Error())
		return processErr
	}
	if item.Stream != expectedStream {
		permanentFailure = true
		processErr = d.failDelivery(ctx, item, true, fmt.Sprintf("delivery stream does not match payload kind: %s requires %s", payload.Kind, expectedStream))
		return processErr
	}
	if !item.DestinationID.Valid {
		permanentFailure = true
		processErr = d.failDelivery(ctx, item, true, "destination not configured")
		return processErr
	}
	dest, err = d.loadDestination(ctx, item.OrganizationID, item.DestinationID.String, item.Stream)
	if err != nil {
		permanent, message := destinationLoadFailure(err)
		permanentFailure = permanent
		processErr = d.failDelivery(ctx, item, permanent, message)
		return processErr
	}
	sendOutcome, err := d.sendForKind(ctx, dest, payload)
	if err != nil {
		permanent := isPermanentSendFailure(err)
		permanentFailure = permanent
		message := safeSIEMFailureMessageForDestination(err.Error(), dest)
		if finishErr := d.finish(ctx, item, false, permanent, message); finishErr != nil {
			processErr = finishErr
			return processErr
		}
		d.publishCerebroFanout(ctx, item, dest, payload, sendOutcome, false, message)
		telemetryErr = err
		processErr = errors.New(message)
		return processErr
	}
	if err := d.finish(ctx, item, true, false, ""); err != nil {
		processErr = err
		return processErr
	}
	_, _ = d.db.ExecContext(ctx, `
		UPDATE siem_destinations
		SET last_delivery_at = NOW(), deliveries_ok = deliveries_ok + 1, last_error = NULL, status = 'ACTIVE', updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, dest.ID, dest.OrganizationID)
	d.publishCerebroFanout(ctx, item, dest, payload, sendOutcome, true, "")
	return nil
}

func (d *Dispatcher) fail(ctx context.Context, item delivery, permanent bool, message string) error {
	return d.failWithHealth(ctx, item, permanent, message, true)
}

func (d *Dispatcher) failDelivery(ctx context.Context, item delivery, permanent bool, message string) error {
	return d.failWithHealth(ctx, item, permanent, message, false)
}

func (d *Dispatcher) failWithHealth(ctx context.Context, item delivery, permanent bool, message string, updateDestinationHealth bool) error {
	safeMessage := safeSIEMFailureMessage(message)
	if err := d.finish(ctx, item, false, permanent, safeMessage, updateDestinationHealth); err != nil {
		return err
	}
	return errors.New(safeMessage)
}

func (d *Dispatcher) loadDestination(ctx context.Context, organizationID string, id string, stream string) (destination, error) {
	var dest destination
	err := d.db.QueryRowContext(ctx, `
		SELECT id, organization_id, kind::text, name, endpoint_url, file_path, index, encrypted_token
		FROM siem_destinations
		WHERE id = $1 AND organization_id = $2 AND status IN ('ACTIVE', 'ERROR') AND $3::"SiemStreamType" = ANY(streams)
	`, id, organizationID, stream).Scan(&dest.ID, &dest.OrganizationID, &dest.Kind, &dest.Name, &dest.EndpointURL, &dest.FilePath, &dest.Index, &dest.EncryptedToken)
	return dest, err
}

func destinationLoadFailure(err error) (bool, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return true, "destination not active"
	}
	return false, err.Error()
}

func permanentAdapterError(message string) error {
	return permanentSendError{message: message}
}

func isPermanentSendFailure(err error) bool {
	var permanent permanentSendError
	if errors.As(err, &permanent) {
		return true
	}
	var statusErr httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.statusCode >= http.StatusMultipleChoices && statusErr.statusCode < http.StatusInternalServerError
	}
	return false
}

func (d *Dispatcher) finish(ctx context.Context, item delivery, ok bool, permanent bool, message string, updateDestinationHealth ...bool) error {
	attempts := item.Attempts + 1
	if ok {
		res, err := d.db.ExecContext(ctx, `
			UPDATE siem_deliveries
			SET status = 'DELIVERED', attempts = $1, delivered_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $2 AND lease_owner = $3 AND organization_id = $4
		`, attempts, item.ID, d.leaseOwner, item.OrganizationID)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil && rows != 1 {
			return errDeliveryLeaseLost
		}
		return nil
	}
	status := "FAILED"
	if permanent || attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	safeMessage := safeSIEMFailureMessage(message)
	nextAttemptAt := time.Now().UTC().Add(nextRetryDelay(attempts))
	res, err := d.db.ExecContext(ctx, `
		UPDATE siem_deliveries
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6 AND organization_id = $7
	`, status, attempts, nextAttemptAt, safeMessage, item.ID, d.leaseOwner, item.OrganizationID)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		return errDeliveryLeaseLost
	}
	shouldUpdateDestinationHealth := true
	if len(updateDestinationHealth) > 0 {
		shouldUpdateDestinationHealth = updateDestinationHealth[0]
	}
	if shouldUpdateDestinationHealth && item.DestinationID.Valid {
		_, _ = d.db.ExecContext(ctx, `
			UPDATE siem_destinations
			SET deliveries_fail = deliveries_fail + 1, last_error = $1, status = 'ERROR', updated_at = NOW()
			WHERE id = $2 AND organization_id = $3
		`, safeMessage, item.DestinationID.String, item.OrganizationID)
	}
	return nil
}

func parsePayload(raw json.RawMessage) (Payload, error) {
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, err
	}
	if payload.Kind != "finding" && payload.Kind != "event" && payload.Kind != "audit_log" {
		return payload, errors.New("invalid delivery kind")
	}
	if strings.TrimSpace(payload.OrganizationID) == "" || strings.TrimSpace(payload.OccurredAt) == "" || payload.Record == nil {
		return payload, errors.New("invalid delivery payload")
	}
	return payload, nil
}

func BuildEnvelope(destID string, orgID string, payload Payload) Envelope {
	return Envelope{
		SchemaVersion:  schemaVersion(payload.Kind),
		Source:         "aperio",
		Producer:       "aperio.sspm",
		DestinationID:  destID,
		OrganizationID: orgID,
		Kind:           payload.Kind,
		OccurredAt:     payload.OccurredAt,
		Record:         payload.Record,
	}
}

func StreamForKind(kind string) (string, error) {
	switch kind {
	case "finding":
		return "FINDINGS", nil
	case "event":
		return "EVENTS", nil
	case "audit_log":
		return "AUDIT_LOGS", nil
	default:
		return "", errors.New("invalid delivery kind")
	}
}

func writeJSONFile(dest destination, payload Payload) error {
	if !dest.FilePath.Valid || strings.TrimSpace(dest.FilePath.String) == "" {
		return errors.New("file_path is not configured")
	}
	path, err := normalizeFilePath(dest.FilePath.String)
	if err != nil {
		return err
	}
	root, err := siemExportRoot()
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := rejectSymlinkPath(root, parent, true); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkPath(root, parent, true); err != nil {
		return err
	}
	if err := rejectSymlinkPath(root, path, true); err != nil {
		return err
	}
	encoded, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(encoded, '\n'))
	return err
}

func (d *Dispatcher) sendForKind(ctx context.Context, dest destination, payload Payload) (sendResult, error) {
	switch dest.Kind {
	case "SPLUNK_HEC":
		return sendResult{}, d.sendSplunk(ctx, dest, payload)
	case "PANTHER":
		return sendResult{}, d.sendPanther(ctx, dest, payload)
	case "PANOPTICON":
		return sendResult{}, d.sendPanopticon(ctx, dest, payload)
	case "ELASTIC":
		return sendResult{}, d.sendElastic(ctx, dest, payload)
	case "DATADOG":
		return sendResult{}, d.sendDatadog(ctx, dest, payload)
	case "GENERIC_WEBHOOK":
		return sendResult{}, d.sendGenericWebhook(ctx, dest, payload)
	case "CEREBRO_CLAIMS":
		return d.sendCerebroClaims(ctx, dest, payload)
	case "JSON_FILE":
		return sendResult{}, writeJSONFile(dest, payload)
	default:
		return sendResult{}, permanentAdapterError(fmt.Sprintf("unsupported Go SIEM destination kind %s", dest.Kind))
	}
}

func (d *Dispatcher) sendSplunk(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	token, err := requireDestinationToken(dest, "missing HEC token")
	if err != nil {
		return err
	}
	body := map[string]any{
		"event":      BuildEnvelope(dest.ID, dest.OrganizationID, payload),
		"sourcetype": "aperio:" + payload.Kind,
		"source":     "aperio",
	}
	if dest.Index.Valid && strings.TrimSpace(dest.Index.String) != "" {
		body["index"] = strings.TrimSpace(dest.Index.String)
	}
	if occurredAt, err := time.Parse(time.RFC3339Nano, payload.OccurredAt); err == nil {
		body["time"] = occurredAt.Unix()
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return d.postJSON(ctx, dest.EndpointURL.String, map[string]string{
		"authorization": "Splunk " + token,
	}, encoded)
}

func (d *Dispatcher) sendPanther(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	token, err := requireDestinationToken(dest, "missing Panther API token")
	if err != nil {
		return err
	}
	bodyBytes, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	return d.postJSON(ctx, dest.EndpointURL.String, map[string]string{
		"x-api-key": token,
	}, bodyBytes)
}

func (d *Dispatcher) sendPanopticon(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	headers := map[string]string{}
	token, err := optionalDestinationToken(dest)
	if err != nil {
		return err
	}
	if strings.TrimSpace(token) != "" {
		headers["authorization"] = "Bearer " + token
	}
	bodyBytes, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	return d.postJSON(ctx, dest.EndpointURL.String, headers, bodyBytes)
}

func (d *Dispatcher) sendElastic(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	if !dest.Index.Valid || strings.TrimSpace(dest.Index.String) == "" {
		return permanentAdapterError("Elasticsearch index missing")
	}
	token, err := requireDestinationToken(dest, "missing Elasticsearch API key")
	if err != nil {
		return err
	}
	body := strings.Join([]string{
		mustMarshalString(map[string]any{"index": map[string]any{"_index": strings.TrimSpace(dest.Index.String)}}),
		mustMarshalString(BuildEnvelope(dest.ID, dest.OrganizationID, payload)),
		"",
	}, "\n")
	return d.postWithContentType(ctx, dest.EndpointURL.String, "application/x-ndjson", map[string]string{
		"authorization": "ApiKey " + token,
	}, []byte(body))
}

func (d *Dispatcher) sendDatadog(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	token, err := requireDestinationToken(dest, "missing DD-API-KEY")
	if err != nil {
		return err
	}
	bodyBytes, err := json.Marshal([]map[string]any{{
		"ddsource": "aperio",
		"service":  "aperio-" + payload.Kind,
		"ddtags":   "org:" + dest.OrganizationID,
		"message":  BuildEnvelope(dest.ID, dest.OrganizationID, payload),
	}})
	if err != nil {
		return err
	}
	return d.postJSON(ctx, dest.EndpointURL.String, map[string]string{
		"DD-API-KEY": token,
	}, bodyBytes)
}

func (d *Dispatcher) sendGenericWebhook(ctx context.Context, dest destination, payload Payload) error {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return permanentAdapterError("endpoint not configured")
	}
	bodyBytes, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		return err
	}
	headers := map[string]string{}
	if dest.EncryptedToken.Valid && strings.TrimSpace(dest.EncryptedToken.String) != "" {
		token, err := decryptString(dest.EncryptedToken.String, destinationTokenAAD(dest))
		if err != nil {
			return permanentAdapterError("SIEM token decrypt failed")
		}
		signature := hmac.New(sha256.New, []byte(token))
		_, _ = signature.Write(bodyBytes)
		headers["x-aperio-signature"] = hex.EncodeToString(signature.Sum(nil))
	}
	return d.postJSON(ctx, dest.EndpointURL.String, headers, bodyBytes)
}

func (d *Dispatcher) sendCerebroClaims(ctx context.Context, dest destination, payload Payload) (sendResult, error) {
	if !dest.EndpointURL.Valid || strings.TrimSpace(dest.EndpointURL.String) == "" {
		return sendResult{}, permanentAdapterError("Cerebro API URL missing")
	}
	if !dest.Index.Valid || strings.TrimSpace(dest.Index.String) == "" {
		return sendResult{}, permanentAdapterError("Cerebro source runtime ID is not configured")
	}
	token, err := requireDestinationToken(dest, "missing Cerebro API token")
	if err != nil {
		return sendResult{}, err
	}
	runtimeID := strings.TrimSpace(dest.Index.String)
	runtimePath := "/source-runtimes/" + url.PathEscape(runtimeID)
	headers := map[string]string{"authorization": "Bearer " + token}
	if err := d.getJSON(ctx, joinEndpointPath(dest.EndpointURL.String, runtimePath), headers); err != nil {
		return sendResult{}, fmt.Errorf("Cerebro runtime check failed: %w", err)
	}
	claims, err := buildCerebroClaims(dest, payload)
	if err != nil {
		return sendResult{}, err
	}
	result := sendResult{
		CerebroClaims:    claims,
		CerebroRuntimeID: runtimeID,
		FindingID:        firstString(payload.Record["findingId"], payload.Record["id"]),
		DedupeKey:        firstString(payload.Record["dedupeKey"]),
	}
	bodyBytes, err := json.Marshal(map[string]any{
		"runtime_id": runtimeID,
		"claims":     claims,
	})
	if err != nil {
		return result, err
	}
	if err := d.postJSON(ctx, joinEndpointPath(dest.EndpointURL.String, runtimePath+"/claims"), headers, bodyBytes); err != nil {
		return result, err
	}
	return result, nil
}

func (d *Dispatcher) postJSON(ctx context.Context, endpoint string, headers map[string]string, body []byte) error {
	return d.postWithContentType(ctx, endpoint, "application/json", headers, body)
}

func (d *Dispatcher) postWithContentType(ctx context.Context, endpoint string, contentType string, headers map[string]string, body []byte) error {
	return d.doHTTPRequest(ctx, http.MethodPost, endpoint, contentType, headers, body)
}

func (d *Dispatcher) getJSON(ctx context.Context, endpoint string, headers map[string]string) error {
	requestHeaders := map[string]string{"accept": "application/json"}
	for key, value := range headers {
		requestHeaders[key] = value
	}
	return d.doHTTPRequest(ctx, http.MethodGet, endpoint, "", requestHeaders, nil)
}

func (d *Dispatcher) doHTTPRequest(ctx context.Context, method string, endpoint string, contentType string, headers map[string]string, body []byte) error {
	if err := d.checkEndpoint(ctx, endpoint); err != nil {
		return permanentAdapterError(err.Error())
	}
	requestCtx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := d.webhookHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		statusText := strings.TrimSpace(http.StatusText(res.StatusCode))
		if statusText == "" {
			statusText = "HTTP error"
		}
		return httpStatusError{statusCode: res.StatusCode, statusText: statusText}
	}
	return nil
}

func (d *Dispatcher) webhookHTTPClient() *http.Client {
	if d.httpClient != nil {
		client := *d.httpClient
		client.CheckRedirect = blockWebhookRedirect
		return &client
	}
	return &http.Client{
		Timeout:       networkTimeout,
		Transport:     safeWebhookTransport(),
		CheckRedirect: blockWebhookRedirect,
	}
}

func blockWebhookRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func buildCerebroClaims(dest destination, payload Payload) ([]cerebroClaim, error) {
	return cerebroclaims.Build(cerebroclaims.BuildInput{
		OrganizationID: dest.OrganizationID,
		RuntimeID:      strings.TrimSpace(dest.Index.String),
		Payload: cerebroclaims.Payload{
			Kind:       payload.Kind,
			OccurredAt: payload.OccurredAt,
			Record:     payload.Record,
		},
	})
}

func cerebroRef(organizationID, runtimeID, entityType, externalID, label string) cerebroEntityRef {
	return cerebroclaims.Ref(organizationID, runtimeID, entityType, externalID, label)
}

func safeWebhookTransport() http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	dialer := &net.Dialer{Timeout: networkTimeout, KeepAlive: 30 * time.Second}
	base.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		target, err := safeDialAddress(ctx, address, net.DefaultResolver)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, target)
	}
	return base
}

func safeDialAddress(ctx context.Context, address string, resolver endpointResolver) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("endpoint dial target is invalid")
	}
	host = normalizeHostname(host)
	if host == "" {
		return "", errors.New("endpoint URL hostname is required")
	}
	if isBlockedHostname(host) {
		return "", errors.New("endpoint URL must not target loopback, local, or private hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return "", errors.New("endpoint URL must not target loopback, local, or private hosts")
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	lookupCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		lookupCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
	}
	defer cancel()
	addresses, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return "", errors.New("endpoint URL hostname could not be resolved")
	}
	for _, address := range addresses {
		if isPrivateIP(address.IP) {
			return "", errors.New("endpoint URL must not resolve to loopback or private addresses")
		}
	}
	return net.JoinHostPort(addresses[0].IP.String(), port), nil
}

func (d *Dispatcher) checkEndpoint(ctx context.Context, endpoint string) error {
	if d.endpointSafetyCheck != nil {
		return d.endpointSafetyCheck(ctx, endpoint)
	}
	return assertSafeEndpointURL(ctx, endpoint)
}

func siemExportRoot() (string, error) {
	root := strings.TrimSpace(os.Getenv("APERIO_SIEM_EXPORT_DIR"))
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		root = filepath.Join(cwd, "var", "siem-exports")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return root, nil
}

func normalizeFilePath(raw string) (string, error) {
	root, err := siemExportRoot()
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid SIEM export path")
	}
	candidate := trimmed
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid SIEM export path: file path must stay within %s", root)
	}
	return candidate, nil
}

func rejectSymlinkPath(root string, target string, includeTarget bool) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid SIEM export path: export root symlinks are not allowed")
		}
		if !info.IsDir() {
			return errors.New("invalid SIEM export path: export root is not a directory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("invalid SIEM export path: file path must stay within %s", root)
	}
	if relative == "." {
		return nil
	}
	parts := strings.Split(relative, string(filepath.Separator))
	limit := len(parts)
	if !includeTarget {
		limit--
	}
	current := root
	for index := 0; index < limit; index++ {
		part := parts[index]
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid SIEM export path: symlink path components are not allowed")
		}
		if !info.IsDir() && index < limit-1 {
			return errors.New("invalid SIEM export path: path component is not a directory")
		}
	}
	return nil
}

func assertSafeEndpointURL(ctx context.Context, raw string) error {
	return assertSafeEndpointURLWithResolver(ctx, raw, net.DefaultResolver)
}

func assertSafeEndpointURLWithResolver(ctx context.Context, raw string, resolver endpointResolver) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("endpoint URL must be a valid absolute URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("endpoint URL must use HTTPS")
	}
	host := normalizeHostname(parsed.Hostname())
	if host == "" {
		return errors.New("endpoint URL hostname is required")
	}
	if isBlockedHostname(host) {
		return errors.New("endpoint URL must not target loopback, local, or private hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return errors.New("endpoint URL must not target loopback, local, or private hosts")
		}
		return nil
	}
	lookupCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		lookupCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
	}
	defer cancel()
	addresses, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("endpoint URL hostname could not be resolved")
	}
	for _, address := range addresses {
		if isPrivateIP(address.IP) {
			return errors.New("endpoint URL must not resolve to loopback or private addresses")
		}
	}
	return nil
}

func normalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func isBlockedHostname(host string) bool {
	if host == "localhost" || host == "0.0.0.0" {
		return true
	}
	if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return true
	}
	for _, suffix := range []string{".internal", ".local", ".localhost", ".localdomain", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		first, second, third := int(v4[0]), int(v4[1]), int(v4[2])
		return first == 0 ||
			first == 10 ||
			first == 127 ||
			(first == 100 && second >= 64 && second <= 127) ||
			(first == 169 && second == 254) ||
			(first == 172 && second >= 16 && second <= 31) ||
			(first == 192 && second == 0 && third == 0) ||
			(first == 192 && second == 0 && third == 2) ||
			(first == 192 && second == 168) ||
			(first == 198 && (second == 18 || second == 19)) ||
			(first == 198 && second == 51 && third == 100) ||
			(first == 203 && second == 0 && third == 113) ||
			first >= 224
	}
	lower := strings.ToLower(ip.String())
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		strings.HasPrefix(lower, "2001:db8")
}

func destinationTokenAAD(dest destination) string {
	return runtimeutil.SIEMDestinationTokenAAD(dest.OrganizationID, dest.ID)
}

func optionalDestinationToken(dest destination) (string, error) {
	if !dest.EncryptedToken.Valid || strings.TrimSpace(dest.EncryptedToken.String) == "" {
		return "", nil
	}
	token, err := decryptString(dest.EncryptedToken.String, destinationTokenAAD(dest))
	if err != nil {
		return "", permanentAdapterError("SIEM token decrypt failed")
	}
	return token, nil
}

func requireDestinationToken(dest destination, missingMessage string) (string, error) {
	token, err := optionalDestinationToken(dest)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(token) == "" {
		return "", permanentAdapterError(missingMessage)
	}
	return token, nil
}

func decryptString(encrypted string, additionalAuthenticatedData string) (string, error) {
	return runtimeutil.DecryptString(encrypted, additionalAuthenticatedData)
}

func resolveEncryptionKey() ([]byte, error) {
	return runtimeutil.ResolveEncryptionKeyFromEnv()
}

func boundedLimit(limit int) int {
	if limit < 1 {
		return 25
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func emitSIEMDeliveryWideEvent(item delivery, payload Payload, dest destination, processErr error, permanent bool, duration time.Duration) {
	telemetry.EmitWide(siemDeliveryWideEvent(item, payload, dest, processErr, permanent, duration))
	telemetry.IncCounter("aperio_siem_deliveries_total", map[string]string{
		"stream":  item.Stream,
		"outcome": siemDeliveryMetricOutcome(item, processErr, permanent),
	})
}

func emitSIEMDeliveryWideEventForAttempt(item delivery, payload Payload, dest destination, processErr error, permanent bool, duration time.Duration, attempt int) {
	telemetry.EmitWide(siemDeliveryWideEventForAttempt(item, payload, dest, processErr, permanent, duration, attempt))
	telemetry.IncCounter("aperio_siem_deliveries_total", map[string]string{
		"stream":  item.Stream,
		"outcome": siemDeliveryMetricOutcome(item, processErr, permanent),
	})
}

func siemDeliveryWideEvent(item delivery, payload Payload, dest destination, processErr error, permanent bool, duration time.Duration) telemetry.WideEvent {
	return siemDeliveryWideEventForAttempt(item, payload, dest, processErr, permanent, duration, item.Attempts+1)
}

func siemDeliveryWideEventForAttempt(item delivery, payload Payload, dest destination, processErr error, permanent bool, duration time.Duration, attempt int) telemetry.WideEvent {
	destinationID := dest.ID
	if destinationID == "" && item.DestinationID.Valid {
		destinationID = item.DestinationID.String
	}
	dimensions := map[string]string{
		"outcome":        siemDeliveryOutcome(item, processErr, permanent),
		"stream":         item.Stream,
		"payload_kind":   payload.Kind,
		"destination_id": destinationID,
	}
	if dest.Kind != "" {
		dimensions["destination_kind"] = dest.Kind
	}
	if processErr != nil {
		dimensions["error_kind"] = siemDeliveryErrorKind(processErr, permanent)
		if permanence := siemDeliveryPermanence(item, processErr, permanent); permanence != "" {
			dimensions["permanence"] = permanence
		}
	}
	if attempt < 0 {
		attempt = 0
	}
	return telemetry.WideEvent{
		Name:         "siem.delivery.process",
		Service:      "siem-dispatcher",
		Organization: item.OrganizationID,
		Dimensions:   dimensions,
		Measurements: map[string]int64{
			"attempt":      int64(attempt),
			"max_attempts": int64(item.MaxAttempts),
			"duration_ms":  duration.Milliseconds(),
		},
	}
}

func siemDeliveryOutcome(item delivery, processErr error, permanent bool) string {
	if processErr == nil {
		return "delivered"
	}
	if errors.Is(processErr, errDeliveryLeaseLost) {
		return "lost_lease"
	}
	if isTimeoutError(processErr) && item.Attempts+1 < item.MaxAttempts {
		return "timeout"
	}
	if permanent || item.Attempts+1 >= item.MaxAttempts {
		return "dead_letter"
	}
	return "retryable_failed"
}

func siemDeliveryMetricOutcome(item delivery, processErr error, permanent bool) string {
	switch siemDeliveryOutcome(item, processErr, permanent) {
	case "delivered":
		return "delivered"
	case "dead_letter":
		return "dead_letter"
	default:
		return "failed"
	}
}

func siemDeliveryPermanence(item delivery, processErr error, permanent bool) string {
	if processErr == nil || errors.Is(processErr, errDeliveryLeaseLost) {
		return ""
	}
	if permanent {
		return "permanent"
	}
	if item.Attempts+1 >= item.MaxAttempts {
		return "exhausted"
	}
	return "retryable"
}

func siemDeliveryErrorKind(processErr error, permanent bool) string {
	if processErr == nil {
		return ""
	}
	if errors.Is(processErr, errDeliveryLeaseLost) {
		return "lease_lost"
	}
	if isTimeoutError(processErr) {
		return "timeout"
	}
	var statusErr httpStatusError
	if errors.As(processErr, &statusErr) {
		if statusErr.statusCode >= http.StatusInternalServerError {
			return "http_5xx"
		}
		return "http_4xx"
	}
	message := strings.ToLower(processErr.Error())
	switch {
	case strings.Contains(message, "max delivery attempts"):
		return "max_attempts"
	case strings.Contains(message, "invalid delivery"):
		return "invalid_payload"
	case strings.Contains(message, "payload organization mismatch"):
		return "tenant_mismatch"
	case strings.Contains(message, "destination"):
		return "destination"
	case strings.Contains(message, "decrypt") || strings.Contains(message, "not configured") || permanent:
		return "permanent"
	default:
		return "error"
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func safeSIEMFailureMessage(message string) string {
	return truncate(runtimeutil.RedactText(message, siemRedactionSecretsFromEnv()...), 500)
}

func safeSIEMFailureMessageForDestination(message string, dest destination) string {
	sanitized := message
	if dest.EndpointURL.Valid {
		endpoint := strings.TrimSpace(dest.EndpointURL.String)
		if endpoint != "" {
			redactedEndpoint := runtimeutil.RedactDSN(endpoint)
			if redactedEndpoint != "" && redactedEndpoint != endpoint {
				sanitized = strings.ReplaceAll(sanitized, endpoint, redactedEndpoint)
			}
		}
	}
	secrets := append(siemRedactionSecretsFromEnv(), siemRedactionSecretsFromDestination(dest)...)
	return truncate(runtimeutil.RedactText(sanitized, secrets...), 500)
}

func siemRedactionSecretsFromEnv() []string {
	envNames := []string{
		"APERIO_ENCRYPTION_KEY",
		"DATABASE_URL",
		"APERIO_TEST_DATABASE_URL",
		"APERIO_NATS_URL",
		"APERIO_AUTH_SECRET",
	}
	secrets := []string{}
	for _, name := range envNames {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		secrets = append(secrets, raw)
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if parsed.User != nil {
			if password, ok := parsed.User.Password(); ok {
				secrets = append(secrets, password)
			}
		}
		query := parsed.Query()
		for key, values := range query {
			if !siemSensitiveKey(key) {
				continue
			}
			secrets = append(secrets, values...)
		}
	}
	return secrets
}

func siemRedactionSecretsFromDestination(dest destination) []string {
	secrets := []string{}
	if dest.EndpointURL.Valid {
		raw := strings.TrimSpace(dest.EndpointURL.String)
		if parsed, err := url.Parse(raw); err == nil {
			if parsed.User != nil {
				if userInfo := parsed.User.String(); userInfo != "" {
					secrets = append(secrets, userInfo)
				}
				if username := parsed.User.Username(); username != "" {
					secrets = append(secrets, username)
				}
				if password, ok := parsed.User.Password(); ok {
					secrets = append(secrets, password)
				}
			}
			query := parsed.Query()
			for key, values := range query {
				if !siemSensitiveKey(key) {
					continue
				}
				for _, value := range values {
					if strings.TrimSpace(value) != "" {
						secrets = append(secrets, value, key+"="+value)
					}
				}
			}
		}
	}
	if token, err := optionalDestinationToken(dest); err == nil && strings.TrimSpace(token) != "" {
		secrets = append(secrets, token)
	}
	return secrets
}

func siemSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "api-key") ||
		normalized == "key" ||
		strings.Contains(normalized, "credential")
}

func schemaVersion(kind string) string {
	switch kind {
	case "finding":
		return "aperio.finding.v1"
	case "event":
		return "aperio.event.v1"
	default:
		return "aperio.audit_log.v1"
	}
}

func firstString(values ...any) string {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case float64:
			return fmt.Sprintf("%v", typed)
		case bool:
			return fmt.Sprintf("%t", typed)
		}
	}
	return ""
}

func mustMarshalString(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func joinEndpointPath(baseURL string, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func nextRetryDelay(attempt int) time.Duration {
	delay := 30 * time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return delay
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func randomID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
