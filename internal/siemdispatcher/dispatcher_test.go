package siemdispatcher

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/aperio/internal/telemetry"
)

type siemParityFixture struct {
	DestinationID       string          `json:"destinationId"`
	Stream              string          `json:"stream"`
	Payload             Payload         `json:"payload"`
	ExpectedDeliveryKey string          `json:"expectedDeliveryKey"`
	ReopenedSourceEvent string          `json:"reopenedSourceEventId"`
	ReopenedOccurredAt  string          `json:"reopenedOccurredAt"`
	RawPayload          json.RawMessage `json:"-"`
}

type siemDedupeCasesFixture struct {
	Cases []struct {
		Name                string  `json:"name"`
		DestinationID       string  `json:"destinationId"`
		Stream              string  `json:"stream"`
		Payload             Payload `json:"payload"`
		ExpectedDeliveryKey string  `json:"expectedDeliveryKey"`
	} `json:"cases"`
}

type siemEnvelopeCasesFixture struct {
	Cases []struct {
		Name             string          `json:"name"`
		ExpectedStream   string          `json:"expectedStream"`
		DestinationID    string          `json:"destinationId"`
		OrganizationID   string          `json:"organizationId"`
		Payload          Payload         `json:"payload"`
		ExpectedEnvelope json.RawMessage `json:"expectedEnvelope"`
	} `json:"cases"`
}

type siemLocalAdapterHarnessFixture struct {
	DesignNote              string   `json:"designNote"`
	NoProductionDestination []string `json:"noProductionDestinations"`
	Adapters                []struct {
		Kind       string `json:"kind"`
		Harness    string `json:"harness"`
		Endpoint   string `json:"endpointUrl"`
		FilePath   string `json:"filePath"`
		SafetyNote string `json:"expectedSafety"`
	} `json:"adapters"`
}

type genericWebhookFixture struct {
	Destination struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
		EndpointURL    string `json:"endpointUrl"`
		Token          string `json:"token"`
	} `json:"destination"`
	Payload         Payload `json:"payload"`
	ExpectedRequest struct {
		Method          string          `json:"method"`
		URL             string          `json:"url"`
		ContentType     string          `json:"contentType"`
		SignatureHeader string          `json:"signatureHeader"`
		Signature       string          `json:"signature"`
		Body            json.RawMessage `json:"body"`
	} `json:"expectedRequest"`
}

type siemHTTPAdapterRequestsFixture struct {
	Description string  `json:"description"`
	Payload     Payload `json:"payload"`
	Cases       []struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Destination struct {
			ID             string `json:"id"`
			OrganizationID string `json:"organizationId"`
			EndpointURL    string `json:"endpointUrl"`
			Token          string `json:"token"`
			Index          string `json:"index"`
		} `json:"destination"`
		ExpectedRequest struct {
			Method        string            `json:"method"`
			URL           string            `json:"url"`
			ContentType   string            `json:"contentType"`
			Headers       map[string]string `json:"headers"`
			AbsentHeaders []string          `json:"absentHeaders"`
			Body          json.RawMessage   `json:"body"`
			RawBody       string            `json:"rawBody"`
		} `json:"expectedRequest"`
	} `json:"cases"`
	NegativeCases []struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"negativeCases"`
}

type siemCerebroClaimsFixture struct {
	Description string `json:"description"`
	Destination struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
		EndpointURL    string `json:"endpointUrl"`
		Token          string `json:"token"`
		Index          string `json:"index"`
	} `json:"destination"`
	Payload  Payload `json:"payload"`
	Expected struct {
		RuntimeRequest struct {
			Method        string            `json:"method"`
			URL           string            `json:"url"`
			Headers       map[string]string `json:"headers"`
			AbsentHeaders []string          `json:"absentHeaders"`
		} `json:"runtimeRequest"`
		ClaimRequest struct {
			Method        string            `json:"method"`
			URL           string            `json:"url"`
			Headers       map[string]string `json:"headers"`
			AbsentHeaders []string          `json:"absentHeaders"`
			Body          struct {
				RuntimeID string `json:"runtime_id"`
			} `json:"body"`
		} `json:"claimRequest"`
		ClaimCount  int    `json:"claimCount"`
		SourceEvent string `json:"sourceEventId"`
		FindingID   string `json:"findingId"`
		DedupeKey   string `json:"dedupeKey"`
		FindingURN  string `json:"findingURN"`
	} `json:"expected"`
}

type siemJSONFileSinkFixture struct {
	Description string `json:"description"`
	Destination struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
		FilePath       string `json:"filePath"`
	} `json:"destination"`
	Payloads        []Payload       `json:"payloads"`
	PreexistingLine json.RawMessage `json:"preexistingLine"`
	UnsafePaths     []string        `json:"unsafePaths"`
}

type capturedHTTPCall struct {
	method string
	url    string
	header http.Header
	body   []byte
}

type captureTransport struct {
	calls    int
	method   string
	url      string
	header   http.Header
	body     []byte
	requests []capturedHTTPCall
	status   int
	location string
	err      error
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	c.method = req.Method
	c.url = req.URL.String()
	c.header = req.Header.Clone()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	c.body = body
	c.requests = append(c.requests, capturedHTTPCall{
		method: c.method,
		url:    c.url,
		header: c.header.Clone(),
		body:   append([]byte(nil), body...),
	})
	if c.err != nil {
		return nil, c.err
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	header := make(http.Header)
	if c.location != "" {
		header.Set("location", c.location)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

type staticResolver struct {
	addresses []net.IPAddr
	err       error
}

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, r.err
}

func assertJSONEqual(t *testing.T, name string, got []byte, want []byte) {
	t.Helper()
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("%s decode actual JSON: %v", name, err)
	}
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("%s decode expected JSON: %v", name, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("%s JSON = %s, want %s", name, string(got), string(want))
	}
}

func bytesTrimTrailingNewline(raw []byte) []byte {
	return []byte(strings.TrimSuffix(string(raw), "\n"))
}

func hasCerebroClaim(claims []cerebroClaim, claimType string, predicate string, objectValue string) bool {
	for _, claim := range claims {
		if claim.ClaimType != claimType || claim.Predicate != predicate {
			continue
		}
		if objectValue == "" || claim.ObjectValue == objectValue {
			return true
		}
	}
	return false
}

func mustMarshalEnvelope(t *testing.T, dest destination, payload Payload) []byte {
	t.Helper()
	encoded, err := json.Marshal(BuildEnvelope(dest.ID, dest.OrganizationID, payload))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func readJSONFixture[T any](t *testing.T, filename string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", filename))
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	var fixture T
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode %s: %v", filename, err)
	}
	return fixture
}

func readSiemParityFixture(t *testing.T) siemParityFixture {
	t.Helper()
	fixture := readJSONFixture[siemParityFixture](t, "siem-finding-delivery.json")
	fixture.RawPayload, _ = json.Marshal(fixture)
	return fixture
}

func TestStableDeliveryKeyIncludesFindingOccurrence(t *testing.T) {
	fixture := readSiemParityFixture(t)
	payload := fixture.Payload
	first := StableDeliveryKey(payload, fixture.DestinationID, fixture.Stream)
	reopenedPayload := payload
	reopenedPayload.OccurredAt = fixture.ReopenedOccurredAt
	reopenedPayload.Record = map[string]any{}
	for key, value := range payload.Record {
		reopenedPayload.Record[key] = value
	}
	reopenedPayload.Record["sourceEventId"] = fixture.ReopenedSourceEvent
	reopened := StableDeliveryKey(reopenedPayload, fixture.DestinationID, fixture.Stream)
	if first != fixture.ExpectedDeliveryKey {
		t.Fatalf("delivery key = %s, want shared golden %s", first, fixture.ExpectedDeliveryKey)
	}
	if first == reopened {
		t.Fatal("expected reopened finding occurrence to produce a distinct key")
	}
	if first != StableDeliveryKey(payload, fixture.DestinationID, fixture.Stream) {
		t.Fatal("expected stable delivery key to be deterministic")
	}
}

func TestStableDeliveryKeySharedCases(t *testing.T) {
	fixture := readJSONFixture[siemDedupeCasesFixture](t, "siem-dedupe-cases.json")
	seen := map[string]struct{}{}
	for _, testCase := range fixture.Cases {
		got := StableDeliveryKey(testCase.Payload, testCase.DestinationID, testCase.Stream)
		if got != testCase.ExpectedDeliveryKey {
			t.Fatalf("%s delivery key = %s, want %s", testCase.Name, got, testCase.ExpectedDeliveryKey)
		}
		if _, ok := seen[got]; ok {
			t.Fatalf("%s produced duplicate delivery key %s", testCase.Name, got)
		}
		seen[got] = struct{}{}
	}
}

func TestBuildEnvelopeUsesCanonicalSIEMShape(t *testing.T) {
	payload := Payload{
		Kind:           "event",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "evt_1"},
	}
	envelope := BuildEnvelope("dst_1", "org_1", payload)
	if envelope.SchemaVersion != "aperio.event.v1" {
		t.Fatalf("schema version = %s", envelope.SchemaVersion)
	}
	if envelope.Source != "aperio" || envelope.Producer != "aperio.sspm" {
		t.Fatalf("unexpected source/producer: %#v", envelope)
	}
	if envelope.DestinationID != "dst_1" || envelope.OrganizationID != "org_1" {
		t.Fatalf("unexpected routing fields: %#v", envelope)
	}
}

func TestBuildEnvelopeSharedCases(t *testing.T) {
	fixture := readJSONFixture[siemEnvelopeCasesFixture](t, "siem-envelope-cases.json")
	for _, testCase := range fixture.Cases {
		envelope := BuildEnvelope(testCase.DestinationID, testCase.OrganizationID, testCase.Payload)
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("%s marshal envelope: %v", testCase.Name, err)
		}
		assertJSONEqual(t, testCase.Name, encoded, testCase.ExpectedEnvelope)
	}
}

func TestStreamForKindSharedCases(t *testing.T) {
	fixture := readJSONFixture[siemEnvelopeCasesFixture](t, "siem-envelope-cases.json")
	for _, testCase := range fixture.Cases {
		stream, err := StreamForKind(testCase.Payload.Kind)
		if err != nil {
			t.Fatalf("%s stream mapping: %v", testCase.Name, err)
		}
		if stream != testCase.ExpectedStream {
			t.Fatalf("%s stream = %s, want %s", testCase.Name, stream, testCase.ExpectedStream)
		}
	}
	if _, err := StreamForKind("unknown"); err == nil {
		t.Fatal("expected unknown payload kind to fail closed")
	}
}

func TestGoOwnedAdaptersUseLocalHarnessWithoutProductionEndpoints(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[siemLocalAdapterHarnessFixture](t, "siem-local-adapter-harness.json")
	if fixture.DesignNote == "" {
		t.Fatal("local adapter harness fixture must document the endpoint-safety-compatible pattern")
	}
	payload := Payload{
		Kind:           "finding",
		OrganizationID: "org_harness",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record: map[string]any{
			"findingId":     "fnd_harness",
			"dedupeKey":     "dedupe_harness",
			"sourceEventId": "evt_harness",
			"provider":      "GITHUB",
			"title":         "Harness finding",
			"severity":      "HIGH",
			"status":        "OPEN",
		},
	}

	seen := map[string]bool{}
	for _, adapter := range fixture.Adapters {
		adapter := adapter
		t.Run(adapter.Kind, func(t *testing.T) {
			seen[adapter.Kind] = true
			for _, productionHost := range fixture.NoProductionDestination {
				if adapter.Endpoint != "" && strings.Contains(strings.ToLower(adapter.Endpoint), strings.ToLower(productionHost)) {
					t.Fatalf("%s harness endpoint uses production host %s", adapter.Kind, productionHost)
				}
			}
			dest := destination{
				ID:             "dst_" + strings.ToLower(adapter.Kind),
				OrganizationID: payload.OrganizationID,
				Kind:           adapter.Kind,
				Name:           adapter.Kind + " harness",
				EndpointURL:    sql.NullString{String: adapter.Endpoint, Valid: adapter.Endpoint != ""},
				FilePath:       sql.NullString{String: adapter.FilePath, Valid: adapter.FilePath != ""},
				Index:          sql.NullString{String: "runtime-harness", Valid: true},
			}
			if adapter.Kind == "ELASTIC" {
				dest.Index = sql.NullString{String: "aperio-harness", Valid: true}
			}
			if adapter.Kind != "JSON_FILE" {
				dest.EncryptedToken = sql.NullString{
					String: encryptForDispatcherTest(t, "token-"+strings.ToLower(adapter.Kind), destinationTokenAAD(dest)),
					Valid:  true,
				}
			}

			if adapter.Kind == "JSON_FILE" {
				exportRoot := t.TempDir()
				t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
				if err := writeJSONFile(dest, payload); err != nil {
					t.Fatalf("write JSON file through local harness: %v", err)
				}
				raw, err := os.ReadFile(filepath.Join(exportRoot, adapter.FilePath))
				if err != nil {
					t.Fatalf("read harness JSONL: %v", err)
				}
				assertJSONEqual(t, "json file harness body", bytesTrimTrailingNewline(raw), mustMarshalEnvelope(t, dest, payload))
				return
			}

			transport := &captureTransport{}
			checkedEndpoints := []string{}
			dispatcher := &Dispatcher{
				httpClient: &http.Client{Transport: transport},
				endpointSafetyCheck: func(_ context.Context, endpoint string) error {
					if !strings.HasPrefix(endpoint, "https://capture.aperio.test/") {
						return fmt.Errorf("unexpected non-local harness endpoint %s", endpoint)
					}
					checkedEndpoints = append(checkedEndpoints, endpoint)
					return nil
				},
			}
			if _, err := dispatcher.sendForKind(context.Background(), dest, payload); err != nil {
				t.Fatalf("send %s through local harness: %v", adapter.Kind, err)
			}
			if len(checkedEndpoints) == 0 {
				t.Fatal("expected endpoint-safety check before local capture")
			}
			if transport.calls == 0 {
				t.Fatal("expected local capture transport to receive request")
			}
			for _, call := range transport.requests {
				if !strings.HasPrefix(call.url, "https://capture.aperio.test/") {
					t.Fatalf("captured non-local URL %s", call.url)
				}
				for _, productionHost := range fixture.NoProductionDestination {
					if strings.Contains(strings.ToLower(call.url), strings.ToLower(productionHost)) {
						t.Fatalf("captured production host %s in %s", productionHost, call.url)
					}
				}
				if strings.Contains(string(call.body), "token-"+strings.ToLower(adapter.Kind)) {
					t.Fatalf("%s request body leaked plaintext token", adapter.Kind)
				}
			}
		})
	}
	for _, kind := range []string{"SPLUNK_HEC", "PANTHER", "PANOPTICON", "ELASTIC", "DATADOG", "GENERIC_WEBHOOK", "CEREBRO_CLAIMS", "JSON_FILE"} {
		if !seen[kind] {
			t.Fatalf("local adapter harness missing %s", kind)
		}
	}
}

func TestHTTPAdapterRequestContractsMatchLocalCaptureFixtures(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[siemHTTPAdapterRequestsFixture](t, "siem-http-adapter-requests.json")
	if fixture.Description == "" {
		t.Fatal("HTTP adapter request fixture must document local-only capture constraints")
	}
	for _, testCase := range fixture.Cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			dest := destination{
				ID:             testCase.Destination.ID,
				OrganizationID: testCase.Destination.OrganizationID,
				Kind:           testCase.Kind,
				Name:           testCase.Name,
				EndpointURL:    sql.NullString{String: testCase.Destination.EndpointURL, Valid: testCase.Destination.EndpointURL != ""},
				Index:          sql.NullString{String: testCase.Destination.Index, Valid: testCase.Destination.Index != ""},
			}
			if testCase.Destination.Token != "" {
				dest.EncryptedToken = sql.NullString{
					String: encryptForDispatcherTest(t, testCase.Destination.Token, destinationTokenAAD(dest)),
					Valid:  true,
				}
			}
			transport := &captureTransport{}
			checkedEndpoints := []string{}
			dispatcher := &Dispatcher{
				httpClient: &http.Client{Transport: transport},
				endpointSafetyCheck: func(_ context.Context, endpoint string) error {
					if endpoint != testCase.ExpectedRequest.URL {
						t.Fatalf("endpoint safety checked %q, want %q", endpoint, testCase.ExpectedRequest.URL)
					}
					if !strings.HasPrefix(endpoint, "https://capture.aperio.test/") {
						t.Fatalf("fixture endpoint must stay local-only, got %s", endpoint)
					}
					checkedEndpoints = append(checkedEndpoints, endpoint)
					return nil
				},
			}
			if _, err := dispatcher.sendForKind(context.Background(), dest, fixture.Payload); err != nil {
				t.Fatalf("send %s: %v", testCase.Kind, err)
			}
			if len(checkedEndpoints) != 1 {
				t.Fatalf("expected one endpoint-safety check, got %d", len(checkedEndpoints))
			}
			if transport.calls != 1 {
				t.Fatalf("expected one captured request, got %d", transport.calls)
			}
			if transport.method != testCase.ExpectedRequest.Method || transport.url != testCase.ExpectedRequest.URL {
				t.Fatalf("request = %s %s, want %s %s", transport.method, transport.url, testCase.ExpectedRequest.Method, testCase.ExpectedRequest.URL)
			}
			if got := transport.header.Get("content-type"); got != testCase.ExpectedRequest.ContentType {
				t.Fatalf("content-type = %q, want %q", got, testCase.ExpectedRequest.ContentType)
			}
			for header, want := range testCase.ExpectedRequest.Headers {
				if got := transport.header.Get(header); got != want {
					t.Fatalf("%s header %s = %q, want %q", testCase.Kind, header, got, want)
				}
			}
			for _, header := range testCase.ExpectedRequest.AbsentHeaders {
				if got := transport.header.Get(header); got != "" {
					t.Fatalf("%s header %s unexpectedly set to %q", testCase.Kind, header, got)
				}
			}
			if testCase.ExpectedRequest.RawBody != "" {
				if got := string(transport.body); got != testCase.ExpectedRequest.RawBody {
					t.Fatalf("%s raw body = %q, want %q", testCase.Kind, got, testCase.ExpectedRequest.RawBody)
				}
			} else {
				assertJSONEqual(t, testCase.Name+" body", transport.body, testCase.ExpectedRequest.Body)
			}
			if testCase.Destination.Token != "" && strings.Contains(string(transport.body), testCase.Destination.Token) {
				t.Fatalf("%s request body leaked plaintext token", testCase.Kind)
			}
		})
	}
}

func TestHTTPAdapterRequiredFieldsAndCredentialsDoNotSendRequests(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[siemHTTPAdapterRequestsFixture](t, "siem-http-adapter-requests.json")
	for _, testCase := range fixture.NegativeCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			dest := destination{
				ID:             "dst_negative_" + testCase.Name,
				OrganizationID: fixture.Payload.OrganizationID,
				Kind:           testCase.Kind,
				Name:           testCase.Name,
				EndpointURL:    sql.NullString{String: "https://capture.aperio.test/" + testCase.Name, Valid: true},
			}
			switch testCase.Name {
			case "elastic_missing_index":
				dest.EncryptedToken = sql.NullString{
					String: encryptForDispatcherTest(t, "fixture-elastic-token", destinationTokenAAD(dest)),
					Valid:  true,
				}
			case "elastic_missing_token":
				dest.Index = sql.NullString{String: "aperio-negative", Valid: true}
			case "generic_webhook_tampered_secret":
				dest.EncryptedToken = sql.NullString{
					String: tamperEncryptedTagForDispatcherTest(t, encryptForDispatcherTest(t, "fixture-generic-secret", destinationTokenAAD(dest))),
					Valid:  true,
				}
			}
			transport := &captureTransport{}
			dispatcher := &Dispatcher{
				httpClient:          &http.Client{Transport: transport},
				endpointSafetyCheck: func(context.Context, string) error { return nil },
			}
			_, err := dispatcher.sendForKind(context.Background(), dest, fixture.Payload)
			if err == nil || !strings.Contains(err.Error(), testCase.Message) {
				t.Fatalf("expected %q failure, got %v", testCase.Message, err)
			}
			if transport.calls != 0 {
				t.Fatalf("%s should fail closed before HTTP transport, got %d calls", testCase.Name, transport.calls)
			}
		})
	}
}

func TestCerebroClaimsRequestContractMatchesLocalCaptureFixture(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[siemCerebroClaimsFixture](t, "siem-cerebro-claims.json")
	if fixture.Description == "" {
		t.Fatal("Cerebro fixture must document local-only capture constraints")
	}
	dest := destination{
		ID:             fixture.Destination.ID,
		OrganizationID: fixture.Destination.OrganizationID,
		Kind:           "CEREBRO_CLAIMS",
		Name:           "Cerebro fixture",
		EndpointURL:    sql.NullString{String: fixture.Destination.EndpointURL, Valid: true},
		Index:          sql.NullString{String: fixture.Destination.Index, Valid: true},
	}
	dest.EncryptedToken = sql.NullString{
		String: encryptForDispatcherTest(t, fixture.Destination.Token, destinationTokenAAD(dest)),
		Valid:  true,
	}
	transport := &captureTransport{}
	checkedEndpoints := []string{}
	dispatcher := &Dispatcher{
		httpClient: &http.Client{Transport: transport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			if !strings.HasPrefix(endpoint, "https://capture.aperio.test/") {
				t.Fatalf("Cerebro fixture endpoint must stay local-only, got %s", endpoint)
			}
			checkedEndpoints = append(checkedEndpoints, endpoint)
			return nil
		},
	}
	result, err := dispatcher.sendCerebroClaims(context.Background(), dest, fixture.Payload)
	if err != nil {
		t.Fatalf("send Cerebro claims: %v", err)
	}
	if result.CerebroRuntimeID != fixture.Destination.Index || result.FindingID != fixture.Expected.FindingID || result.DedupeKey != fixture.Expected.DedupeKey {
		t.Fatalf("unexpected Cerebro send metadata: %#v", result)
	}
	if len(result.CerebroClaims) != fixture.Expected.ClaimCount {
		t.Fatalf("metadata claim count = %d, want %d", len(result.CerebroClaims), fixture.Expected.ClaimCount)
	}
	if len(checkedEndpoints) != 2 {
		t.Fatalf("expected endpoint-safety checks for runtime and claim requests, got %d", len(checkedEndpoints))
	}
	if transport.calls != 2 || len(transport.requests) != 2 {
		t.Fatalf("expected runtime check and claim write, got calls=%d requests=%d", transport.calls, len(transport.requests))
	}

	runtimeRequest := transport.requests[0]
	if runtimeRequest.method != fixture.Expected.RuntimeRequest.Method || runtimeRequest.url != fixture.Expected.RuntimeRequest.URL {
		t.Fatalf("runtime request = %s %s, want %s %s", runtimeRequest.method, runtimeRequest.url, fixture.Expected.RuntimeRequest.Method, fixture.Expected.RuntimeRequest.URL)
	}
	for header, want := range fixture.Expected.RuntimeRequest.Headers {
		if got := runtimeRequest.header.Get(header); got != want {
			t.Fatalf("runtime header %s = %q, want %q", header, got, want)
		}
	}
	for _, header := range fixture.Expected.RuntimeRequest.AbsentHeaders {
		if got := runtimeRequest.header.Get(header); got != "" {
			t.Fatalf("runtime header %s unexpectedly set to %q", header, got)
		}
	}
	if len(runtimeRequest.body) != 0 {
		t.Fatalf("runtime request unexpectedly had body %q", string(runtimeRequest.body))
	}

	claimRequest := transport.requests[1]
	if claimRequest.method != fixture.Expected.ClaimRequest.Method || claimRequest.url != fixture.Expected.ClaimRequest.URL {
		t.Fatalf("claim request = %s %s, want %s %s", claimRequest.method, claimRequest.url, fixture.Expected.ClaimRequest.Method, fixture.Expected.ClaimRequest.URL)
	}
	for header, want := range fixture.Expected.ClaimRequest.Headers {
		if got := claimRequest.header.Get(header); got != want {
			t.Fatalf("claim header %s = %q, want %q", header, got, want)
		}
	}
	for _, header := range fixture.Expected.ClaimRequest.AbsentHeaders {
		if got := claimRequest.header.Get(header); got != "" {
			t.Fatalf("claim header %s unexpectedly set to %q", header, got)
		}
	}
	if strings.Contains(string(claimRequest.body), fixture.Destination.Token) || strings.Contains(string(runtimeRequest.body), fixture.Destination.Token) {
		t.Fatal("Cerebro request body leaked plaintext token")
	}
	var body struct {
		RuntimeID string         `json:"runtime_id"`
		Claims    []cerebroClaim `json:"claims"`
	}
	if err := json.Unmarshal(claimRequest.body, &body); err != nil {
		t.Fatalf("decode claim request body: %v", err)
	}
	if body.RuntimeID != fixture.Expected.ClaimRequest.Body.RuntimeID {
		t.Fatalf("runtime_id = %q, want %q", body.RuntimeID, fixture.Expected.ClaimRequest.Body.RuntimeID)
	}
	if len(body.Claims) != fixture.Expected.ClaimCount {
		t.Fatalf("claim body count = %d, want %d", len(body.Claims), fixture.Expected.ClaimCount)
	}
	findingExists := body.Claims[0]
	if findingExists.SubjectURN != fixture.Expected.FindingURN || findingExists.SourceEventID != fixture.Expected.SourceEvent {
		t.Fatalf("finding existence claim = %#v", findingExists)
	}
	if findingExists.Attributes["ruleId"] != "github.public_repository_created" || findingExists.Attributes["sourceEventId"] != fixture.Expected.SourceEvent {
		t.Fatalf("finding attributes = %#v", findingExists.Attributes)
	}
	if !hasCerebroClaim(body.Claims, "relation", "affects", "") {
		t.Fatalf("missing affects relation claim: %#v", body.Claims)
	}
	if !hasCerebroClaim(body.Claims, "attribute", "riskScore", "95") {
		t.Fatalf("missing riskScore attribute claim: %#v", body.Claims)
	}
}

func TestCerebroRefEscapesExternalIDLikeEncodeURIComponent(t *testing.T) {
	ref := cerebroRef(
		"org_urn_encoding",
		"runtime-main",
		"finding",
		"finding:id with spaces!*'()~:/?#[]@é",
		"encoded finding",
	)
	want := "urn:cerebro:org_urn_encoding:runtime:runtime-main:finding:finding%3Aid%20with%20spaces!*'()~%3A%2F%3F%23%5B%5D%40%C3%A9"
	if ref.URN != want {
		t.Fatalf("Cerebro URN = %q, want %q", ref.URN, want)
	}
}

func TestJSONFileSinkAppendsConfinedDeterministicJSONLFixture(t *testing.T) {
	fixture := readJSONFixture[siemJSONFileSinkFixture](t, "siem-json-file-sink.json")
	if fixture.Description == "" {
		t.Fatal("JSON_FILE fixture must document JSONL confinement semantics")
	}
	if len(fixture.Payloads) != 2 {
		t.Fatalf("expected two JSON_FILE payloads, got %d", len(fixture.Payloads))
	}
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	dest := destination{
		ID:             fixture.Destination.ID,
		OrganizationID: fixture.Destination.OrganizationID,
		Kind:           "JSON_FILE",
		Name:           "JSON file fixture",
		FilePath:       sql.NullString{String: fixture.Destination.FilePath, Valid: true},
	}
	outputPath := filepath.Join(exportRoot, fixture.Destination.FilePath)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		t.Fatalf("create preexisting JSONL parent: %v", err)
	}
	var preexistingValue any
	if err := json.Unmarshal(fixture.PreexistingLine, &preexistingValue); err != nil {
		t.Fatalf("decode preexisting JSONL fixture: %v", err)
	}
	preexistingLine, err := json.Marshal(preexistingValue)
	if err != nil {
		t.Fatalf("compact preexisting JSONL fixture: %v", err)
	}
	if err := os.WriteFile(outputPath, append(preexistingLine, '\n'), 0o600); err != nil {
		t.Fatalf("write preexisting JSONL line: %v", err)
	}
	for _, payload := range fixture.Payloads {
		if err := writeJSONFile(dest, payload); err != nil {
			t.Fatalf("append JSONL payload %s: %v", firstString(payload.Record["sourceEventId"]), err)
		}
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read JSONL output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected preexisting plus two appended lines, got %d: %q", len(lines), string(raw))
	}
	assertJSONEqual(t, "preexisting line preserved", []byte(lines[0]), fixture.PreexistingLine)
	for index, payload := range fixture.Payloads {
		var envelope Envelope
		if err := json.Unmarshal([]byte(lines[index+1]), &envelope); err != nil {
			t.Fatalf("decode JSONL envelope %d: %v", index+1, err)
		}
		if envelope.DestinationID != dest.ID || envelope.OrganizationID != dest.OrganizationID || envelope.SchemaVersion != "aperio.finding.v1" {
			t.Fatalf("unexpected JSONL envelope %d: %#v", index+1, envelope)
		}
		if envelope.Record["sourceEventId"] != payload.Record["sourceEventId"] {
			t.Fatalf("sourceEventId line %d = %v, want %v", index+1, envelope.Record["sourceEventId"], payload.Record["sourceEventId"])
		}
	}

	createdDest := dest
	createdDest.FilePath = sql.NullString{String: "tenant-b/new/findings.jsonl", Valid: true}
	if err := writeJSONFile(createdDest, fixture.Payloads[0]); err != nil {
		t.Fatalf("write JSONL with missing parent dirs: %v", err)
	}
	createdPath := filepath.Join(exportRoot, "tenant-b/new/findings.jsonl")
	info, err := os.Stat(createdPath)
	if err != nil {
		t.Fatalf("stat created JSONL: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("created JSONL mode = %v, want 0600", info.Mode().Perm())
	}
	for _, unsafePath := range fixture.UnsafePaths {
		unsafeDest := dest
		unsafeDest.FilePath = sql.NullString{String: unsafePath, Valid: true}
		if err := writeJSONFile(unsafeDest, fixture.Payloads[0]); err == nil {
			t.Fatalf("expected unsafe path %q to be rejected", unsafePath)
		}
	}
}

func TestJSONFileSinkRejectsSymlinkComponentsAndFinalSymlink(t *testing.T) {
	exportRoot := t.TempDir()
	outsideRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	payload := Payload{
		Kind:           "finding",
		OrganizationID: "org_symlink",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"findingId": "fnd_symlink", "sourceEventId": "evt_symlink"},
	}
	dest := destination{
		ID:             "dst_symlink",
		OrganizationID: payload.OrganizationID,
		Kind:           "JSON_FILE",
		Name:           "JSON file symlink fixture",
	}

	componentLink := filepath.Join(exportRoot, "tenant-link")
	if err := os.Symlink(outsideRoot, componentLink); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	dest.FilePath = sql.NullString{String: "tenant-link/findings.jsonl", Valid: true}
	if err := writeJSONFile(dest, payload); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink component rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outsideRoot, "findings.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("symlink component write touched outside target, stat err=%v", err)
	}

	insideDir := filepath.Join(exportRoot, "tenant-real")
	if err := os.MkdirAll(insideDir, 0o755); err != nil {
		t.Fatalf("create inside dir: %v", err)
	}
	outsideFile := filepath.Join(outsideRoot, "outside.jsonl")
	original := []byte("outside target must not change\n")
	if err := os.WriteFile(outsideFile, original, 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	finalLink := filepath.Join(insideDir, "findings.jsonl")
	if err := os.Symlink(outsideFile, finalLink); err != nil {
		t.Skipf("final symlink creation unavailable: %v", err)
	}
	dest.FilePath = sql.NullString{String: "tenant-real/findings.jsonl", Valid: true}
	if err := writeJSONFile(dest, payload); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected final symlink rejection, got %v", err)
	}
	after, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("read outside target: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("final symlink write mutated outside target: %q", string(after))
	}
}

func TestNetworkAdapterHarnessPreservesEndpointSafetyGate(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	payload := Payload{
		Kind:           "finding",
		OrganizationID: "org_safety",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"findingId": "fnd_safety", "sourceEventId": "evt_safety"},
	}
	for _, kind := range []string{"SPLUNK_HEC", "PANTHER", "PANOPTICON", "ELASTIC", "DATADOG", "GENERIC_WEBHOOK", "CEREBRO_CLAIMS"} {
		t.Run(kind, func(t *testing.T) {
			dest := destination{
				ID:             "dst_safety_" + strings.ToLower(kind),
				OrganizationID: payload.OrganizationID,
				Kind:           kind,
				EndpointURL:    sql.NullString{String: "https://capture.aperio.test/" + strings.ToLower(kind), Valid: true},
				Index:          sql.NullString{String: "runtime-safety", Valid: true},
			}
			if kind == "ELASTIC" {
				dest.Index = sql.NullString{String: "aperio-safety", Valid: true}
			}
			dest.EncryptedToken = sql.NullString{
				String: encryptForDispatcherTest(t, "token-"+strings.ToLower(kind), destinationTokenAAD(dest)),
				Valid:  true,
			}
			transport := &captureTransport{}
			dispatcher := &Dispatcher{
				httpClient: &http.Client{Transport: transport},
				endpointSafetyCheck: func(context.Context, string) error {
					return errors.New("blocked by endpoint safety")
				},
			}
			_, err := dispatcher.sendForKind(context.Background(), dest, payload)
			if err == nil || !strings.Contains(err.Error(), "endpoint safety") {
				t.Fatalf("expected endpoint safety failure, got %v", err)
			}
			if transport.calls != 0 {
				t.Fatalf("unsafe endpoint should be blocked before transport, got %d calls", transport.calls)
			}
		})
	}
}

func TestSendGenericWebhookCapturesReferenceRequestShape(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
	fixture := readJSONFixture[genericWebhookFixture](t, "siem-generic-webhook-delivery.json")
	destination := destination{
		ID:             fixture.Destination.ID,
		OrganizationID: fixture.Destination.OrganizationID,
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: fixture.Destination.EndpointURL, Valid: true},
	}
	destination.EncryptedToken = sql.NullString{
		String: encryptForDispatcherTest(t, fixture.Destination.Token, destinationTokenAAD(destination)),
		Valid:  true,
	}
	transport := &captureTransport{}
	safetyChecked := false
	dispatcher := &Dispatcher{
		httpClient: &http.Client{Transport: transport},
		endpointSafetyCheck: func(_ context.Context, endpoint string) error {
			safetyChecked = true
			if endpoint != fixture.ExpectedRequest.URL {
				t.Fatalf("endpoint safety checked %q, want %q", endpoint, fixture.ExpectedRequest.URL)
			}
			return nil
		},
	}

	if err := dispatcher.sendGenericWebhook(context.Background(), destination, fixture.Payload); err != nil {
		t.Fatalf("send generic webhook: %v", err)
	}
	if !safetyChecked {
		t.Fatal("expected send-time endpoint safety check")
	}
	if transport.calls != 1 {
		t.Fatalf("expected one request, got %d", transport.calls)
	}
	if transport.method != fixture.ExpectedRequest.Method || transport.url != fixture.ExpectedRequest.URL {
		t.Fatalf("request = %s %s", transport.method, transport.url)
	}
	if transport.header.Get("content-type") != fixture.ExpectedRequest.ContentType {
		t.Fatalf("content-type = %q", transport.header.Get("content-type"))
	}
	if got := transport.header.Get(fixture.ExpectedRequest.SignatureHeader); got != fixture.ExpectedRequest.Signature {
		t.Fatalf("signature = %s, want %s", got, fixture.ExpectedRequest.Signature)
	}
	assertJSONEqual(t, "generic webhook body", transport.body, fixture.ExpectedRequest.Body)
	if strings.Contains(string(transport.body), fixture.Destination.Token) {
		t.Fatal("webhook request body must not contain the signing secret")
	}
}

func TestDecryptStringFailsClosedForCredentialEnvelopeErrors(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	aad := "org_1:siem:dst_1:token"
	plaintext := "fixture-siem-token-not-secret"
	validEnvelope := "eyJ2ZXJzaW9uIjoxLCJhbGdvcml0aG0iOiJhZXMtMjU2LWdjbSIsIml2IjoiTVRJek5EVTJOemc1TURFeSIsInRhZyI6Im1sUjJUS1QyMmdsMHBOOTRNa0NYX3ciLCJjaXBoZXJ0ZXh0IjoiN1Qta25Jc0lRakVsOW1XQWRNSjNfUDJQaDE5X3RVellFaDgifQ"

	t.Run("missing key", func(t *testing.T) {
		t.Setenv("APERIO_ENCRYPTION_KEY", "")
		_, err := decryptString(validEnvelope, "org_demo:GITHUB:writer:access_token")
		if err == nil || !strings.Contains(err.Error(), "APERIO_ENCRYPTION_KEY is required") {
			t.Fatalf("expected missing key failure, got %v", err)
		}
		if strings.Contains(err.Error(), "demo-provider-token-GITHUB") {
			t.Fatal("missing-key error leaked plaintext credential")
		}
	})

	for _, testCase := range []struct {
		name      string
		encrypted func(t *testing.T) string
		aad       string
	}{
		{
			name:      "malformed envelope",
			encrypted: func(*testing.T) string { return "not-a-valid-envelope" },
			aad:       aad,
		},
		{
			name: "wrong aad",
			encrypted: func(t *testing.T) string {
				return encryptForDispatcherTest(t, plaintext, aad)
			},
			aad: aad + ":wrong",
		},
		{
			name: "tampered tag",
			encrypted: func(t *testing.T) string {
				return tamperEncryptedTagForDispatcherTest(t, encryptForDispatcherTest(t, plaintext, aad))
			},
			aad: aad,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("APERIO_ENCRYPTION_KEY", "base64:"+base64.StdEncoding.EncodeToString(key))
			_, err := decryptString(testCase.encrypted(t), testCase.aad)
			if err == nil {
				t.Fatal("expected decrypt failure")
			}
			if strings.Contains(err.Error(), plaintext) {
				t.Fatalf("decrypt error leaked plaintext credential: %v", err)
			}
		})
	}
}

func TestLocalCaptureSmokeTransportOnlyAllowsSyntheticEndpoints(t *testing.T) {
	var captured struct {
		Method     string              `json:"method"`
		URL        string              `json:"url"`
		Headers    map[string][]string `json:"headers"`
		BodyBase64 string              `json:"bodyBase64"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/capture" {
			t.Fatalf("unexpected capture path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode capture body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client, checkEndpoint, err := localCaptureFromURL(server.URL + "/capture")
	if err != nil {
		t.Fatalf("local capture setup: %v", err)
	}
	if err := checkEndpoint(context.Background(), "https://splunk.aperio.test/collector"); err != nil {
		t.Fatalf("synthetic endpoint rejected: %v", err)
	}
	for _, unsafeEndpoint := range []string{
		"http://splunk.aperio.test/collector",
		"https://localhost/collector",
		"https://example.com/collector",
		"https://aperio.test/collector",
		"https://splunk.aperio.test.evil/collector",
		"https://user:pass@splunk.aperio.test/collector",
	} {
		if err := checkEndpoint(context.Background(), unsafeEndpoint); err == nil {
			t.Fatalf("expected local capture endpoint %s to be rejected", unsafeEndpoint)
		}
	}

	req, err := http.NewRequest(http.MethodPost, "https://splunk.aperio.test/collector", strings.NewReader("fixture-body"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Splunk fixture-token")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("capture request: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("capture status = %d", res.StatusCode)
	}
	if captured.Method != http.MethodPost || captured.URL != "https://splunk.aperio.test/collector" {
		t.Fatalf("captured request = %#v", captured)
	}
	decodedBody, err := base64.StdEncoding.DecodeString(captured.BodyBase64)
	if err != nil {
		t.Fatalf("decode captured body: %v", err)
	}
	if string(decodedBody) != "fixture-body" {
		t.Fatalf("captured body = %q", string(decodedBody))
	}
	if got := captured.Headers["Authorization"]; !reflect.DeepEqual(got, []string{"Splunk fixture-token"}) {
		t.Fatalf("captured authorization header = %#v", got)
	}
}

func TestSendGenericWebhookEndpointSafetyBlocksHTTP(t *testing.T) {
	transport := &captureTransport{}
	dispatcher := &Dispatcher{httpClient: &http.Client{Transport: transport}}
	err := dispatcher.sendGenericWebhook(context.Background(), destination{
		ID:             "dst_webhook_unsafe",
		OrganizationID: "org_1",
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: "https://127.0.0.1:9000/aperio", Valid: true},
	}, Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "fnd_1"},
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback endpoint safety error, got %v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("unsafe endpoint should be blocked before HTTP, got %d calls", transport.calls)
	}
}

func TestSendGenericWebhookDoesNotFollowRedirects(t *testing.T) {
	transport := &captureTransport{
		status:   http.StatusFound,
		location: "https://169.254.169.254/latest/meta-data",
	}
	dispatcher := &Dispatcher{
		httpClient:          &http.Client{Transport: transport},
		endpointSafetyCheck: func(context.Context, string) error { return nil },
	}
	err := dispatcher.sendGenericWebhook(context.Background(), destination{
		ID:             "dst_webhook_redirect",
		OrganizationID: "org_1",
		Kind:           "GENERIC_WEBHOOK",
		EndpointURL:    sql.NullString{String: "https://webhook.receiver.example/aperio", Valid: true},
	}, Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"id": "fnd_1"},
	})
	if err == nil || !strings.Contains(err.Error(), "302 Found") {
		t.Fatalf("expected redirect response to fail without following, got %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("redirect should not be followed, got %d calls", transport.calls)
	}
}

func TestEndpointSafetyRejectsDNSRebindingToPrivateAddress(t *testing.T) {
	err := assertSafeEndpointURLWithResolver(
		context.Background(),
		"https://webhook.receiver.example/aperio",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	)
	if err == nil || !strings.Contains(err.Error(), "private addresses") {
		t.Fatalf("expected DNS private-address rejection, got %v", err)
	}
	if err := assertSafeEndpointURLWithResolver(
		context.Background(),
		"https://8.8.8.8/aperio",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	); err != nil {
		t.Fatalf("public literal IP should not require DNS resolver, got %v", err)
	}
}

func TestSafeDialAddressUsesValidatedResolvedIP(t *testing.T) {
	if _, err := safeDialAddress(
		context.Background(),
		"webhook.receiver.example:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}},
	); err == nil || !strings.Contains(err.Error(), "private addresses") {
		t.Fatalf("expected private resolved address rejection, got %v", err)
	}

	target, err := safeDialAddress(
		context.Background(),
		"webhook.receiver.example:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}},
	)
	if err != nil {
		t.Fatalf("public resolved address rejected: %v", err)
	}
	if target != "8.8.8.8:443" {
		t.Fatalf("dial target = %q, want resolved IP target", target)
	}

	if _, err := safeDialAddress(
		context.Background(),
		"127.0.0.1:443",
		staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}},
	); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected private literal rejection, got %v", err)
	}
}

func TestNormalizeFilePathConfinesRawDatabasePathsToExportRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", root)
	relativePath, err := normalizeFilePath("tenant-a/findings.jsonl")
	if err != nil {
		t.Fatalf("relative path: %v", err)
	}
	if relativePath != filepath.Join(root, "tenant-a", "findings.jsonl") {
		t.Fatalf("relative path normalized to %s", relativePath)
	}
	insideAbsolute := filepath.Join(root, "absolute", "findings.jsonl")
	if got, err := normalizeFilePath(insideAbsolute); err != nil || got != insideAbsolute {
		t.Fatalf("inside absolute path = %s err=%v", got, err)
	}
	for _, unsafe := range []string{
		"../escape.jsonl",
		filepath.Join(root+"-sibling", "findings.jsonl"),
		root,
	} {
		if got, err := normalizeFilePath(unsafe); err == nil {
			t.Fatalf("expected %q to be rejected, got %s", unsafe, got)
		}
	}
}

func TestDestinationLoadFailureOnlyPermanentForMissingRows(t *testing.T) {
	permanent, message := destinationLoadFailure(sql.ErrNoRows)
	if !permanent || message != "destination not active" {
		t.Fatalf("expected missing destination to be permanent, got permanent=%v message=%q", permanent, message)
	}

	permanent, message = destinationLoadFailure(errors.New("statement timeout"))
	if permanent {
		t.Fatalf("expected transient load error to retry, got permanent with message %q", message)
	}
	if message != "statement timeout" {
		t.Fatalf("unexpected transient message %q", message)
	}
}

func TestSIEMDeliveryWideEventCoversOutcomesWithoutSecrets(t *testing.T) {
	base := delivery{
		ID:             "sdel_1",
		OrganizationID: "org_1",
		DestinationID:  sql.NullString{String: "dst_1", Valid: true},
		Stream:         "FINDINGS",
		Attempts:       0,
		MaxAttempts:    3,
	}
	payload := Payload{
		Kind:           "finding",
		OrganizationID: "org_1",
		OccurredAt:     "2026-06-06T00:00:00.000Z",
		Record:         map[string]any{"findingId": "fnd_1", "sourceEventId": "evt_1"},
	}
	dest := destination{ID: "dst_1", OrganizationID: "org_1", Kind: "GENERIC_WEBHOOK"}

	delivered := siemDeliveryWideEvent(base, payload, dest, nil, false, 7*time.Millisecond)
	if delivered.Name != "siem.delivery.process" || delivered.Service != "siem-dispatcher" {
		t.Fatalf("unexpected telemetry identity: %#v", delivered)
	}
	if delivered.Organization != "org_1" ||
		delivered.Dimensions["outcome"] != "delivered" ||
		delivered.Dimensions["destination_kind"] != "GENERIC_WEBHOOK" ||
		delivered.Dimensions["destination_id"] != "dst_1" ||
		delivered.Dimensions["stream"] != "FINDINGS" ||
		delivered.Dimensions["payload_kind"] != "finding" {
		t.Fatalf("unexpected delivered dimensions: %#v", delivered.Dimensions)
	}
	if delivered.Measurements["attempt"] != 1 || delivered.Measurements["max_attempts"] != 3 || delivered.Measurements["duration_ms"] != 7 {
		t.Fatalf("unexpected delivered measurements: %#v", delivered.Measurements)
	}
	if _, ok := delivered.Dimensions["error_kind"]; ok {
		t.Fatalf("delivered telemetry should not include error_kind: %#v", delivered.Dimensions)
	}

	retryable := siemDeliveryWideEvent(base, payload, dest, httpStatusError{statusCode: http.StatusServiceUnavailable, statusText: "Service Unavailable"}, false, time.Millisecond)
	if retryable.Dimensions["outcome"] != "retryable_failed" || retryable.Dimensions["error_kind"] != "http_5xx" || retryable.Dimensions["permanence"] != "retryable" {
		t.Fatalf("unexpected retryable telemetry: %#v", retryable.Dimensions)
	}

	timeout := siemDeliveryWideEvent(base, payload, dest, context.DeadlineExceeded, false, time.Millisecond)
	if timeout.Dimensions["outcome"] != "timeout" || timeout.Dimensions["error_kind"] != "timeout" || timeout.Dimensions["permanence"] != "retryable" {
		t.Fatalf("unexpected timeout telemetry: %#v", timeout.Dimensions)
	}

	permanent := siemDeliveryWideEvent(base, payload, dest, httpStatusError{statusCode: http.StatusUnauthorized, statusText: "Unauthorized"}, true, time.Millisecond)
	if permanent.Dimensions["outcome"] != "dead_letter" || permanent.Dimensions["error_kind"] != "http_4xx" || permanent.Dimensions["permanence"] != "permanent" {
		t.Fatalf("unexpected permanent telemetry: %#v", permanent.Dimensions)
	}

	exhaustedItem := base
	exhaustedItem.Attempts = 2
	exhausted := siemDeliveryWideEvent(exhaustedItem, payload, dest, errors.New("temporary outage"), false, time.Millisecond)
	if exhausted.Dimensions["outcome"] != "dead_letter" || exhausted.Dimensions["error_kind"] != "error" || exhausted.Dimensions["permanence"] != "exhausted" {
		t.Fatalf("unexpected exhausted telemetry: %#v", exhausted.Dimensions)
	}

	lostLease := siemDeliveryWideEvent(base, payload, dest, errDeliveryLeaseLost, false, time.Millisecond)
	if lostLease.Dimensions["outcome"] != "lost_lease" || lostLease.Dimensions["error_kind"] != "lease_lost" {
		t.Fatalf("unexpected lost-lease telemetry: %#v", lostLease.Dimensions)
	}

	var sink bytes.Buffer
	restore := telemetry.SetOutput(&sink)
	emitSIEMDeliveryWideEvent(base, payload, dest, errors.New("database password should not be serialized"), false, time.Millisecond)
	restore()
	if !strings.Contains(sink.String(), `"event_name":"siem.delivery.process"`) || strings.Contains(sink.String(), "password") {
		t.Fatalf("unexpected emitted telemetry: %s", sink.String())
	}
}

func encryptForDispatcherTest(t *testing.T, plaintext string, aad string) string {
	t.Helper()
	key, err := resolveEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("123456789012")
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	tagStart := len(sealed) - gcm.Overhead()
	envelope := encryptedEnvelope{
		Version:    1,
		Algorithm:  encryptionAlgorithm,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Tag:        base64.RawURLEncoding.EncodeToString(sealed[tagStart:]),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed[:tagStart]),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func tamperEncryptedTagForDispatcherTest(t *testing.T, encrypted string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Tag = base64.RawURLEncoding.EncodeToString(make([]byte, encryptionNonceBytes+4))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func TestProcessReturnsErrorForRecordedFailure(t *testing.T) {
	state := &dispatcherDriverState{}
	driverName := fmt.Sprintf("siem_failure_%d", time.Now().UnixNano())
	sql.Register(driverName, &dispatcherDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	dispatcher := &Dispatcher{db: db, leaseOwner: "test-owner"}
	err = dispatcher.process(context.Background(), delivery{
		ID:             "del_1",
		OrganizationID: "org_1",
		Payload:        json.RawMessage(`{"kind":"unknown","organizationId":"org_1","occurredAt":"2026-06-06T00:00:00Z","record":{}}`),
		Attempts:       0,
		MaxAttempts:    3,
	})
	if err == nil {
		t.Fatal("expected process to return the delivery failure after recording it")
	}

	status, attempts, message := state.failureUpdate()
	if status != "DEAD_LETTER" || attempts != "1" {
		t.Fatalf("expected recorded dead-letter attempt, got status=%s attempts=%s", status, attempts)
	}
	if !strings.Contains(message, "invalid delivery kind") {
		t.Fatalf("expected recorded parse error, got %q", message)
	}
}

type dispatcherDriverState struct {
	mu    sync.Mutex
	execs [][]driver.NamedValue
}

func (s *dispatcherDriverState) failureUpdate() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.execs) == 0 {
		return "", "", ""
	}
	args := s.execs[len(s.execs)-1]
	return fmt.Sprint(args[0].Value), fmt.Sprint(args[1].Value), fmt.Sprint(args[3].Value)
}

type dispatcherDriver struct {
	state *dispatcherDriverState
}

func (d *dispatcherDriver) Open(string) (driver.Conn, error) {
	return &dispatcherConn{state: d.state}, nil
}

type dispatcherConn struct {
	state *dispatcherDriverState
}

func (c *dispatcherConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}

func (c *dispatcherConn) Close() error {
	return nil
}

func (c *dispatcherConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions not supported")
}

func (c *dispatcherConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "UPDATE siem_deliveries") {
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	c.state.mu.Lock()
	c.state.execs = append(c.state.execs, args)
	c.state.mu.Unlock()
	return driver.RowsAffected(1), nil
}
