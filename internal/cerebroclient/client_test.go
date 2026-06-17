package cerebroclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigFromEnvDefaultsAndTrims(t *testing.T) {
	t.Setenv("CEREBRO_BASE_URL", " https://cerebro.example.com ")
	t.Setenv("CEREBRO_API_KEY", " api-key ")
	t.Setenv("CEREBRO_TOKEN", "ignored-token")
	t.Setenv("CEREBRO_TENANT_ID", " tenant-a ")
	t.Setenv("CEREBRO_SOURCE_RUNTIME_ID", "")
	t.Setenv("CEREBRO_SOURCE_ID", "")
	t.Setenv("CEREBRO_HTTP_TIMEOUT_SECONDS", "7")

	config := ConfigFromEnv()
	if config.BaseURL != "https://cerebro.example.com" {
		t.Fatalf("BaseURL = %q", config.BaseURL)
	}
	if config.APIKey != "api-key" {
		t.Fatalf("APIKey = %q", config.APIKey)
	}
	if config.TenantID != "tenant-a" {
		t.Fatalf("TenantID = %q", config.TenantID)
	}
	if config.RuntimeID != DefaultRuntimeID {
		t.Fatalf("RuntimeID = %q, want %q", config.RuntimeID, DefaultRuntimeID)
	}
	if config.SourceID != DefaultSourceID {
		t.Fatalf("SourceID = %q, want %q", config.SourceID, DefaultSourceID)
	}
	if config.Timeout != 7*time.Second {
		t.Fatalf("Timeout = %s, want 7s", config.Timeout)
	}
	if !config.Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
	runtime := config.DefaultRuntime()
	if runtime.TenantID != "tenant-a" {
		t.Fatalf("DefaultRuntime().TenantID = %q", runtime.TenantID)
	}
	if runtime.Config["surface"] != "aperio_saas_dr" {
		t.Fatalf("DefaultRuntime().Config[surface] = %q", runtime.Config["surface"])
	}
}

func TestPutSourceRuntimeSendsTenantScopedBearerRequest(t *testing.T) {
	var seenBody map[string]SourceRuntime
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/api/source-runtimes/runtime-1" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Cerebro-Tenant"); got != "tenant-a" {
			t.Fatalf("X-Cerebro-Tenant = %q", got)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("Content-Type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runtime": map[string]any{
				"id":        "runtime-1",
				"source_id": "aperio_saas_dr",
				"tenant_id": "tenant-a",
				"config": map[string]string{
					"surface": "aperio_saas_dr",
				},
			},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:  server.URL + "/api",
		APIKey:   "secret-key",
		TenantID: "tenant-a",
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	runtime, err := client.PutSourceRuntime(context.Background(), SourceRuntime{
		ID:       "runtime-1",
		SourceID: "aperio_saas_dr",
		Config: map[string]string{
			"surface": "aperio_saas_dr",
		},
	})
	if err != nil {
		t.Fatalf("PutSourceRuntime() error = %v", err)
	}
	if runtime == nil || runtime.ID != "runtime-1" {
		t.Fatalf("runtime = %#v", runtime)
	}
	if seenBody["runtime"].TenantID != "tenant-a" {
		t.Fatalf("request runtime tenant = %q, want tenant-a", seenBody["runtime"].TenantID)
	}
}

func TestWriteClaimsSendsReplaceExistingAndParsesCounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.EscapedPath() != "/source-runtimes/runtime%2Fwith%20space/claims" {
			t.Fatalf("path = %s", r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
			t.Fatalf("Authorization = %q", got)
		}
		var request WriteClaimsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if request.RuntimeID != "runtime/with space" {
			t.Fatalf("RuntimeID = %q", request.RuntimeID)
		}
		if !request.ReplaceExisting {
			t.Fatal("ReplaceExisting = false, want true")
		}
		if len(request.Claims) != 1 || request.Claims[0].Predicate != "exists" {
			t.Fatalf("Claims = %#v", request.Claims)
		}
		_ = json.NewEncoder(w).Encode(WriteClaimsResponse{
			ClaimsWritten:          1,
			EntitiesUpserted:       1,
			RelationLinksProjected: 0,
			ClaimsRetracted:        2,
		})
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:  server.URL,
		APIKey:   "secret-key",
		TenantID: "tenant-a",
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	response, err := client.WriteClaims(context.Background(), WriteClaimsRequest{
		RuntimeID:       "runtime/with space",
		ReplaceExisting: true,
		Claims: []Claim{{
			SubjectURN: "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1",
			SubjectRef: EntityRef{
				URN:        "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1",
				EntityType: "finding",
				Label:      "Finding",
			},
			Predicate:  "exists",
			ClaimType:  "entity",
			Status:     "asserted",
			ObservedAt: "2026-06-16T00:00:00Z",
		}},
	})
	if err != nil {
		t.Fatalf("WriteClaims() error = %v", err)
	}
	if response.ClaimsWritten != 1 || response.ClaimsRetracted != 2 {
		t.Fatalf("response = %#v", response)
	}
}

func TestListClaimsSendsFiltersAndParsesClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.EscapedPath() != "/api/source-runtimes/runtime%2F1/claims" {
			t.Fatalf("path = %s", r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Cerebro-Tenant"); got != "tenant-a" {
			t.Fatalf("X-Cerebro-Tenant = %q", got)
		}
		query := r.URL.Query()
		if query.Get("subject_urn") != "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1" ||
			query.Get("predicate") != "severity" ||
			query.Get("claim_type") != "attribute" ||
			query.Get("status") != "asserted" ||
			query.Get("source_event_id") != "evt-1" ||
			query.Get("limit") != "25" {
			t.Fatalf("query = %#v", query)
		}
		_ = json.NewEncoder(w).Encode(ListClaimsResponse{
			Claims: []Claim{{
				ID:            "claim-1",
				SubjectURN:    "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1",
				Predicate:     "severity",
				ObjectValue:   "HIGH",
				ClaimType:     "attribute",
				Status:        "asserted",
				SourceEventID: "evt-1",
				ObservedAt:    "2026-06-16T12:00:00Z",
				ValidFrom:     "2026-06-16T12:00:00Z",
				Attributes:    map[string]string{"ruleId": "github.public_repository_created"},
			}},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:  server.URL + "/api",
		APIKey:   "secret-key",
		TenantID: "tenant-a",
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	response, err := client.ListClaims(context.Background(), ListClaimsRequest{
		RuntimeID:     "runtime/1",
		SubjectURN:    " urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1 ",
		Predicate:     "severity",
		ClaimType:     "attribute",
		Status:        "asserted",
		SourceEventID: "evt-1",
		Limit:         25,
	})
	if err != nil {
		t.Fatalf("ListClaims() error = %v", err)
	}
	if len(response.Claims) != 1 {
		t.Fatalf("claims = %d, want 1", len(response.Claims))
	}
	claim := response.Claims[0]
	if claim.ID != "claim-1" || claim.ObjectValue != "HIGH" || claim.ValidFrom == "" || claim.Attributes["ruleId"] != "github.public_repository_created" {
		t.Fatalf("claim = %#v", claim)
	}
}

func TestGetEntityNeighborhoodSendsGraphQueryAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.EscapedPath() != "/api/platform/graph/neighborhood" {
			t.Fatalf("path = %s", r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
			t.Fatalf("Authorization = %q", got)
		}
		query := r.URL.Query()
		if query.Get("root_urn") != "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1" || query.Get("limit") != "10" {
			t.Fatalf("query = %#v", query)
		}
		_ = json.NewEncoder(w).Encode(EntityNeighborhood{
			Root: &GraphEntity{
				URN:        "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1",
				EntityType: "finding",
				Label:      "Public repository created",
			},
			Neighbors: []GraphEntity{{
				URN:        "urn:cerebro:tenant-a:runtime:runtime-1:asset:repo",
				EntityType: "asset",
				Label:      "writer/aperio",
			}},
			Relations: []GraphRelation{{
				FromURN:  "urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1",
				Relation: "affects",
				ToURN:    "urn:cerebro:tenant-a:runtime:runtime-1:asset:repo",
			}},
		})
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:  server.URL + "/api",
		APIKey:   "secret-key",
		TenantID: "tenant-a",
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	response, err := client.GetEntityNeighborhood(context.Background(), " urn:cerebro:tenant-a:runtime:runtime-1:finding:f-1 ", 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if response.Root == nil || response.Root.EntityType != "finding" || len(response.Neighbors) != 1 || len(response.Relations) != 1 {
		t.Fatalf("neighborhood = %#v", response)
	}
	if response.Relations[0].Relation != "affects" {
		t.Fatalf("relation = %#v", response.Relations[0])
	}
}

func TestHTTPErrorDoesNotExposeRequestCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "tenant mismatch", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:  server.URL,
		APIKey:   "super-secret-key",
		TenantID: "tenant-a",
	}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = client.GetSourceRuntime(context.Background(), "runtime-1")
	if err == nil {
		t.Fatal("GetSourceRuntime() error = nil")
	}
	var httpErr HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error type = %T, want HTTPError", err)
	}
	if httpErr.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d", httpErr.StatusCode)
	}
	if strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("error exposed API key: %s", err)
	}
}

func TestNewRejectsUnsafeBaseURL(t *testing.T) {
	_, err := New(Config{
		BaseURL:  "https://user:pass@cerebro.example.com?token=abc",
		APIKey:   "secret-key",
		TenantID: "tenant-a",
	})
	if err == nil {
		t.Fatal("New() error = nil")
	}
	if !strings.Contains(err.Error(), "must not include credentials") {
		t.Fatalf("error = %v", err)
	}
}
