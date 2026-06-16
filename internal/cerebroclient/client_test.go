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
