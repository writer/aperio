package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/aperio/internal/cerebroclient"
)

func TestEnsureCerebroRuntimeSkipsWhenConfigDisabled(t *testing.T) {
	runtime, enabled, err := ensureCerebroRuntime(context.Background(), cerebroclient.Config{})
	if err != nil {
		t.Fatalf("ensureCerebroRuntime() error = %v", err)
	}
	if enabled {
		t.Fatal("enabled = true, want false")
	}
	if runtime != nil {
		t.Fatalf("runtime = %#v, want nil", runtime)
	}
}

func TestEnsureCerebroRuntimePutsDefaultRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/source-runtimes/runtime-a" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer api-key" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Cerebro-Tenant"); got != "tenant-a" {
			t.Fatalf("X-Cerebro-Tenant = %q", got)
		}
		var body map[string]cerebroclient.SourceRuntime
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		runtime := body["runtime"]
		if runtime.ID != "runtime-a" || runtime.SourceID != "aperio-source" || runtime.TenantID != "tenant-a" {
			t.Fatalf("runtime body = %#v", runtime)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runtime": runtime,
		})
	}))
	defer server.Close()

	runtime, enabled, err := ensureCerebroRuntime(context.Background(), cerebroclient.Config{
		BaseURL:   server.URL,
		APIKey:    "api-key",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-a",
		SourceID:  "aperio-source",
		Timeout:   time.Second,
	}, cerebroclient.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("ensureCerebroRuntime() error = %v", err)
	}
	if !enabled {
		t.Fatal("enabled = false, want true")
	}
	if runtime == nil || runtime.ID != "runtime-a" {
		t.Fatalf("runtime = %#v", runtime)
	}
}

func TestEnsureCerebroRuntimeReturnsCerebroFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "tenant mismatch", http.StatusForbidden)
	}))
	defer server.Close()

	runtime, enabled, err := ensureCerebroRuntime(context.Background(), cerebroclient.Config{
		BaseURL:   server.URL,
		APIKey:    "api-key",
		TenantID:  "tenant-a",
		RuntimeID: "runtime-a",
		SourceID:  "aperio-source",
		Timeout:   time.Second,
	}, cerebroclient.WithHTTPClient(server.Client()))
	if err == nil {
		t.Fatal("ensureCerebroRuntime() error = nil")
	}
	if !enabled {
		t.Fatal("enabled = false, want true")
	}
	if runtime != nil {
		t.Fatalf("runtime = %#v, want nil", runtime)
	}
}
