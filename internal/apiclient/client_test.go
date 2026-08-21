package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRPCUsesBearerTokenAndConnectProcedure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/aperio.v1.AperioService/ForceSyncIntegration" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer apk_live_test.secret" {
			t.Fatalf("authorization = %q", got)
		}
		if got := request.Header.Get("Connect-Protocol-Version"); got != "1" {
			t.Fatalf("connect protocol version = %q", got)
		}
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["integrationId"] != "int_test" {
			t.Fatalf("payload = %#v", payload)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"id":"int_test"}}`))
	}))
	defer server.Close()

	client, err := New(server.URL, "apk_live_test.secret")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RPC(context.Background(), "ForceSyncIntegration", map[string]string{"integrationId": "int_test"})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(result) {
		t.Fatalf("invalid result: %s", result)
	}
}

func TestHealthChecksLivenessAndReadiness(t *testing.T) {
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen[request.URL.Path] = true
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !seen["/healthz"] || !seen["/readyz"] {
		t.Fatalf("seen = %#v", seen)
	}
}

func TestCompatUnwrapsTunneledJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["method"] != "GET" || payload["path"] != "/api/v1/admin/api-tokens" {
			t.Fatalf("payload = %#v", payload)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"bodyJson":"{\"data\":[]}"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "session.token")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Compat(context.Background(), http.MethodGet, "/api/v1/admin/api-tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"data":[]}` {
		t.Fatalf("result = %s", result)
	}
}
