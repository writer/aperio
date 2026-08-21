package bootstrap

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
)

func TestAuthorizeCompatCredentialScopes(t *testing.T) {
	read := compatAuth{CredentialKind: "api_token", Scopes: []string{"READ"}}
	if err := authorizeCompatCredential(read, http.MethodGet, "/api/v1/siem"); err != nil {
		t.Fatalf("READ token rejected for GET: %v", err)
	}
	if err := authorizeCompatCredential(read, http.MethodPost, "/api/v1/siem"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("READ POST code = %v, err = %v", connect.CodeOf(err), err)
	}
	write := compatAuth{CredentialKind: "api_token", Scopes: []string{"WRITE"}}
	if err := authorizeCompatCredential(write, http.MethodPost, "/api/v1/siem"); err != nil {
		t.Fatalf("WRITE token rejected for POST: %v", err)
	}
	if err := authorizeCompatCredential(write, http.MethodGet, "/api/v1/admin/settings"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("WRITE admin code = %v, err = %v", connect.CodeOf(err), err)
	}
	admin := compatAuth{CredentialKind: "api_token", Scopes: []string{"ADMIN"}}
	if err := authorizeCompatCredential(admin, http.MethodGet, "/api/v1/admin/settings"); err != nil {
		t.Fatalf("ADMIN token rejected for admin GET: %v", err)
	}
	if err := authorizeCompatCredential(admin, http.MethodGet, "/api/v1/admin/api-tokens"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("token management code = %v, err = %v", connect.CodeOf(err), err)
	}
}

func TestAPITokenCreateAuthenticateAndRevoke(t *testing.T) {
	app, sessionAuth := newTestDBApp(t)
	created, err := app.compatCreateAPIToken(context.Background(), map[string]any{
		"name":   "CI read token",
		"scopes": []any{"READ"},
	}, sessionAuth)
	if err != nil {
		t.Fatal(err)
	}
	data := dataMap(t, created)
	rawToken, _ := data["token"].(string)
	tokenID, _ := data["id"].(string)
	if rawToken == "" || tokenID == "" {
		t.Fatalf("created token response = %#v", data)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+rawToken)
	auth, err := app.compatAuthFromSession(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	if auth.OrganizationID != sessionAuth.OrganizationID || auth.APITokenID != tokenID || auth.CredentialKind != "api_token" {
		t.Fatalf("API token auth = %#v", auth)
	}
	if !hasCompatScope(auth.Scopes, "READ") {
		t.Fatalf("API token scopes = %#v", auth.Scopes)
	}
	listed, err := app.compatListAPITokens(context.Background(), sessionAuth)
	if err != nil {
		t.Fatal(err)
	}
	listEnvelope := listed.(map[string]any)
	rows := listEnvelope["data"].([]map[string]any)
	if len(rows) != 1 || rows[0]["id"] != tokenID {
		t.Fatalf("listed API tokens = %#v", rows)
	}
	if _, err := app.compatRevokeAPIToken(context.Background(), tokenID, sessionAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := app.compatAuthFromSession(context.Background(), header); err == nil {
		t.Fatal("revoked API token still authenticates")
	}
}

func TestNormalizeCompatAPITokenScopes(t *testing.T) {
	scopes, err := normalizeCompatAPITokenScopes([]string{"read", "WRITE", "read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 || scopes[0] != "READ" || scopes[1] != "WRITE" {
		t.Fatalf("scopes = %#v", scopes)
	}
	if _, err := normalizeCompatAPITokenScopes([]string{"ROOT"}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid scope code = %v, err = %v", connect.CodeOf(err), err)
	}
}
