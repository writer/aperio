package bootstrap

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	oauthProtectedResourceMetadataPath    = "/.well-known/oauth-protected-resource"
	oauthProtectedResourceMetadataMCPPath = "/.well-known/oauth-protected-resource/api/v1/mcp"
	oauthAuthorizationServerMetadataPath  = "/.well-known/oauth-authorization-server"
	oauthAuthorizePath                    = "/oauth/authorize"
	oauthTokenPath                        = "/oauth/token" // #nosec G101 -- HTTP route path, not a secret token.
	oauthRevokePath                       = "/oauth/revoke"
	cerebroMCPEndpointPath                = "/api/v1/mcp"
)

func (a *App) WithCerebroOAuthIssuerURL(issuerURL string) *App {
	a.cerebroOAuthIssuerURL = strings.TrimSpace(issuerURL)
	return a
}

func (a *App) handleOAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	issuer, resource, ok := a.cerebroOAuthDiscoveryConfig()
	if !ok {
		writeError(w, http.StatusNotFound, "Cerebro OAuth discovery is not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": compatCerebroMCPBearerMethods(),
		"scopes_supported":         []string{compatCerebroReadScope},
	})
}

func (a *App) handleOAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	issuer, _, ok := a.cerebroOAuthDiscoveryConfig()
	if !ok {
		writeError(w, http.StatusNotFound, "Cerebro OAuth discovery is not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + oauthAuthorizePath,
		"token_endpoint":                        issuer + oauthTokenPath,
		"revocation_endpoint":                   issuer + oauthRevokePath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 compatCerebroMCPGrantTypes(),
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{compatCerebroReadScope},
		"resource_indicators_supported":         true,
	})
}

func (a *App) cerebroOAuthDiscoveryConfigured() bool {
	_, _, ok := a.cerebroOAuthDiscoveryConfig()
	return ok
}

func (a *App) cerebroOAuthDiscoveryConfig() (string, string, bool) {
	if a == nil {
		return "", "", false
	}
	issuer := normalizeOAuthIssuerURL(a.cerebroOAuthIssuerURL)
	resource := normalizeAbsoluteURL(a.cerebroMCPServerURL)
	if issuer == "" || resource == "" {
		return "", "", false
	}
	return issuer, resource, true
}

func normalizeOAuthIssuerURL(raw string) string {
	base := normalizeAbsoluteURL(raw)
	if base == "" {
		return ""
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return ""
	}
	path := strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.HasSuffix(path, "/api"):
		path = strings.TrimSuffix(path, "/api")
	case hasVersionedAPIPathSuffix(path):
		path = path[:strings.LastIndex(path, "/api/")]
	}
	parsed.Path = path
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/")
}

func hasVersionedAPIPathSuffix(path string) bool {
	apiIndex := strings.LastIndex(path, "/api/")
	if apiIndex < 0 {
		return false
	}
	version := path[apiIndex+len("/api/"):]
	if len(version) < 2 || version[0] != 'v' || strings.Contains(version, "/") {
		return false
	}
	for _, ch := range version[1:] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func normalizeAbsoluteURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ""
	}
	return parsed.String()
}

func requestOrigin(r *http.Request) string {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}
