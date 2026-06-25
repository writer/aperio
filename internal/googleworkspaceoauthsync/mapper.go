package googleworkspaceoauthsync

import "strings"

// googleToken mirrors the subset of Google Directory API
// users.tokens.list payload the sync consumes. Intentionally narrow.
type googleToken struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Scopes      []string `json:"scopes"`
	UserKey     string   `json:"userKey"`
	Anonymous   bool     `json:"anonymous"`
	NativeApp   bool     `json:"nativeApp"`
}

type googleTokensResponse struct {
	Items []googleToken `json:"items"`
}

// parsedToken is the SQL-ready projection of a googleToken.
type parsedToken struct {
	ClientID  string
	Label     string
	Scopes    []string
	Anonymous bool
	NativeApp bool
}

func parseToken(t googleToken) parsedToken {
	return parsedToken{
		ClientID:  strings.TrimSpace(t.ClientID),
		Label:     strings.TrimSpace(t.DisplayText),
		Scopes:    append([]string(nil), t.Scopes...),
		Anonymous: t.Anonymous,
		NativeApp: t.NativeApp,
	}
}

// DisplayName returns the human-readable label that goes into both
// security_assets.name and oauth_app_grants.app_display_name. Falls back
// to the client id when Google did not return a friendly label.
func (p parsedToken) DisplayName() string {
	if p.Label != "" {
		return p.Label
	}
	return p.ClientID
}

// Summary renders a short, deterministic blurb for security_assets.summary
// that the Shadow IT page can show without an extra query. Lists the first
// few scopes to give the reader a quick sense of what the app can do.
func (p parsedToken) Summary() string {
	if len(p.Scopes) == 0 {
		return "Third-party OAuth app"
	}
	risk := googleOAuthAssetRisk(p.Scopes)
	preview := p.Scopes
	if len(preview) > 3 {
		preview = preview[:3]
	}
	suffix := ""
	if len(p.Scopes) > 3 {
		suffix = ", +" + itoa(len(p.Scopes)-3) + " more"
	}
	if len(risk.riskReasons) > 0 {
		return "Risk drivers: " + strings.Join(risk.riskReasons, "; ") + ". OAuth scopes: " + strings.Join(preview, ", ") + suffix
	}
	return "OAuth scopes: " + strings.Join(preview, ", ") + suffix
}

func mergeOAuthAppToken(existing, next parsedToken) parsedToken {
	merged := existing
	if merged.ClientID == "" {
		merged.ClientID = next.ClientID
	}
	if merged.Label == "" {
		merged.Label = next.Label
	}
	seen := map[string]struct{}{}
	scopes := make([]string, 0, len(existing.Scopes)+len(next.Scopes))
	for _, scope := range append(append([]string{}, existing.Scopes...), next.Scopes...) {
		key := strings.ToLower(strings.TrimSpace(scope))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		scopes = append(scopes, strings.TrimSpace(scope))
	}
	merged.Scopes = scopes
	merged.Anonymous = existing.Anonymous || next.Anonymous
	merged.NativeApp = existing.NativeApp || next.NativeApp
	return merged
}

type oauthAssetRisk struct {
	criticality           string
	riskScore             int
	containsSensitiveData bool
	isPrivileged          bool
	riskReasons           []string
}

func googleOAuthAssetRisk(scopes []string) oauthAssetRisk {
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "" {
			normalized = append(normalized, scope)
		}
	}
	if len(normalized) == 0 {
		return oauthAssetRisk{criticality: "LOW", riskScore: 10}
	}
	criticalScopeSet := map[string]struct{}{
		"https://mail.google.com/":                               {},
		"https://www.googleapis.com/auth/gmail.modify":           {},
		"https://www.googleapis.com/auth/gmail.insert":           {},
		"https://www.googleapis.com/auth/gmail.settings.basic":   {},
		"https://www.googleapis.com/auth/gmail.settings.sharing": {},
		"https://www.googleapis.com/auth/drive":                  {},
	}
	highScopeSet := map[string]struct{}{
		"https://www.googleapis.com/auth/gmail.readonly":                        {},
		"https://www.googleapis.com/auth/gmail.metadata":                        {},
		"https://www.googleapis.com/auth/gmail.send":                            {},
		"https://www.googleapis.com/auth/gmail.compose":                         {},
		"https://www.googleapis.com/auth/gmail.labels":                          {},
		"https://www.googleapis.com/auth/gmail.addons.current.message.readonly": {},
		"https://www.googleapis.com/auth/gmail.addons.current.message.action":   {},
		"https://www.googleapis.com/auth/gmail.addons.execute":                  {},
		"https://www.googleapis.com/auth/drive.readonly":                        {},
		"https://www.googleapis.com/auth/drive.file":                            {},
		"https://www.googleapis.com/auth/drive.metadata":                        {},
		"https://www.googleapis.com/auth/drive.metadata.readonly":               {},
		"https://www.googleapis.com/auth/admin.directory.user.readonly":         {},
		"https://www.googleapis.com/auth/admin.directory.group.readonly":        {},
		"https://www.googleapis.com/auth/cloud-platform":                        {},
		"https://www.googleapis.com/auth/bigquery":                              {},
	}
	criticalMatches := 0
	highMatches := 0
	highValueMatches := 0
	isPrivileged := false
	riskReasons := []string{}
	for _, scope := range normalized {
		if _, ok := criticalScopeSet[scope]; ok {
			criticalMatches++
		}
		if _, ok := highScopeSet[scope]; ok {
			highMatches++
		}
		switch {
		case scope == "https://mail.google.com/" ||
			strings.Contains(scope, "gmail.modify") ||
			strings.Contains(scope, "gmail.settings"):
			riskReasons = appendOAuthReason(riskReasons, "Full mailbox access")
		case strings.Contains(scope, "gmail.readonly") ||
			strings.Contains(scope, "gmail.metadata") ||
			strings.Contains(scope, "gmail.send") ||
			strings.Contains(scope, "gmail.compose"):
			riskReasons = appendOAuthReason(riskReasons, "Mailbox read/send access")
		}
		if scope == "https://www.googleapis.com/auth/drive" ||
			strings.Contains(scope, "/auth/drive.") {
			riskReasons = appendOAuthReason(riskReasons, "Google Drive file access")
		}
		if strings.Contains(scope, "admin") || strings.Contains(scope, "drive") || strings.Contains(scope, "directory") {
			highValueMatches++
		}
		if strings.Contains(scope, "admin") || strings.Contains(scope, "directory") {
			isPrivileged = true
			riskReasons = appendOAuthReason(riskReasons, "Directory or admin access")
		}
		if strings.Contains(scope, "cloud-platform") || strings.Contains(scope, "bigquery") {
			highValueMatches++
			riskReasons = appendOAuthReason(riskReasons, "Google Cloud data access")
		}
	}
	if criticalMatches > 0 {
		return oauthAssetRisk{criticality: "CRITICAL", riskScore: minOAuthRisk(97, 92+criticalMatches), containsSensitiveData: true, isPrivileged: isPrivileged, riskReasons: riskReasons}
	}
	if highMatches > 0 {
		return oauthAssetRisk{criticality: "HIGH", riskScore: minOAuthRisk(91, 84+highMatches), containsSensitiveData: true, isPrivileged: isPrivileged, riskReasons: riskReasons}
	}
	if highValueMatches > 0 {
		return oauthAssetRisk{criticality: "HIGH", riskScore: 82, containsSensitiveData: true, isPrivileged: isPrivileged, riskReasons: riskReasons}
	}
	return oauthAssetRisk{criticality: "MEDIUM", riskScore: 45}
}

func appendOAuthReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func minOAuthRisk(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = digits[n%10]
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
