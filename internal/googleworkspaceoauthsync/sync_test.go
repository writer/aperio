package googleworkspaceoauthsync

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTokenPreservesScopes(t *testing.T) {
	got := parseToken(googleToken{
		ClientID:    "  vendor-app  ",
		DisplayText: " Vendor Analytics ",
		Scopes:      []string{"drive.readonly", "gmail.metadata"},
		Anonymous:   false,
		NativeApp:   true,
	})
	if got.ClientID != "vendor-app" {
		t.Fatalf("ClientID trim: got %q", got.ClientID)
	}
	if got.Label != "Vendor Analytics" {
		t.Fatalf("Label trim: got %q", got.Label)
	}
	if got.NativeApp != true || got.Anonymous != false {
		t.Fatalf("flag passthrough wrong: %+v", got)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("Scopes len: got %d", len(got.Scopes))
	}
}

func TestDisplayNameFallsBackToClientID(t *testing.T) {
	if got := (parsedToken{ClientID: "abc.apps", Label: ""}).DisplayName(); got != "abc.apps" {
		t.Fatalf("DisplayName fallback: got %q", got)
	}
	if got := (parsedToken{ClientID: "abc", Label: "Acme"}).DisplayName(); got != "Acme" {
		t.Fatalf("DisplayName label: got %q", got)
	}
}

func TestSummaryTruncatesLongScopeLists(t *testing.T) {
	scopes := []string{"a", "b", "c", "d", "e"}
	got := (parsedToken{Scopes: scopes}).Summary()
	if !strings.Contains(got, "a, b, c") {
		t.Fatalf("Summary should include first 3 scopes: got %q", got)
	}
	if !strings.Contains(got, "+2 more") {
		t.Fatalf("Summary should report remainder: got %q", got)
	}
}

func TestSummaryHandlesEmptyScopes(t *testing.T) {
	if got := (parsedToken{}).Summary(); got != "Third-party OAuth app" {
		t.Fatalf("empty-scope summary: got %q", got)
	}
}

func TestSummaryIncludesRiskDriversForSensitiveScopes(t *testing.T) {
	got := (parsedToken{Scopes: []string{
		"https://mail.google.com/",
		"https://www.googleapis.com/auth/drive.readonly",
	}}).Summary()
	if !strings.Contains(got, "Risk drivers: Full mailbox access; Google Drive file access.") {
		t.Fatalf("summary should explain scope risk drivers: got %q", got)
	}
}

func TestGoogleOAuthAssetRiskScoresSensitiveScopes(t *testing.T) {
	cases := []struct {
		name        string
		scopes      []string
		criticality string
		riskFloor   int
		sensitive   bool
		privileged  bool
		reason      string
	}{
		{
			name:        "critical gmail",
			scopes:      []string{"https://mail.google.com/"},
			criticality: "CRITICAL",
			riskFloor:   92,
			sensitive:   true,
			reason:      "Full mailbox access",
		},
		{
			name:        "high gmail readonly",
			scopes:      []string{"https://www.googleapis.com/auth/gmail.readonly"},
			criticality: "HIGH",
			riskFloor:   84,
			sensitive:   true,
			reason:      "Mailbox read/send access",
		},
		{
			name:        "critical drive full access",
			scopes:      []string{"https://www.googleapis.com/auth/drive"},
			criticality: "CRITICAL",
			riskFloor:   92,
			sensitive:   true,
			reason:      "Google Drive file access",
		},
		{
			name:        "admin directory",
			scopes:      []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"},
			criticality: "HIGH",
			riskFloor:   82,
			sensitive:   true,
			privileged:  true,
			reason:      "Directory or admin access",
		},
		{
			name:        "cloud data",
			scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
			criticality: "HIGH",
			riskFloor:   82,
			sensitive:   true,
			reason:      "Google Cloud data access",
		},
		{
			name:        "basic profile",
			scopes:      []string{"openid", "email", "profile"},
			criticality: "MEDIUM",
			riskFloor:   45,
		},
		{
			name:        "empty",
			scopes:      nil,
			criticality: "LOW",
			riskFloor:   10,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := googleOAuthAssetRisk(c.scopes)
			if got.criticality != c.criticality || got.riskScore < c.riskFloor || got.containsSensitiveData != c.sensitive || got.isPrivileged != c.privileged {
				t.Fatalf("risk = %+v, want criticality=%s risk>=%d sensitive=%t privileged=%t", got, c.criticality, c.riskFloor, c.sensitive, c.privileged)
			}
			if c.reason != "" && !containsOAuthReason(got.riskReasons, c.reason) {
				t.Fatalf("risk reasons = %v, want %q", got.riskReasons, c.reason)
			}
		})
	}
}

func containsOAuthReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestMergeOAuthAppTokenAggregatesRiskScopes(t *testing.T) {
	low := parsedToken{ClientID: "client-1", Label: "Client One", Scopes: []string{"openid", "email"}}
	critical := parsedToken{ClientID: "client-1", Scopes: []string{"https://mail.google.com/", "openid"}}

	for _, merged := range []parsedToken{
		mergeOAuthAppToken(low, critical),
		mergeOAuthAppToken(critical, low),
	} {
		risk := googleOAuthAssetRisk(merged.Scopes)
		if risk.criticality != "CRITICAL" || risk.riskScore < 92 || !risk.containsSensitiveData {
			t.Fatalf("merged scopes %v produced risk %+v, want critical sensitive app", merged.Scopes, risk)
		}
		if got := strings.Join(merged.Scopes, ","); !strings.Contains(got, "openid") || !strings.Contains(got, "https://mail.google.com/") {
			t.Fatalf("merged scopes lost observed grants: %v", merged.Scopes)
		}
	}
}

// TestShortHashDistinguishesDistinctUserKeys pins the collision-resistance
// property the grant PK relies on. Two identities that share an empty
// external_id must derive distinct PK suffixes from their email userKey so
// upsertOauthGrant does not abort the sweep with a duplicate-key error on
// the second user under the same (integration, client) pair.
func TestShortHashDistinguishesDistinctUserKeys(t *testing.T) {
	a := shortHash("alice@example.test")
	b := shortHash("bob@example.test")
	if a == b {
		t.Fatalf("distinct emails must hash to distinct PK suffixes: %q == %q", a, b)
	}
	if shortHash("alice@example.test") != a {
		t.Fatal("shortHash must be deterministic")
	}
	if shortHash("") == shortHash("alice@example.test") {
		t.Fatal("empty userKey must not collide with a real one")
	}
	if len(a) != 12 {
		t.Fatalf("shortHash should produce a 12-char fragment, got %d", len(a))
	}
}

// TestGrantPKAndArbiterMoveTogether pins the invariant that the grant PK
// and the natural-key arbiter (user_email) move together so neither the
// recreate case (email reused, new external_id) nor the rename case
// (external_id stable, email changes) can wedge the sweep with an
// unabsorbable unique violation. The PK suffix must change iff the
// email-or-external-id key changes.
func TestGrantPKAndArbiterMoveTogether(t *testing.T) {
	pkFor := func(email, externalID string) string {
		key := email
		if key == "" {
			key = externalID
		}
		return shortHash(key)
	}
	// Recreate: same email, different external_id -> same PK -> arbiter
	// matches existing row, DO UPDATE absorbs.
	if pkFor("alice@example.test", "ext-old") != pkFor("alice@example.test", "ext-new") {
		t.Fatal("email-reuse / recreate must keep the PK stable so arbiter UPDATE absorbs the row")
	}
	// Rename: stable external_id, new email -> different PK -> fresh
	// INSERT (no PK collision), arbiter miss, new row.
	if pkFor("alice.old@example.test", "ext-1") == pkFor("alice.new@example.test", "ext-1") {
		t.Fatal("rename must produce a different PK so the fresh INSERT does not collide with the prior row")
	}
	// Empty-email fallback: still distinguishes two external_ids.
	if pkFor("", "ext-1") == pkFor("", "ext-2") {
		t.Fatal("empty-email fallback must distinguish distinct external_ids")
	}
}

func TestStringArrayLiteralEscapes(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "{}"},
		{[]string{}, "{}"},
		{[]string{"a", "b"}, `{"a","b"}`},
		{[]string{`with "quote"`}, `{"with \"quote\""}`},
		{[]string{`back\slash`}, `{"back\\slash"}`},
	}
	for _, c := range cases {
		if got := stringArrayLiteral(c.in); got != c.want {
			t.Errorf("stringArrayLiteral(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func FuzzStringArrayLiteralRoundTrip(f *testing.F) {
	for _, seed := range [][]string{
		nil,
		{""},
		{"a", "b"},
		{`with "quote"`},
		{`back\slash`},
		{"comma,value", "{brace}", "NULL"},
	} {
		f.Add(strings.Join(seed, "\x00"))
	}
	f.Fuzz(func(t *testing.T, joined string) {
		values := []string{}
		if joined != "" {
			values = strings.Split(joined, "\x00")
		}
		got, err := parseStringArrayLiteralForTest(stringArrayLiteral(values))
		if err != nil {
			t.Fatalf("parse array literal: %v", err)
		}
		if len(got) != len(values) {
			t.Fatalf("round trip length = %d, want %d (%q -> %q)", len(got), len(values), values, stringArrayLiteral(values))
		}
		for i := range values {
			if got[i] != values[i] {
				t.Fatalf("round trip[%d] = %q, want %q (%q)", i, got[i], values[i], stringArrayLiteral(values))
			}
		}
	})
}

func parseStringArrayLiteralForTest(literal string) ([]string, error) {
	if literal == "{}" {
		return nil, nil
	}
	if len(literal) < 2 || literal[0] != '{' || literal[len(literal)-1] != '}' {
		return nil, errors.New("invalid array literal")
	}
	body := literal[1 : len(literal)-1]
	values := []string{}
	for len(body) > 0 {
		if body[0] != '"' {
			return nil, errors.New("expected quoted element")
		}
		body = body[1:]
		var builder strings.Builder
		for {
			if len(body) == 0 {
				return nil, errors.New("unterminated quoted element")
			}
			ch := body[0]
			body = body[1:]
			if ch == '\\' {
				if len(body) == 0 {
					return nil, errors.New("trailing escape")
				}
				builder.WriteByte(body[0])
				body = body[1:]
				continue
			}
			if ch == '"' {
				values = append(values, builder.String())
				break
			}
			builder.WriteByte(ch)
		}
		if len(body) == 0 {
			break
		}
		if body[0] != ',' {
			return nil, errors.New("expected comma")
		}
		body = body[1:]
	}
	return values, nil
}
