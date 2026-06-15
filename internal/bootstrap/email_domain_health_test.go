package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"testing"
)

type fakeEmailDNSResolver struct {
	txt    map[string][]string
	txtErr map[string]error
	mx     map[string][]*net.MX
	mxErr  map[string]error
}

func (f fakeEmailDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.txtErr[name]; ok {
		return nil, err
	}
	return f.txt[name], nil
}

func (f fakeEmailDNSResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err, ok := f.mxErr[name]; ok {
		return nil, err
	}
	return f.mx[name], nil
}

func TestNormalizeDomainCandidate(t *testing.T) {
	cases := map[string]string{
		"example.com":                    "example.com",
		"Security@Example.COM":           "example.com",
		"https://mail.example.com/admin": "mail.example.com",
		"www.example.com":                "example.com",
		"tenant-id-without-dot":          "",
		"192.168.0.1":                    "",
		"":                               "",
	}
	for input, want := range cases {
		if got := normalizeDomainCandidate(input); got != want {
			t.Fatalf("normalizeDomainCandidate(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEvaluateEmailDomainHealthHealthy(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 256))
	resolver := fakeEmailDNSResolver{
		txt: map[string][]string{
			"example.com": {
				"v=spf1 include:_spf.google.com -all",
			},
			"_dmarc.example.com": {
				"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com",
			},
			"default._domainkey.example.com": {
				"v=DKIM1; k=rsa; p=" + key,
			},
		},
		mx: map[string][]*net.MX{
			"example.com": {
				{Host: "aspmx.l.google.com.", Pref: 1},
			},
		},
	}

	result := evaluateEmailDomainHealth(context.Background(), resolver, "example.com", []string{"GOOGLE_WORKSPACE"})
	if result.Status != "HEALTHY" {
		t.Fatalf("status = %s, want HEALTHY", result.Status)
	}
	if result.SPFStatus != "HEALTHY" {
		t.Fatalf("spf status = %s, want HEALTHY", result.SPFStatus)
	}
	if result.DKIMStatus != "HEALTHY" {
		t.Fatalf("dkim status = %s, want HEALTHY", result.DKIMStatus)
	}
	if result.DMARCStatus != "HEALTHY" {
		t.Fatalf("dmarc status = %s, want HEALTHY", result.DMARCStatus)
	}
	if result.IssueCount != 0 {
		t.Fatalf("issue count = %d, want 0", result.IssueCount)
	}
	if result.Payload.SPFLookups != 1 {
		t.Fatalf("spf lookups = %d, want 1", result.Payload.SPFLookups)
	}
	if len(result.Payload.DKIMSelectors) == 0 {
		t.Fatalf("expected at least one DKIM selector")
	}
}

func TestEvaluateEmailDomainHealthDetectsIssues(t *testing.T) {
	weakKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
	resolver := fakeEmailDNSResolver{
		txt: map[string][]string{
			"risky.example.com": {
				"v=spf1 +all",
			},
			"default._domainkey.risky.example.com": {
				"v=DKIM1; p=" + weakKey,
			},
		},
		txtErr: map[string]error{
			"_dmarc.risky.example.com": errors.New("not found"),
		},
		mx: map[string][]*net.MX{
			"risky.example.com": {},
		},
	}

	result := evaluateEmailDomainHealth(context.Background(), resolver, "risky.example.com", []string{"GOOGLE_WORKSPACE"})
	if result.Status != "FAILING" {
		t.Fatalf("status = %s, want FAILING", result.Status)
	}
	if result.FailingIssueCount == 0 {
		t.Fatalf("failing issues = 0, want > 0")
	}
	if !containsIssueCode(result.Payload.Issues, "spf_permissive_all") {
		t.Fatalf("expected spf_permissive_all issue, got %+v", result.Payload.Issues)
	}
	if !containsIssueCode(result.Payload.Issues, "dmarc_missing") {
		t.Fatalf("expected dmarc_missing issue, got %+v", result.Payload.Issues)
	}
	if !containsIssueCode(result.Payload.Issues, "dkim_weak_key") {
		t.Fatalf("expected dkim_weak_key issue, got %+v", result.Payload.Issues)
	}
}

func containsIssueCode(issues []emailDomainIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestDiscoverEmailDomainSourcesIncludesIdentityEmails(t *testing.T) {
	app, auth := newTestDBApp(t)
	ctx := context.Background()

	result, err := app.compatCreateIntegration(ctx, map[string]any{
		"provider":          "GOOGLE_WORKSPACE",
		"displayName":       "Google Workspace",
		"externalAccountId": "google-demo",
		"mode":              "READ_ONLY",
		"credentials": map[string]any{
			"accessToken": "access-token-12345",
		},
	}, auth)
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	integrationID := stringFromAny(asMap(asMap(result)["data"])["id"])
	if integrationID == "" {
		t.Fatal("missing integration id")
	}

	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO saas_identities (
			id, organization_id, integration_id, provider, external_id, email, kind, status,
			linked_asset_ids, is_privileged, is_external, risk_score, created_at, updated_at
		) VALUES ($1,$2,$3,'GOOGLE_WORKSPACE',$4,$5,'USER','ACTIVE',$6,FALSE,FALSE,0,NOW(),NOW())
	`, compatID("sid"), auth.OrganizationID, integrationID, "google:user:morgan-finance", "morgan.finance@acme.test", []string{}); err != nil {
		t.Fatalf("seed saas identity: %v", err)
	}

	sources, err := app.discoverEmailDomainSources(ctx, auth.OrganizationID)
	if err != nil {
		t.Fatalf("discover domains: %v", err)
	}
	found := false
	for _, source := range sources {
		if source.Domain == "acme.test" {
			found = true
			if len(source.Providers) != 1 || source.Providers[0] != "GOOGLE_WORKSPACE" {
				t.Fatalf("acme.test providers = %v, want [GOOGLE_WORKSPACE]", source.Providers)
			}
		}
	}
	if !found {
		t.Fatalf("expected acme.test in discovered domains, got %+v", sources)
	}
}

func TestEvaluateEmailDomainHealthFlagsMalformedPermissivePolicies(t *testing.T) {
	resolver := fakeEmailDNSResolver{
		txt: map[string][]string{
			"broken.example.com": {
				"v=spf1 ?all",
			},
			"_dmarc.broken.example.com": {
				"v=DMARC1; p=definitely-not-valid; rua=mailto:dmarc@example.com",
			},
			"default._domainkey.broken.example.com": {
				"v=DKIM1; p=not-valid-base64",
			},
		},
		mx: map[string][]*net.MX{
			"broken.example.com": {
				{Host: "mx1.example.com.", Pref: 10},
			},
		},
	}

	result := evaluateEmailDomainHealth(context.Background(), resolver, "broken.example.com", []string{"GOOGLE_WORKSPACE"})
	if result.Status != "FAILING" {
		t.Fatalf("status = %s, want FAILING", result.Status)
	}
	if !containsIssueCode(result.Payload.Issues, "spf_neutral_all") {
		t.Fatalf("expected spf_neutral_all issue, got %+v", result.Payload.Issues)
	}
	if !containsIssueCode(result.Payload.Issues, "dmarc_policy_invalid") {
		t.Fatalf("expected dmarc_policy_invalid issue, got %+v", result.Payload.Issues)
	}
	if !containsIssueCode(result.Payload.Issues, "dkim_invalid_key_material") {
		t.Fatalf("expected dkim_invalid_key_material issue, got %+v", result.Payload.Issues)
	}
}
