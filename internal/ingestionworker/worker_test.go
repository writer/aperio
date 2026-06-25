package ingestionworker

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/aperio/internal/telemetry"
)

type githubParityFixture struct {
	Positive struct {
		Payload         githubFixturePayload `json:"payload"`
		ExpectedFinding struct {
			RuleID      string         `json:"ruleId"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Severity    string         `json:"severity"`
			RiskScore   int            `json:"riskScore"`
			Target      string         `json:"target"`
			Evidence    map[string]any `json:"evidence"`
			DedupeKey   string         `json:"dedupeKey"`
		} `json:"expectedFinding"`
	} `json:"positive"`
	Alias struct {
		Payload githubFixturePayload `json:"payload"`
	} `json:"alias"`
	CanonicalPrivateNegative struct {
		Payload githubFixturePayload `json:"payload"`
	} `json:"canonicalPrivateNegative"`
	Negative struct {
		Payload githubFixturePayload `json:"payload"`
	} `json:"negative"`
	DisabledCheck string `json:"disabledCheck"`
}

type githubFixturePayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor"`
	OccurredAt     string         `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

type slackParityFixture struct {
	Positive struct {
		Payload         slackFixturePayload `json:"payload"`
		ExpectedFinding struct {
			RuleID      string         `json:"ruleId"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Severity    string         `json:"severity"`
			RiskScore   int            `json:"riskScore"`
			Target      string         `json:"target"`
			Evidence    map[string]any `json:"evidence"`
			DedupeKey   string         `json:"dedupeKey"`
		} `json:"expectedFinding"`
	} `json:"positive"`
	Alias struct {
		Payload slackFixturePayload `json:"payload"`
	} `json:"alias"`
	Negative struct {
		Payload slackFixturePayload `json:"payload"`
	} `json:"negative"`
	DisabledCheck string `json:"disabledCheck"`
}

type slackFixturePayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor"`
	OccurredAt     string         `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

type oktaParityFixture struct {
	Positive struct {
		Payload         oktaFixturePayload `json:"payload"`
		ExpectedFinding struct {
			RuleID      string         `json:"ruleId"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Severity    string         `json:"severity"`
			RiskScore   int            `json:"riskScore"`
			Target      string         `json:"target"`
			Evidence    map[string]any `json:"evidence"`
			DedupeKey   string         `json:"dedupeKey"`
		} `json:"expectedFinding"`
	} `json:"positive"`
	Aliases []struct {
		Payload oktaFixturePayload `json:"payload"`
	} `json:"aliases"`
	Negative struct {
		Payload oktaFixturePayload `json:"payload"`
	} `json:"negative"`
	AdditionalNegatives []struct {
		Name    string             `json:"name"`
		Payload oktaFixturePayload `json:"payload"`
	} `json:"additionalNegatives"`
	DisabledCheck string `json:"disabledCheck"`
}

type oktaFixturePayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor"`
	OccurredAt     string         `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

type googleRulesFixture struct {
	Rules []googleParityFixture `json:"rules"`
}

type googleParityFixture struct {
	RuleID   string `json:"ruleId"`
	Positive struct {
		Payload         googleFixturePayload `json:"payload"`
		ExpectedFinding struct {
			RuleID      string         `json:"ruleId"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Severity    string         `json:"severity"`
			RiskScore   int            `json:"riskScore"`
			Target      string         `json:"target"`
			Evidence    map[string]any `json:"evidence"`
			DedupeKey   string         `json:"dedupeKey"`
		} `json:"expectedFinding"`
	} `json:"positive"`
	Variants []struct {
		Name            string               `json:"name"`
		Payload         googleFixturePayload `json:"payload"`
		ExpectedFinding struct {
			RuleID      string         `json:"ruleId"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Severity    string         `json:"severity"`
			RiskScore   int            `json:"riskScore"`
			Target      string         `json:"target"`
			Evidence    map[string]any `json:"evidence"`
			DedupeKey   string         `json:"dedupeKey"`
		} `json:"expectedFinding"`
	} `json:"variants"`
	Negative struct {
		Payload googleFixturePayload `json:"payload"`
	} `json:"negative"`
	AdditionalNegatives []struct {
		Name    string               `json:"name"`
		Payload googleFixturePayload `json:"payload"`
	} `json:"additionalNegatives"`
	DisabledCheck string `json:"disabledCheck"`
}

type googleFixturePayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor"`
	OccurredAt     string         `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

func readGitHubParityFixture(t *testing.T) githubParityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "github-public-repository.json"))
	if err != nil {
		t.Fatalf("read GitHub parity fixture: %v", err)
	}
	var fixture githubParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode GitHub parity fixture: %v", err)
	}
	return fixture
}

func readSlackParityFixture(t *testing.T) slackParityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "slack-mfa-disabled.json"))
	if err != nil {
		t.Fatalf("read Slack parity fixture: %v", err)
	}
	var fixture slackParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode Slack parity fixture: %v", err)
	}
	return fixture
}

func readOktaParityFixture(t *testing.T, name string) oktaParityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", name))
	if err != nil {
		t.Fatalf("read Okta parity fixture %s: %v", name, err)
	}
	var fixture oktaParityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode Okta parity fixture %s: %v", name, err)
	}
	return fixture
}

func readOktaParityFixtures(t *testing.T) []oktaParityFixture {
	t.Helper()
	fixtureNames := []string{
		"okta-admin-role-assigned.json",
		"okta-mfa-factor-reset.json",
		"okta-password-policy-weakened.json",
		"okta-suspicious-signin.json",
	}
	fixtures := make([]oktaParityFixture, 0, len(fixtureNames))
	for _, name := range fixtureNames {
		fixtures = append(fixtures, readOktaParityFixture(t, name))
	}
	return fixtures
}

func readGoogleParityFixtures(t *testing.T) []googleParityFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "google-admin-oauth-rules.json"))
	if err != nil {
		t.Fatalf("read Google Workspace parity fixture: %v", err)
	}
	var fixture googleRulesFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode Google Workspace parity fixture: %v", err)
	}
	return fixture.Rules
}

func TestNormalizeEventTypeMatchesTypeScriptReference(t *testing.T) {
	cases := map[string]string{
		"repository.publicized":             "REPOSITORY_PUBLICIZED",
		" two-factor auth disabled ":        "TWO_FACTOR_AUTH_DISABLED",
		"//public-repository-created/":      "PUBLIC_REPOSITORY_CREATED",
		"mfa.disabled":                      "MFA_DISABLED",
		"user.account.privilege.grant":      "USER_ACCOUNT_PRIVILEGE_GRANT",
		"user.mfa.factor.reset_all":         "USER_MFA_FACTOR_RESET_ALL",
		"policy.lifecycle.update":           "POLICY_LIFECYCLE_UPDATE",
		"user.session.start":                "USER_SESSION_START",
		"external.sharing.enabled":          "EXTERNAL_SHARING_ENABLED",
		"risky.oauth.grant":                 "RISKY_OAUTH_GRANT",
		"email.forwarding.enabled":          "EMAIL_FORWARDING_ENABLED",
		"mailbox.delegation.granted":        "MAILBOX_DELEGATION_GRANTED",
		"legacy.mail.auth.used":             "LEGACY_MAIL_AUTH_USED",
		"forwarding.delegate.send.as.combo": "FORWARDING_DELEGATE_SEND_AS_COMBO",
	}
	for input, want := range cases {
		if got := normalizeEventType(input); got != want {
			t.Fatalf("normalizeEventType(%q) = %q, want %q", input, got, want)
		}
	}
}

func (p githubFixturePayload) jobPayload(t *testing.T) JobPayload {
	t.Helper()
	occurredAt, err := time.Parse(time.RFC3339Nano, p.OccurredAt)
	if err != nil {
		t.Fatalf("parse fixture occurredAt: %v", err)
	}
	return JobPayload{
		OrganizationID: p.OrganizationID,
		IntegrationID:  p.IntegrationID,
		Provider:       p.Provider,
		EventType:      p.EventType,
		Source:         p.Source,
		Actor:          p.Actor,
		OccurredAt:     occurredAt,
		Payload:        p.Payload,
	}
}

func (p slackFixturePayload) jobPayload(t *testing.T) JobPayload {
	t.Helper()
	occurredAt, err := time.Parse(time.RFC3339Nano, p.OccurredAt)
	if err != nil {
		t.Fatalf("parse fixture occurredAt: %v", err)
	}
	return JobPayload{
		OrganizationID: p.OrganizationID,
		IntegrationID:  p.IntegrationID,
		Provider:       p.Provider,
		EventType:      p.EventType,
		Source:         p.Source,
		Actor:          p.Actor,
		OccurredAt:     occurredAt,
		Payload:        p.Payload,
	}
}

func (p oktaFixturePayload) jobPayload(t *testing.T) JobPayload {
	t.Helper()
	occurredAt, err := time.Parse(time.RFC3339Nano, p.OccurredAt)
	if err != nil {
		t.Fatalf("parse fixture occurredAt: %v", err)
	}
	return JobPayload{
		OrganizationID: p.OrganizationID,
		IntegrationID:  p.IntegrationID,
		Provider:       p.Provider,
		EventType:      p.EventType,
		Source:         p.Source,
		Actor:          p.Actor,
		OccurredAt:     occurredAt,
		Payload:        p.Payload,
	}
}

func (p googleFixturePayload) jobPayload(t *testing.T) JobPayload {
	t.Helper()
	occurredAt, err := time.Parse(time.RFC3339Nano, p.OccurredAt)
	if err != nil {
		t.Fatalf("parse fixture occurredAt: %v", err)
	}
	return JobPayload{
		OrganizationID: p.OrganizationID,
		IntegrationID:  p.IntegrationID,
		Provider:       p.Provider,
		EventType:      p.EventType,
		Source:         p.Source,
		Actor:          p.Actor,
		OccurredAt:     occurredAt,
		Payload:        p.Payload,
	}
}

func assertJSONEqual(t *testing.T, got any, want any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got JSON: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want JSON: %v", err)
	}
	var gotNormalized any
	var wantNormalized any
	if err := json.Unmarshal(gotJSON, &gotNormalized); err != nil {
		t.Fatalf("normalize got JSON: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantNormalized); err != nil {
		t.Fatalf("normalize want JSON: %v", err)
	}
	if !reflect.DeepEqual(gotNormalized, wantNormalized) {
		t.Fatalf("JSON mismatch: got %#v, want %#v", gotNormalized, wantNormalized)
	}
}

func TestEvaluateGitHubPublicRepository(t *testing.T) {
	fixture := readGitHubParityFixture(t)
	payload := fixture.Positive.Payload.jobPayload(t)
	findings := Evaluate(payload, nil)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
		t.Fatalf("rule id = %s", findings[0].RuleID)
	}
	if findings[0].Title != fixture.Positive.ExpectedFinding.Title {
		t.Fatalf("title = %s", findings[0].Title)
	}
	if findings[0].Description != fixture.Positive.ExpectedFinding.Description {
		t.Fatalf("description = %s", findings[0].Description)
	}
	if findings[0].Target != fixture.Positive.ExpectedFinding.Target {
		t.Fatalf("target = %s", findings[0].Target)
	}
	if findings[0].Severity != fixture.Positive.ExpectedFinding.Severity || findings[0].RiskScore != fixture.Positive.ExpectedFinding.RiskScore {
		t.Fatalf("unexpected severity/risk: %#v", findings[0])
	}
	if !reflect.DeepEqual(findings[0].Evidence, fixture.Positive.ExpectedFinding.Evidence) {
		t.Fatalf("evidence = %#v, want %#v", findings[0].Evidence, fixture.Positive.ExpectedFinding.Evidence)
	}

	aliasFindings := Evaluate(fixture.Alias.Payload.jobPayload(t), nil)
	if len(aliasFindings) != 1 || aliasFindings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
		t.Fatalf("expected canonical event alias to produce GitHub public repository finding, got %#v", aliasFindings)
	}
	if got := Evaluate(fixture.CanonicalPrivateNegative.Payload.jobPayload(t), nil); len(got) != 0 {
		t.Fatalf("expected canonical private repository-created payload to produce no findings, got %#v", got)
	}
	if got := Evaluate(fixture.Negative.Payload.jobPayload(t), nil); len(got) != 0 {
		t.Fatalf("expected private repository negative to produce no findings, got %#v", got)
	}
	if got := Evaluate(payload, []string{fixture.DisabledCheck}); len(got) != 0 {
		t.Fatalf("expected disabled check to produce no findings, got %#v", got)
	}
}

func TestEvaluateSlackMFADisabled(t *testing.T) {
	fixture := readSlackParityFixture(t)
	payload := fixture.Positive.Payload.jobPayload(t)
	findings := Evaluate(payload, nil)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
		t.Fatalf("rule id = %s", findings[0].RuleID)
	}
	if findings[0].Title != fixture.Positive.ExpectedFinding.Title {
		t.Fatalf("title = %s", findings[0].Title)
	}
	if findings[0].Description != fixture.Positive.ExpectedFinding.Description {
		t.Fatalf("description = %s", findings[0].Description)
	}
	if findings[0].Target != fixture.Positive.ExpectedFinding.Target {
		t.Fatalf("target = %s", findings[0].Target)
	}
	if findings[0].Severity != fixture.Positive.ExpectedFinding.Severity || findings[0].RiskScore != fixture.Positive.ExpectedFinding.RiskScore {
		t.Fatalf("unexpected severity/risk: %#v", findings[0])
	}
	if !reflect.DeepEqual(findings[0].Evidence, fixture.Positive.ExpectedFinding.Evidence) {
		t.Fatalf("evidence = %#v, want %#v", findings[0].Evidence, fixture.Positive.ExpectedFinding.Evidence)
	}
	if got := DedupeKey(payload, findings[0]); got != fixture.Positive.ExpectedFinding.DedupeKey {
		t.Fatalf("dedupe key = %s, want TS-compatible hash", got)
	}

	aliasFindings := Evaluate(fixture.Alias.Payload.jobPayload(t), nil)
	if len(aliasFindings) != 1 || aliasFindings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
		t.Fatalf("expected two-factor auth alias to produce Slack MFA finding, got %#v", aliasFindings)
	}
	if got := Evaluate(fixture.Negative.Payload.jobPayload(t), nil); len(got) != 0 {
		t.Fatalf("expected unrelated Slack event to produce no findings, got %#v", got)
	}
	if got := Evaluate(payload, []string{fixture.DisabledCheck}); len(got) != 0 {
		t.Fatalf("expected disabled check to produce no findings, got %#v", got)
	}
}

func TestEvaluateOktaRules(t *testing.T) {
	for _, fixture := range readOktaParityFixtures(t) {
		t.Run(fixture.Positive.ExpectedFinding.RuleID, func(t *testing.T) {
			payload := fixture.Positive.Payload.jobPayload(t)
			findings := Evaluate(payload, nil)
			if len(findings) != 1 {
				t.Fatalf("expected one finding, got %d", len(findings))
			}
			finding := findings[0]
			if finding.RuleID != fixture.Positive.ExpectedFinding.RuleID {
				t.Fatalf("rule id = %s", finding.RuleID)
			}
			if finding.Title != fixture.Positive.ExpectedFinding.Title {
				t.Fatalf("title = %s", finding.Title)
			}
			if finding.Description != fixture.Positive.ExpectedFinding.Description {
				t.Fatalf("description = %s", finding.Description)
			}
			if finding.Target != fixture.Positive.ExpectedFinding.Target {
				t.Fatalf("target = %s", finding.Target)
			}
			if finding.Severity != fixture.Positive.ExpectedFinding.Severity || finding.RiskScore != fixture.Positive.ExpectedFinding.RiskScore {
				t.Fatalf("unexpected severity/risk: %#v", finding)
			}
			assertJSONEqual(t, finding.Evidence, fixture.Positive.ExpectedFinding.Evidence)
			if got := DedupeKey(payload, finding); got != fixture.Positive.ExpectedFinding.DedupeKey {
				t.Fatalf("dedupe key = %s, want TS-compatible hash", got)
			}
			for _, alias := range fixture.Aliases {
				aliasFindings := Evaluate(alias.Payload.jobPayload(t), nil)
				if len(aliasFindings) != 1 || aliasFindings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
					t.Fatalf("expected alias %s to produce %s finding, got %#v", alias.Payload.EventType, fixture.Positive.ExpectedFinding.RuleID, aliasFindings)
				}
			}
			if got := Evaluate(fixture.Negative.Payload.jobPayload(t), nil); len(got) != 0 {
				t.Fatalf("expected negative fixture to produce no findings, got %#v", got)
			}
			for _, negative := range fixture.AdditionalNegatives {
				if got := Evaluate(negative.Payload.jobPayload(t), nil); len(got) != 0 {
					t.Fatalf("expected negative fixture %q to produce no findings, got %#v", negative.Name, got)
				}
			}
			if got := Evaluate(payload, []string{fixture.DisabledCheck}); len(got) != 0 {
				t.Fatalf("expected disabled check to produce no findings, got %#v", got)
			}
		})
	}
}

func TestEvaluateGoogleWorkspaceAdminOAuthRules(t *testing.T) {
	for _, fixture := range readGoogleParityFixtures(t) {
		t.Run(fixture.Positive.ExpectedFinding.RuleID, func(t *testing.T) {
			payload := fixture.Positive.Payload.jobPayload(t)
			findings := Evaluate(payload, nil)
			if len(findings) != 1 {
				t.Fatalf("expected one finding, got %d", len(findings))
			}
			finding := findings[0]
			if finding.RuleID != fixture.Positive.ExpectedFinding.RuleID {
				t.Fatalf("rule id = %s", finding.RuleID)
			}
			if finding.Title != fixture.Positive.ExpectedFinding.Title {
				t.Fatalf("title = %s", finding.Title)
			}
			if finding.Description != fixture.Positive.ExpectedFinding.Description {
				t.Fatalf("description = %s", finding.Description)
			}
			if finding.Target != fixture.Positive.ExpectedFinding.Target {
				t.Fatalf("target = %s", finding.Target)
			}
			if finding.Severity != fixture.Positive.ExpectedFinding.Severity || finding.RiskScore != fixture.Positive.ExpectedFinding.RiskScore {
				t.Fatalf("unexpected severity/risk: %#v", finding)
			}
			assertJSONEqual(t, finding.Evidence, fixture.Positive.ExpectedFinding.Evidence)
			if got := DedupeKey(payload, finding); got != fixture.Positive.ExpectedFinding.DedupeKey {
				t.Fatalf("dedupe key = %s, want TS-compatible hash", got)
			}
			for _, variant := range fixture.Variants {
				variantPayload := variant.Payload.jobPayload(t)
				variantFindings := Evaluate(variantPayload, nil)
				if len(variantFindings) != 1 || variantFindings[0].RuleID != fixture.Positive.ExpectedFinding.RuleID {
					t.Fatalf("expected variant %q to produce %s finding, got %#v", variant.Name, fixture.Positive.ExpectedFinding.RuleID, variantFindings)
				}
				variantFinding := variantFindings[0]
				if variantFinding.Title != variant.ExpectedFinding.Title ||
					variantFinding.Description != variant.ExpectedFinding.Description ||
					variantFinding.Target != variant.ExpectedFinding.Target ||
					variantFinding.Severity != variant.ExpectedFinding.Severity ||
					variantFinding.RiskScore != variant.ExpectedFinding.RiskScore {
					t.Fatalf("variant %q finding = %#v, want %#v", variant.Name, variantFinding, variant.ExpectedFinding)
				}
				assertJSONEqual(t, variantFinding.Evidence, variant.ExpectedFinding.Evidence)
				if got := DedupeKey(variantPayload, variantFinding); got != variant.ExpectedFinding.DedupeKey {
					t.Fatalf("variant %q dedupe key = %s, want TS-compatible hash", variant.Name, got)
				}
			}
			if got := Evaluate(fixture.Negative.Payload.jobPayload(t), nil); len(got) != 0 {
				t.Fatalf("expected negative fixture to produce no findings, got %#v", got)
			}
			for _, negative := range fixture.AdditionalNegatives {
				if got := Evaluate(negative.Payload.jobPayload(t), nil); len(got) != 0 {
					t.Fatalf("expected negative fixture %q to produce no findings, got %#v", negative.Name, got)
				}
			}
			if got := Evaluate(payload, []string{fixture.DisabledCheck}); len(got) != 0 {
				t.Fatalf("expected disabled check to produce no findings, got %#v", got)
			}
		})
	}
}

func TestDedupeKeyIsStableAcrossObservations(t *testing.T) {
	fixture := readGitHubParityFixture(t)
	payload := fixture.Positive.Payload.jobPayload(t)
	finding := Finding{RuleID: fixture.Positive.ExpectedFinding.RuleID, Target: fixture.Positive.ExpectedFinding.Target}
	first := DedupeKey(payload, finding)
	second := DedupeKey(payload, finding)
	if first == "" || first != second {
		t.Fatalf("dedupe key not stable: %q %q", first, second)
	}
	if first != fixture.Positive.ExpectedFinding.DedupeKey {
		t.Fatalf("dedupe key = %s, want TS-compatible hash", first)
	}
	payload.EventType = "OTHER_EVENT"
	if DedupeKey(payload, finding) != first {
		t.Fatal("dedupe key should exclude event type so repeated observations update the same finding")
	}
	payload.Provider = "SLACK"
	if DedupeKey(payload, finding) != first {
		t.Fatal("dedupe key should exclude provider to match the TypeScript worker")
	}
	oktaFixture := readOktaParityFixture(t, "okta-admin-role-assigned.json")
	oktaPayload := oktaFixture.Positive.Payload.jobPayload(t)
	oktaFinding := Evaluate(oktaPayload, nil)[0]
	if got := DedupeKey(oktaPayload, oktaFinding); got != oktaFixture.Positive.ExpectedFinding.DedupeKey {
		t.Fatalf("Okta dedupe key = %s, want TS-compatible dedupeTarget hash", got)
	}
	googleFixture := readGoogleParityFixtures(t)[3]
	googlePayload := googleFixture.Variants[2].Payload.jobPayload(t)
	googleFinding := Evaluate(googlePayload, nil)[0]
	if got := DedupeKey(googlePayload, googleFinding); got != googleFixture.Variants[2].ExpectedFinding.DedupeKey {
		t.Fatalf("Google risky OAuth empty-scope dedupe key = %s, want TS-compatible dedupeTarget hash", got)
	}
}

func TestFindingPayloadAddsOAuthClaimContext(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org-oauth",
		IntegrationID:  "int-google",
		Provider:       "GOOGLE_WORKSPACE",
		EventType:      "RISKY_OAUTH_GRANT",
		Source:         "google_admin_reports",
		Actor:          "analyst@example.com",
		OccurredAt:     time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
	}
	finding := Finding{
		RuleID:      "google_workspace.risky_oauth_grant",
		Title:       "Critical Gmail-scoped OAuth grant",
		Description: "A Google Workspace user granted a third-party OAuth client access to sensitive Google scopes.",
		Severity:    SeverityCritical,
		RiskScore:   97,
		Target:      "Vendor Mail App",
		Tags:        []string{TagOAuthRiskyGrant, TagDataAccess},
		Evidence: map[string]any{
			"appName":    "Vendor Mail App",
			"clientId":   "client-123",
			"clientType": "WEB",
			"scopes":     []string{"https://mail.google.com/", "https://www.googleapis.com/auth/drive.file"},
			"riskReason": "Granted full mailbox or mailbox-settings access",
		},
	}
	delivery := findingPayload(payload, finding, "evt-oauth", persistedFinding{ID: "fnd-oauth", Status: "OPEN"})

	requireRecordString(t, delivery.Record, "oauthAppId", "client-123")
	requireRecordString(t, delivery.Record, "oauthAppName", "Vendor Mail App")
	requireRecordString(t, delivery.Record, "oauthClientType", "WEB")
	requireRecordString(t, delivery.Record, "oauthRiskReason", "Granted full mailbox or mailbox-settings access")
	requireRecordString(t, delivery.Record, "oauthUserEmail", "analyst@example.com")
	requireRecordNumber(t, delivery.Record, "oauthScopeCount", 2)
	if scopes := stringArray(delivery.Record["oauthScopes"]); !reflect.DeepEqual(scopes, []string{"https://mail.google.com/", "https://www.googleapis.com/auth/drive.file"}) {
		t.Fatalf("oauthScopes = %#v", delivery.Record["oauthScopes"])
	}
}

func TestIngestionJobWideEventCoversOutcomesWithoutSecrets(t *testing.T) {
	base := job{
		ID:             "job_1",
		OrganizationID: "org_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Attempts:       0,
		MaxAttempts:    3,
	}
	success := ingestionJobWideEvent(base, nil, 7*time.Millisecond)
	if success.Name != "ingestion.job.process" || success.Service != "ingestion-worker" {
		t.Fatalf("unexpected telemetry identity: %#v", success)
	}
	if success.Organization != "org_1" || success.Dimensions["outcome"] != "succeeded" || success.Dimensions["provider"] != "GITHUB" || success.Dimensions["event_type"] != "PUBLIC_REPOSITORY_CREATED" {
		t.Fatalf("unexpected success dimensions: %#v", success.Dimensions)
	}
	if success.Measurements["attempt"] != 1 || success.Measurements["max_attempts"] != 3 || success.Measurements["duration_ms"] != 7 {
		t.Fatalf("unexpected success measurements: %#v", success.Measurements)
	}
	if _, ok := success.Dimensions["error_kind"]; ok {
		t.Fatalf("success telemetry should not include error_kind: %#v", success.Dimensions)
	}

	retry := ingestionJobWideEvent(base, errors.New("database password should not be serialized"), time.Millisecond)
	if retry.Dimensions["outcome"] != "failed" || retry.Dimensions["error_kind"] != "error" {
		t.Fatalf("unexpected retry telemetry: %#v", retry.Dimensions)
	}
	if strings.Contains(fmt.Sprint(retry.Dimensions), "password") {
		t.Fatalf("telemetry dimensions leaked raw error text: %#v", retry.Dimensions)
	}

	deadLetterJob := base
	deadLetterJob.Attempts = 2
	deadLetter := ingestionJobWideEvent(deadLetterJob, errors.New("boom"), time.Millisecond)
	if deadLetter.Dimensions["outcome"] != "dead_letter" || deadLetter.Measurements["attempt"] != 3 {
		t.Fatalf("unexpected dead-letter telemetry: %#v %#v", deadLetter.Dimensions, deadLetter.Measurements)
	}

	lostLease := ingestionJobWideEvent(base, errIngestionLeaseLost, time.Millisecond)
	if lostLease.Dimensions["outcome"] != "lost_lease" || lostLease.Dimensions["error_kind"] != "lease_lost" {
		t.Fatalf("unexpected lost-lease telemetry: %#v", lostLease.Dimensions)
	}

	unsupported := ingestionJobWideEvent(base, errUnsupportedIngestionWork, time.Millisecond)
	if unsupported.Dimensions["outcome"] != "dead_letter" || unsupported.Dimensions["error_kind"] != "unsupported" {
		t.Fatalf("unexpected unsupported-work telemetry: %#v", unsupported.Dimensions)
	}

	var sink bytes.Buffer
	restore := telemetry.SetOutput(&sink)
	emitIngestionJobWideEvent(base, nil, time.Millisecond)
	restore()
	if !strings.Contains(sink.String(), `"event_name":"ingestion.job.process"`) || strings.Contains(sink.String(), "password") {
		t.Fatalf("unexpected emitted telemetry: %s", sink.String())
	}
}

func TestIntegrationConfigValidatesProviderCredentialShapes(t *testing.T) {
	ensureIngestionWorkerTestEncryptionKey(t)
	baseJob := func(provider, eventType string) job {
		return job{
			ID:             "job_1",
			OrganizationID: "org_1",
			IntegrationID:  "int_1",
			Provider:       provider,
			EventType:      eventType,
		}
	}
	baseConfig := func(provider string, legacy bool) integrationConfig {
		return integrationConfig{
			ID:                     "int_1",
			OrganizationID:         "org_1",
			Provider:               provider,
			ExternalAccountID:      "acct_1",
			EncryptedAccessToken:   encryptIngestionWorkerSecret(t, "org_1", "int_1", provider, "acct_1", "access_token", testIngestionWorkerAccessToken, legacy),
			EncryptedRefreshToken:  sql.NullString{String: encryptIngestionWorkerSecret(t, "org_1", "int_1", provider, "acct_1", "refresh_token", testIngestionWorkerRefreshToken, legacy), Valid: true},
			EncryptedWebhookSecret: sql.NullString{String: encryptIngestionWorkerSecret(t, "org_1", "int_1", provider, "acct_1", "webhook_secret", testIngestionWorkerWebhookSecret, legacy), Valid: true},
		}
	}

	t.Run("GitHub canonical credential envelope with refresh and webhook succeeds", func(t *testing.T) {
		config := baseConfig("GITHUB", false)
		if err := config.validateForJob(baseJob("GITHUB", "PUBLIC_REPOSITORY_CREATED")); err != nil {
			t.Fatalf("validate GitHub canonical config: %v", err)
		}
	})

	t.Run("GitHub legacy credential envelope with refresh and webhook succeeds", func(t *testing.T) {
		config := baseConfig("GITHUB", true)
		if err := config.validateForJob(baseJob("GITHUB", "PUBLIC_REPOSITORY_CREATED")); err != nil {
			t.Fatalf("validate GitHub legacy config: %v", err)
		}
	})

	t.Run("Slack access token without optional secrets succeeds", func(t *testing.T) {
		config := integrationConfig{
			ID:                   "int_1",
			OrganizationID:       "org_1",
			Provider:             "SLACK",
			ExternalAccountID:    "acct_1",
			EncryptedAccessToken: encryptIngestionWorkerSecret(t, "org_1", "int_1", "SLACK", "acct_1", "access_token", testIngestionWorkerAccessToken, false),
		}
		if err := config.validateForJob(baseJob("SLACK", "MFA_DISABLED")); err != nil {
			t.Fatalf("validate Slack access-only config: %v", err)
		}
	})

	t.Run("Okta missing refresh token fails provider config validation", func(t *testing.T) {
		config := baseConfig("OKTA", false)
		config.EncryptedRefreshToken = sql.NullString{}
		if err := config.validateForJob(baseJob("OKTA", "ADMIN_ROLE_ASSIGNED")); !errors.Is(err, errIntegrationConfigurationIncomplete) {
			t.Fatalf("Okta missing refresh error = %v", err)
		}
	})

	t.Run("tampered refresh token fails closed", func(t *testing.T) {
		config := baseConfig("GITHUB", false)
		config.EncryptedRefreshToken = sql.NullString{String: tamperIngestionWorkerEnvelopeTag(t, config.EncryptedRefreshToken.String), Valid: true}
		if err := config.validateForJob(baseJob("GITHUB", "PUBLIC_REPOSITORY_CREATED")); !errors.Is(err, errIntegrationCredentialUnavailable) {
			t.Fatalf("tampered refresh error = %v", err)
		}
	})

	t.Run("tampered webhook secret fails closed", func(t *testing.T) {
		config := baseConfig("SLACK", false)
		config.EncryptedWebhookSecret = sql.NullString{String: tamperIngestionWorkerEnvelopeTag(t, config.EncryptedWebhookSecret.String), Valid: true}
		if err := config.validateForJob(baseJob("SLACK", "MFA_DISABLED")); !errors.Is(err, errIntegrationCredentialUnavailable) {
			t.Fatalf("tampered webhook error = %v", err)
		}
	})

	t.Run("Google OAuth-only mailbox audit events do not require service account scan config", func(t *testing.T) {
		for _, eventType := range []string{
			"EMAIL_FORWARDING_ENABLED",
			"MAILBOX_DELEGATION_GRANTED",
			"LEGACY_MAIL_AUTH_USED",
			"FORWARDING_DELEGATE_SEND_AS_COMBO",
		} {
			config := baseConfig("GOOGLE_WORKSPACE", false)
			if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", eventType)); err != nil {
				t.Fatalf("validate Google OAuth-only config for %s: %v", eventType, err)
			}
		}
	})

	t.Run("Google mailbox canonical service account config succeeds", func(t *testing.T) {
		config := baseConfig("GOOGLE_WORKSPACE", false)
		config.GoogleMailboxScanClientEmail = sql.NullString{String: "mailbox-scanner@example.com", Valid: true}
		config.EncryptedGoogleMailboxScanPrivateKey = sql.NullString{
			String: encryptIngestionWorkerMailboxKey(t, "org_1", "int_1", "acct_1", testIngestionWorkerMailboxPrivKey, false),
			Valid:  true,
		}
		if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", "EMAIL_FORWARDING_ENABLED")); err != nil {
			t.Fatalf("validate Google mailbox canonical config: %v", err)
		}
	})

	t.Run("Google mailbox legacy service account config succeeds", func(t *testing.T) {
		config := baseConfig("GOOGLE_WORKSPACE", true)
		config.GoogleMailboxScanClientEmail = sql.NullString{String: "mailbox-scanner@example.com", Valid: true}
		config.EncryptedGoogleMailboxScanPrivateKey = sql.NullString{
			String: encryptIngestionWorkerMailboxKey(t, "org_1", "int_1", "acct_1", testIngestionWorkerMailboxPrivKey, true),
			Valid:  true,
		}
		if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", "MAILBOX_DELEGATION_GRANTED")); err != nil {
			t.Fatalf("validate Google mailbox legacy config: %v", err)
		}
	})

	t.Run("Google mailbox optional service account config requires both fields when partially configured", func(t *testing.T) {
		config := baseConfig("GOOGLE_WORKSPACE", false)
		config.GoogleMailboxScanClientEmail = sql.NullString{String: "mailbox-scanner@example.com", Valid: true}
		if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", "EMAIL_FORWARDING_ENABLED")); !errors.Is(err, errIntegrationConfigurationIncomplete) {
			t.Fatalf("Google mailbox missing private key error = %v", err)
		}
		config = baseConfig("GOOGLE_WORKSPACE", false)
		config.EncryptedGoogleMailboxScanPrivateKey = sql.NullString{
			String: encryptIngestionWorkerMailboxKey(t, "org_1", "int_1", "acct_1", testIngestionWorkerMailboxPrivKey, false),
			Valid:  true,
		}
		if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", "EMAIL_FORWARDING_ENABLED")); !errors.Is(err, errIntegrationConfigurationIncomplete) {
			t.Fatalf("Google mailbox missing client email error = %v", err)
		}
	})

	t.Run("Google mailbox tampered private key fails closed", func(t *testing.T) {
		config := baseConfig("GOOGLE_WORKSPACE", false)
		config.GoogleMailboxScanClientEmail = sql.NullString{String: "mailbox-scanner@example.com", Valid: true}
		encrypted := encryptIngestionWorkerMailboxKey(t, "org_1", "int_1", "acct_1", testIngestionWorkerMailboxPrivKey, false)
		config.EncryptedGoogleMailboxScanPrivateKey = sql.NullString{String: tamperIngestionWorkerEnvelopeTag(t, encrypted), Valid: true}
		if err := config.validateForJob(baseJob("GOOGLE_WORKSPACE", "EMAIL_FORWARDING_ENABLED")); !errors.Is(err, errIntegrationCredentialUnavailable) {
			t.Fatalf("Google mailbox tampered key error = %v", err)
		}
	})
}

func TestProcessMarksJobFailureWhenInsertFails(t *testing.T) {
	state := newFailureDriverState(t, "")
	driverName := fmt.Sprintf("ingestion_failure_%d", time.Now().UnixNano())
	sql.Register(driverName, &failureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	worker := &Worker{db: db, leaseOwner: "test-owner"}
	payload, _ := json.Marshal(map[string]any{"repository": map[string]any{"full_name": "writer/aperio", "visibility": "public"}})
	err = worker.process(context.Background(), job{
		ID:             "job_1",
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Source:         "test",
		OccurredAt:     time.Now(),
		Payload:        payload,
		Attempts:       1,
		MaxAttempts:    3,
	})
	if err == nil || !strings.Contains(err.Error(), "ingested event insert failed") {
		t.Fatalf("process should return recorded failure, got %v", err)
	}

	status, attempts, message := state.failureUpdate()
	if status != "FAILED" || attempts != "2" {
		t.Fatalf("expected FAILED attempt 2, got status=%s attempts=%s", status, attempts)
	}
	if !strings.Contains(message, "ingested event insert failed") {
		t.Fatalf("expected stored error message, got %q", message)
	}
	if !state.rolledBack {
		t.Fatal("expected failed transaction to be rolled back before marking job failure")
	}
}

func TestDrainCountsRecordedJobFailureAsFailed(t *testing.T) {
	state := newFailureDriverState(t, "")
	driverName := fmt.Sprintf("ingestion_drain_failure_%d", time.Now().UnixNano())
	sql.Register(driverName, &failureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	worker := &Worker{db: db, leaseOwner: "test-owner"}
	result, err := worker.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Processed != 1 || result.Failed != 1 || result.Succeeded != 0 {
		t.Fatalf("expected one failed job, got %#v", result)
	}
}

func TestFindingsForJobHonorsDisabledChecks(t *testing.T) {
	state := newFailureDriverState(t, `["github.public_repository_created"]`)
	driverName := fmt.Sprintf("ingestion_disabled_%d", time.Now().UnixNano())
	sql.Register(driverName, &failureDriver{state: state})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	worker := &Worker{db: db}
	findings, err := worker.findingsForJob(context.Background(), JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
		EventType:      "PUBLIC_REPOSITORY_CREATED",
		Payload: map[string]any{
			"repository": map[string]any{
				"full_name":  "writer/aperio",
				"visibility": "public",
			},
		},
	}, job{
		OrganizationID: "org_1",
		IntegrationID:  "int_1",
		Provider:       "GITHUB",
	})
	if err != nil {
		t.Fatalf("load disabled checks: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected disabled check to suppress findings, got %#v", findings)
	}
}

func newFailureDriverState(t *testing.T, disabledChecksJSON string) *failureDriverState {
	t.Helper()
	return &failureDriverState{
		disabledChecksJSON:        disabledChecksJSON,
		disabledCheckMetadataJSON: "{}",
		integrationExternalID:     "int_1",
		encryptedAccessToken:      encryptIngestionWorkerSecret(t, "org_1", "int_1", "GITHUB", "int_1", "access_token", testIngestionWorkerAccessToken, false),
		encryptedRefreshToken:     encryptIngestionWorkerSecret(t, "org_1", "int_1", "GITHUB", "int_1", "refresh_token", testIngestionWorkerRefreshToken, false),
		encryptedWebhookSecret:    encryptIngestionWorkerSecret(t, "org_1", "int_1", "GITHUB", "int_1", "webhook_secret", testIngestionWorkerWebhookSecret, false),
		googleMailboxClientEmail:  nil,
		encryptedGoogleMailboxKey: nil,
	}
}

type failureDriverState struct {
	mu                        sync.Mutex
	execs                     [][]driver.NamedValue
	rolledBack                bool
	disabledChecksJSON        string
	disabledCheckMetadataJSON string
	integrationExternalID     string
	encryptedAccessToken      string
	encryptedRefreshToken     string
	encryptedWebhookSecret    string
	googleMailboxClientEmail  any
	encryptedGoogleMailboxKey any
}

func (s *failureDriverState) failureUpdate() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.execs) == 0 {
		return "", "", ""
	}
	args := s.execs[len(s.execs)-1]
	return fmt.Sprint(args[0].Value), fmt.Sprint(args[1].Value), fmt.Sprint(args[3].Value)
}

type failureDriver struct {
	state *failureDriverState
}

func (d *failureDriver) Open(string) (driver.Conn, error) {
	return &failureConn{state: d.state}, nil
}

type failureConn struct {
	state *failureDriverState
}

func (c *failureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}

func (c *failureConn) Close() error {
	return nil
}

func (c *failureConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *failureConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &failureTx{state: c.state}, nil
}

func (c *failureConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "FROM integration_connections") {
		disabled := c.state.disabledChecksJSON
		if disabled == "" {
			disabled = "[]"
		}
		return &singleValueRows{
			columns: []string{
				"id",
				"organization_id",
				"provider",
				"external_account_id",
				"disabled_checks",
				"disabled_check_metadata",
				"encrypted_access_token",
				"encrypted_refresh_token",
				"encrypted_webhook_secret",
				"google_mailbox_scan_client_email",
				"encrypted_google_mailbox_scan_private_key",
			},
			values: [][]driver.Value{{
				"int_1",
				"org_1",
				"GITHUB",
				c.state.integrationExternalID,
				disabled,
				c.state.disabledCheckMetadataJSON,
				c.state.encryptedAccessToken,
				c.state.encryptedRefreshToken,
				c.state.encryptedWebhookSecret,
				c.state.googleMailboxClientEmail,
				c.state.encryptedGoogleMailboxKey,
			}},
		}, nil
	}
	if strings.Contains(query, "RETURNING id, organization_id, integration_id") {
		payload, _ := json.Marshal(map[string]any{"repository": map[string]any{"full_name": "writer/aperio", "visibility": "public"}})
		return &singleValueRows{
			columns: []string{"id", "organization_id", "integration_id", "provider", "event_type", "source", "actor", "occurred_at", "payload", "attempts", "max_attempts"},
			values: [][]driver.Value{{
				"job_1", "org_1", "int_1", "GITHUB", "PUBLIC_REPOSITORY_CREATED", "test", nil, time.Now(), payload, int64(1), int64(3),
			}},
		}, nil
	}
	if strings.Contains(query, "INSERT INTO ingested_events") {
		return nil, errors.New("ingested event insert failed")
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

func (c *failureConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "UPDATE ingestion_jobs") {
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	c.state.mu.Lock()
	c.state.execs = append(c.state.execs, args)
	c.state.mu.Unlock()
	return driver.RowsAffected(1), nil
}

type failureTx struct {
	state *failureDriverState
}

func (tx *failureTx) Commit() error {
	return nil
}

func (tx *failureTx) Rollback() error {
	tx.state.mu.Lock()
	tx.state.rolledBack = true
	tx.state.mu.Unlock()
	return nil
}

type singleValueRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *singleValueRows) Columns() []string {
	return r.columns
}

func (r *singleValueRows) Close() error {
	return nil
}

func (r *singleValueRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
