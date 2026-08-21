package ingestionworker

import (
	"reflect"
	"testing"
	"time"
)

func TestEvaluateUsesDeclarativeRuleVersionAndTenantSeverityOverride(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_slack_1",
		Provider:       "SLACK",
		EventType:      "mfa.disabled",
		Source:         "slack-audit-log",
		OccurredAt:     time.Date(2026, 6, 6, 1, 0, 0, 0, time.UTC),
		Payload: map[string]any{
			"user": map[string]any{"id": "U123", "email": "user@example.com"},
		},
	}
	findings := Evaluate(payload, nil)
	if len(findings) != 1 || findings[0].RuleVersion != "1.0.0" {
		t.Fatalf("declarative findings = %#v", findings)
	}
	if !reflect.DeepEqual(findings[0].Evidence, map[string]any{"user": "user@example.com", "subject": "user@example.com"}) {
		t.Fatalf("declarative evidence = %#v", findings[0].Evidence)
	}
	overridden := EvaluateWithSeverityOverrides(payload, nil, map[string]string{"slack.mfa_disabled": "LOW"})
	if len(overridden) != 1 || overridden[0].Severity != SeverityLow || overridden[0].RiskScore != RiskScoreFor(SeverityLow) {
		t.Fatalf("severity override = %#v", overridden)
	}
}

func TestGitHubDeployKeyRuleEscalatesWriteAccess(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_github_1",
		Provider:       "GITHUB",
		EventType:      "deploy_key.added",
		OccurredAt:     time.Date(2026, 6, 6, 1, 0, 0, 0, time.UTC),
		Payload: map[string]any{
			"repository": map[string]any{"full_name": "acme/api"},
			"key":        map[string]any{"title": "build-bot", "write_enabled": true},
		},
	}
	findings := Evaluate(payload, nil)
	if len(findings) != 1 {
		t.Fatalf("deploy key findings = %#v", findings)
	}
	if findings[0].RuleID != "github.deploy_key_added" || findings[0].Severity != SeverityHigh || findings[0].DedupeTarget != "acme/api:build-bot" {
		t.Fatalf("deploy key finding = %#v", findings[0])
	}
	missingIdentity := payload
	missingIdentity.Payload = map[string]any{"repository": map[string]any{"full_name": "acme/api"}}
	if findings := Evaluate(missingIdentity, nil); len(findings) != 0 {
		t.Fatalf("deploy key without key identity should remain unsupported: %#v", findings)
	}
}

func TestDeclarativeAutoResolutionRequiresCleanEvent(t *testing.T) {
	payload := JobPayload{
		OrganizationID: "org_1",
		IntegrationID:  "int_slack_1",
		Provider:       "SLACK",
		EventType:      "two-factor auth enabled",
		OccurredAt:     time.Date(2026, 6, 6, 1, 0, 0, 0, time.UTC),
		Payload:        map[string]any{"user": map[string]any{"email": "user@example.com"}},
	}
	resolutions, loaded := DeclarativeAutoResolutions(payload, nil)
	if !loaded || len(resolutions) != 1 || resolutions[0].RuleID != "slack.mfa_disabled" || resolutions[0].DedupeTarget != "user@example.com" {
		t.Fatalf("auto resolutions = %#v loaded=%t", resolutions, loaded)
	}
}

func TestDeclarativeRuleCatalogVersionsAreStable(t *testing.T) {
	for ruleID := range declarativeRuleIDs {
		found := false
		for _, entry := range RuleCatalog {
			if entry.ID != ruleID {
				continue
			}
			found = true
			if entry.Version != "1.0.0" {
				t.Errorf("catalog rule %s version = %q, want 1.0.0", ruleID, entry.Version)
			}
			break
		}
		if !found {
			t.Errorf("declarative rule %s has no catalog entry", ruleID)
		}
	}
}
