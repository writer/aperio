package ingestionworker

import (
	"testing"
	"time"
)

func TestExpandedSaasPackRulesEvaluateRepresentativeEvents(t *testing.T) {
	cases := []struct {
		name     string
		payload  JobPayload
		wantRule string
	}{
		{
			name: "github branch protection disabled",
			payload: testPackPayload("GITHUB", "BRANCH_PROTECTION_DISABLED", map[string]any{
				"repository": map[string]any{"full_name": "acme/api"},
				"branch":     "main",
			}),
			wantRule: "github.branch_protection_disabled",
		},
		{
			name: "github oauth app installed",
			payload: testPackPayload("GITHUB", "OAUTH_APP_INSTALLED", map[string]any{
				"app":    map[string]any{"name": "Build Bot"},
				"scopes": []any{"repo", "admin:org"},
			}),
			wantRule: "github.oauth_app_installed",
		},
		{
			name: "slack external shared channel",
			payload: testPackPayload("SLACK", "EXTERNAL_SHARED_CHANNEL_CREATED", map[string]any{
				"channel":               map[string]any{"name": "customer-data"},
				"external_organization": map[string]any{"name": "Partner Co"},
			}),
			wantRule: "slack.external_shared_channel_created",
		},
		{
			name: "slack app installed",
			payload: testPackPayload("SLACK", "APP_INSTALLED", map[string]any{
				"app": map[string]any{
					"name":   "Transcript Exporter",
					"scopes": []any{"channels:history", "files:read"},
				},
			}),
			wantRule: "slack.app_installed",
		},
		{
			name: "microsoft 365 global admin granted",
			payload: testPackPayload("MICROSOFT_365", "DIRECTORY_ROLE_ASSIGNED", map[string]any{
				"target": map[string]any{"userPrincipalName": "alice@example.com"},
				"role":   map[string]any{"displayName": "Global Administrator"},
			}),
			wantRule: "ms365.global_admin_granted",
		},
		{
			name: "atlassian anonymous access enabled",
			payload: testPackPayload("ATLASSIAN", "ANONYMOUS_ACCESS_ENABLED", map[string]any{
				"space": map[string]any{"key": "FIN", "name": "Finance"},
			}),
			wantRule: "atlassian.anonymous_access_enabled",
		},
		{
			name: "atlassian org admin granted",
			payload: testPackPayload("ATLASSIAN", "ORG_ADMIN_GRANTED", map[string]any{
				"target": map[string]any{"email": "owner@example.com"},
				"role":   map[string]any{"name": "Org admin"},
			}),
			wantRule: "atlassian.org_admin_granted",
		},
		{
			name: "salesforce admin profile assigned",
			payload: testPackPayload("SALESFORCE", "PROFILE_ASSIGNED", map[string]any{
				"target":  map[string]any{"username": "admin@example.com"},
				"profile": map[string]any{"name": "System Administrator"},
			}),
			wantRule: "salesforce.admin_profile_assigned",
		},
		{
			name: "salesforce connected app weakened",
			payload: testPackPayload("SALESFORCE", "CONNECTED_APP_UPDATED", map[string]any{
				"connectedApp": map[string]any{"name": "Pipeline Exporter"},
				"changes":      []any{"admin approved users disabled", "refresh token never expires"},
			}),
			wantRule: "salesforce.connected_app_policy_weakened",
		},
		{
			name: "salesforce report exported",
			payload: testPackPayload("SALESFORCE", "REPORT_EXPORTED", map[string]any{
				"report": map[string]any{"name": "Strategic Accounts"},
			}),
			wantRule: "salesforce.report_exported",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := Evaluate(c.payload, nil)
			if !hasRule(findings, c.wantRule) {
				t.Fatalf("Evaluate() rules = %v, want %s", findingRuleIDs(findings), c.wantRule)
			}
			if findings := Evaluate(c.payload, []string{c.wantRule}); hasRule(findings, c.wantRule) {
				t.Fatalf("disabled rule %s still produced finding: %v", c.wantRule, findingRuleIDs(findings))
			}
		})
	}
}

func testPackPayload(provider string, eventType string, record map[string]any) JobPayload {
	return JobPayload{
		OrganizationID: "org_test",
		IntegrationID:  "int_test",
		Provider:       provider,
		EventType:      eventType,
		Source:         "test",
		Actor:          "actor@example.com",
		OccurredAt:     time.Unix(1, 0).UTC(),
		Payload:        record,
	}
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingRuleIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}
