package detection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBuiltinPackCompilesAndEvaluatesMigratedRules(t *testing.T) {
	rules, err := LoadEmbeddedPack(BuiltinFS, "rules/*.yaml")
	if err != nil {
		t.Fatalf("load built-in rules: %v", err)
	}
	if got, want := len(rules), 4; got != want {
		t.Fatalf("built-in rules = %d, want %d", got, want)
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("compile built-in rules: %v", err)
	}

	cases := []struct {
		name        string
		event       Event
		wantRule    string
		wantTitle   string
		wantTarget  string
		wantSubject string
	}{
		{
			name: "github public repository",
			event: Event{
				Provider: "GITHUB", EventType: "repository.publicized", OccurredAt: testTime(),
				Payload: map[string]any{"repository": map[string]any{"full_name": "writer/aperio", "private": false, "visibility": "public"}},
			},
			wantRule: "github.public_repository_created", wantTitle: "Public GitHub repository created", wantTarget: "writer/aperio", wantSubject: "writer/aperio",
		},
		{
			name: "slack mfa",
			event: Event{
				Provider: "SLACK", EventType: "mfa.disabled", Actor: "admin@example.com", OccurredAt: testTime(),
				Payload: map[string]any{"user": map[string]any{"email": "user@example.com", "id": "U123"}},
			},
			wantRule: "slack.mfa_disabled", wantTitle: "Slack multi-factor authentication disabled", wantTarget: "user@example.com", wantSubject: "user@example.com",
		},
		{
			name: "slack external shared channel",
			event: Event{
				Provider: "SLACK", EventType: "EXTERNAL_SHARED_CHANNEL_CREATED", Actor: "admin@example.com", OccurredAt: testTime(),
				Payload: map[string]any{
					"channel":               map[string]any{"name": "customer-data"},
					"external_organization": map[string]any{"name": "Partner Co"},
				},
			},
			wantRule: "slack.external_shared_channel_created", wantTitle: "Slack external shared channel created", wantTarget: "customer-data", wantSubject: "customer-data:Partner Co",
		},
		{
			name: "google external sharing",
			event: Event{
				Provider: "GOOGLE_WORKSPACE", EventType: "EXTERNAL_SHARING_ENABLED", OccurredAt: testTime(),
				Payload: map[string]any{
					"resource":   map[string]any{"id": "drive_file_123", "name": "Board Deck"},
					"parameters": map[string]any{"doc_title": "Board Deck", "doc_id": "drive_file_123", "doc_type": "presentation", "owner": "owner@writer.com", "visibility": "public_on_the_web", "shared_with": "partner@external.example"},
				},
			},
			wantRule: "google_workspace.external_sharing_enabled", wantTitle: "Google Workspace external sharing enabled", wantTarget: "Board Deck", wantSubject: "drive_file_123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := engine.Evaluate(tc.event, OrgContext{}, Overrides{})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %#v, want one", findings)
			}
			finding := findings[0]
			if finding.RuleID != tc.wantRule || finding.Title != tc.wantTitle || finding.Target != tc.wantTarget || finding.DedupeTarget != tc.wantSubject {
				t.Fatalf("finding = %#v", finding)
			}
			if finding.RuleVersion != "1.0.0" || finding.Evidence["ruleVersion"] != nil {
				t.Fatalf("rule version should be a first-class field, not duplicated in evidence: %#v", finding)
			}
		})
	}
}

func TestEngineOverridesAndAutoResolution(t *testing.T) {
	rules, err := LoadEmbeddedPack(BuiltinFS, "rules/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	event := Event{
		Provider: "SLACK", EventType: "MFA_DISABLED", OccurredAt: testTime(),
		Payload: map[string]any{"user": map[string]any{"email": "user@example.com"}},
	}
	findings, err := engine.Evaluate(event, OrgContext{}, Overrides{SeverityOverrides: map[string]string{"slack.mfa_disabled": "LOW"}})
	if err != nil || len(findings) != 1 {
		t.Fatalf("severity override evaluation = %#v, err=%v", findings, err)
	}
	if findings[0].Severity != "LOW" || findings[0].RiskScore >= 55 {
		t.Fatalf("severity override did not lower finding: %#v", findings[0])
	}
	disabled, err := engine.Evaluate(event, OrgContext{}, Overrides{Disabled: map[string]bool{"slack.mfa_disabled": true}})
	if err != nil || len(disabled) != 0 {
		t.Fatalf("disabled evaluation = %#v, err=%v", disabled, err)
	}
	clean := event
	clean.EventType = "two-factor auth enabled"
	resolutions, err := engine.AutoResolve(clean, OrgContext{}, Overrides{})
	if err != nil {
		t.Fatalf("auto resolve: %v", err)
	}
	want := []ResolutionDraft{{RuleID: "slack.mfa_disabled", RuleVersion: "1.0.0", DedupeTarget: "user@example.com", Evidence: map[string]any{
		"ruleId": "slack.mfa_disabled", "ruleVersion": "1.0.0", "subject": "user@example.com", "resolution": "auto_resolve_when", "eventType": "two-factor auth enabled",
	}}}
	if !reflect.DeepEqual(resolutions, want) {
		t.Fatalf("resolutions = %#v, want %#v", resolutions, want)
	}
}

func TestVersionedDedupeMaterialChangesOnlyWithRuleVersion(t *testing.T) {
	rule := Rule{ID: "example.rule", Version: "1.0.0"}
	first := VersionedDedupeHash(rule, "subject-1")
	rule.Version = "1.1.0"
	second := VersionedDedupeHash(rule, "subject-1")
	if first == second || DedupeMaterial(rule, "subject-1") != "example.rule@1.1.0:subject-1" {
		t.Fatalf("versioned dedupe material did not change: first=%s second=%s", first, second)
	}
}

func TestBacktestCountsMatchesAndResolutions(t *testing.T) {
	rules, err := LoadEmbeddedPack(BuiltinFS, "rules/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{
		{Provider: "GITHUB", EventType: "PUBLIC_REPOSITORY_CREATED", OccurredAt: testTime(), Payload: map[string]any{"repository": map[string]any{"full_name": "acme/api", "private": false, "visibility": "public"}}},
		{Provider: "GITHUB", EventType: "REPOSITORY_PRIVATE", OccurredAt: testTime().Add(time.Minute), Payload: map[string]any{"repository": map[string]any{"full_name": "acme/api", "private": true, "visibility": "private"}}},
		{Provider: "GITHUB", EventType: "repository.deleted", OccurredAt: testTime(), Payload: map[string]any{"repository": map[string]any{"full_name": "acme/api", "private": false, "visibility": "public"}}},
	}
	report, err := engine.Backtest("github.public_repository_created", events, OrgContext{}, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Candidates != 2 || report.Matches != 1 || report.Resolutions != 1 {
		t.Fatalf("backtest report = %#v", report)
	}
}

func TestBacktestReplaysRepositoryFixture(t *testing.T) {
	rules, err := LoadEmbeddedPack(BuiltinFS, "rules/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "worker-parity", "github-public-repository.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Positive fixtureEvent `json:"positive"`
		Negative fixtureEvent `json:"negative"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	report, err := engine.Backtest("github.public_repository_created", []Event{fixture.Positive.Event, fixture.Negative.Event}, OrgContext{}, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Candidates != 2 || report.Matches != 1 || report.Resolutions != 1 {
		t.Fatalf("fixture backtest report = %#v", report)
	}
}

type fixtureEvent struct {
	Event Event `json:"payload"`
}

func testTime() time.Time {
	return time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
}
