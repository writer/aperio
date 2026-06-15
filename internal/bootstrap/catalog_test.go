package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestConnectorCatalogExposesProviderFieldsAndScopes(t *testing.T) {
	catalog := compatConnectorCatalog()
	byProvider := map[string]connectorDefinition{}
	for _, definition := range catalog {
		byProvider[definition.Provider] = definition
	}

	wantProviders := []string{"GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE"}
	if len(catalog) != len(wantProviders) {
		t.Fatalf("expected %d connectors, got %d", len(wantProviders), len(catalog))
	}
	for _, provider := range wantProviders {
		if _, ok := byProvider[provider]; !ok {
			t.Fatalf("connector catalog missing provider %s", provider)
		}
	}

	github := byProvider["GITHUB"]
	if github.Name != "GitHub" || github.Category != "Source Control" || github.Availability != "production_ready" {
		t.Fatalf("unexpected GitHub metadata: %+v", github)
	}
	var fieldKeys []string
	for _, field := range github.Fields {
		fieldKeys = append(fieldKeys, field.Key)
	}
	wantFieldKeys := []string{"externalAccountId", "accessToken", "refreshToken", "webhookSecret"}
	if strings.Join(fieldKeys, ",") != strings.Join(wantFieldKeys, ",") {
		t.Fatalf("unexpected GitHub field keys: %v", fieldKeys)
	}
	if github.DocsURL == "" {
		t.Fatal("expected GitHub docs URL to be populated")
	}

	// Google Workspace uses the managed OAuth flow and intentionally exposes no
	// credential fields; the web special-cases it.
	if google := byProvider["GOOGLE_WORKSPACE"]; len(google.Fields) != 0 {
		t.Fatalf("expected Google Workspace to expose no fields, got %d", len(google.Fields))
	}
}

func TestConnectorCatalogMarshalsEmptySlicesAsArrays(t *testing.T) {
	encoded, err := json.Marshal(compatConnectorCatalog())
	if err != nil {
		t.Fatal(err)
	}
	payload := string(encoded)
	// 1Password has no remediation actions/scopes; these must serialize as []
	// (not null) so the web can safely map over them.
	if !strings.Contains(payload, `"remediationActions":[]`) {
		t.Fatal("expected an empty remediationActions array in catalog JSON")
	}
	if !strings.Contains(payload, `"fields":[]`) {
		t.Fatal("expected Google Workspace fields to serialize as an empty array")
	}
	if strings.Contains(payload, "null") {
		t.Fatalf("catalog JSON should not contain null slices: %s", payload)
	}
}

func TestConnectorCatalogAdvertisesOnlyExecutableRemediationActions(t *testing.T) {
	for _, connector := range compatConnectorCatalog() {
		for _, action := range connector.RemediationActions {
			definition, ok := findRemediationActionDefinition(action.Key)
			if !ok {
				t.Fatalf("catalog action %s is not classified", action.Key)
			}
			if definition.Class != remediationActionRealProvider && definition.Class != remediationActionLocalOnly {
				t.Fatalf("catalog advertises non-executable action %s as %s", action.Key, definition.Class)
			}
		}
	}
	for _, connector := range connectorCatalogProto() {
		for _, action := range connector.RemediationActions {
			definition, ok := findRemediationActionDefinition(action.Key)
			if !ok {
				t.Fatalf("typed catalog action %s is not classified", action.Key)
			}
			if definition.Class != remediationActionRealProvider && definition.Class != remediationActionLocalOnly {
				t.Fatalf("typed catalog advertises non-executable action %s as %s", action.Key, definition.Class)
			}
		}
	}
	slack := findConnectorDefinition("SLACK")
	if slack == nil {
		t.Fatal("expected Slack connector definition")
	}
	if !connectorHasRemediationAction(slack, "slack.deactivate_user") {
		t.Fatal("known unsupported Slack action should remain recognized by executor registry")
	}
	exposed := compatConnectorCatalog()
	for _, connector := range exposed {
		if connector.Provider != "SLACK" {
			continue
		}
		if len(connector.RemediationActions) != 1 || connector.RemediationActions[0].Key != "slack.revoke_app_install" {
			t.Fatalf("Slack executable actions = %+v, want only slack.revoke_app_install", connector.RemediationActions)
		}
	}
}

func TestTypeScriptExecutableRemediationFilterMatchesGoClassification(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file path")
	}
	sourcePath := filepath.Join(filepath.Dir(testFile), "..", "..", "packages", "shared", "src", "connectors.ts")
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read TypeScript connector catalog: %v", err)
	}
	source := string(sourceBytes)
	filterPattern := regexp.MustCompile(`executableRemediationActionKeys\s*\.\s*has\s*\(\s*action\.key\s*\)`)
	if !filterPattern.MatchString(source) {
		t.Fatal("TypeScript connector catalog must filter remediation actions through executableRemediationActionKeys")
	}

	blockPattern := regexp.MustCompile(`(?s)const\s+executableRemediationActionKeys\s*=\s*new Set<RemediationActionKey>\(\s*\[(.*?)\]\s*\);`)
	matches := blockPattern.FindStringSubmatch(source)
	if len(matches) != 2 {
		t.Fatal("could not find TypeScript executableRemediationActionKeys set")
	}
	literalPattern := regexp.MustCompile(`"([^"]+)"`)
	tsExecutable := map[string]bool{}
	for _, match := range literalPattern.FindAllStringSubmatch(matches[1], -1) {
		tsExecutable[match[1]] = true
	}

	goExecutable := map[string]bool{}
	for _, definition := range remediationActionDefinitions {
		if definition.Class == remediationActionRealProvider || definition.Class == remediationActionLocalOnly {
			goExecutable[definition.Action] = true
		}
	}
	for action := range goExecutable {
		if !tsExecutable[action] {
			t.Fatalf("Go classifies %s as executable but TypeScript connector catalog does not", action)
		}
	}
	for action := range tsExecutable {
		definition, ok := findRemediationActionDefinition(action)
		if !ok {
			t.Fatalf("TypeScript connector catalog marks unclassified action %s executable", action)
		}
		if !goExecutable[action] {
			t.Fatalf("TypeScript connector catalog marks %s executable but Go classifies it as %s", action, definition.Class)
		}
	}
}

func TestSiemCatalogExposesDestinationFields(t *testing.T) {
	catalog := compatSiemCatalog()
	wantKinds := []string{"SPLUNK_HEC", "PANTHER", "PANOPTICON", "ELASTIC", "DATADOG", "GENERIC_WEBHOOK", "CEREBRO_CLAIMS", "JSON_FILE"}
	if len(catalog) != len(wantKinds) {
		t.Fatalf("expected %d SIEM destinations, got %d", len(wantKinds), len(catalog))
	}
	byKind := map[string]siemDestinationDefinition{}
	for _, definition := range catalog {
		byKind[definition.Kind] = definition
		if len(definition.Fields) == 0 {
			t.Fatalf("SIEM destination %s exposes no fields; the add-destination dialog would be unusable", definition.Kind)
		}
		if len(definition.DefaultStreams) == 0 {
			t.Fatalf("SIEM destination %s has no default streams", definition.Kind)
		}
	}
	splunk := byKind["SPLUNK_HEC"]
	if splunk.Name != "Splunk HEC" || splunk.Vendor != "Splunk" || splunk.Category != "Cloud SIEM" {
		t.Fatalf("unexpected Splunk metadata: %+v", splunk)
	}
	var required []string
	for _, field := range splunk.Fields {
		if field.Required {
			required = append(required, field.Key)
		}
	}
	if strings.Join(required, ",") != "endpointUrl,token" {
		t.Fatalf("unexpected required Splunk fields: %v", required)
	}
}

func TestScopesForModeAppendsRemediationScopes(t *testing.T) {
	readOnly := compatScopesForMode("GITHUB", "READ_ONLY")
	if len(readOnly) != 4 {
		t.Fatalf("expected 4 read scopes for GitHub read-only, got %v", readOnly)
	}
	remediation := compatScopesForMode("GITHUB", "REMEDIATION")
	if len(remediation) != 7 {
		t.Fatalf("expected 7 scopes for GitHub remediation, got %v", remediation)
	}
	for _, scope := range readOnly {
		if scope == "Administration: write" {
			t.Fatal("read-only scopes must not include remediation scopes")
		}
	}
	if got := compatScopesForMode("UNKNOWN", "READ_ONLY"); len(got) != 0 {
		t.Fatalf("expected no scopes for unknown provider, got %v", got)
	}
}

func TestDefaultDisabledChecksMatchCatalog(t *testing.T) {
	cases := map[string][]string{
		"GITHUB":           {"github.deploy_key_added"},
		"SLACK":            {"slack.app_installed"},
		"OKTA":             {"okta.suspicious_signin"},
		"ONE_PASSWORD":     {"one_password.travel_mode_enabled"},
		"GOOGLE_WORKSPACE": {},
		"SALESFORCE":       {},
	}
	for provider, want := range cases {
		got := compatDefaultDisabledChecks(provider)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("provider %s default disabled checks = %v, want %v", provider, got, want)
		}
	}
}

func TestCriticalBaselineCheckSetMatchesCatalog(t *testing.T) {
	for _, connector := range compatConnectorCatalog() {
		baseline := compatCriticalBaselineCheckSet(connector.Provider)
		for _, check := range connector.FindingChecks {
			_, found := baseline[check.Key]
			want := check.DefaultEnabled && strings.EqualFold(check.SeverityHint, "CRITICAL")
			if found != want {
				t.Fatalf("provider %s check %s baseline=%t want %t", connector.Provider, check.Key, found, want)
			}
		}
	}
}

// TestFindingChecksForProviderReturnsFullSet pins the contract relied on
// by compatListConnectorRules: the connector-rules dialog recomputes
// disabled_checks from this list and posts a wholesale replacement, so
// the list MUST include every FindingCheck the connector definition
// surfaces — including DefaultEnabled=false checks like
// github.deploy_key_added and slack.app_installed that aren't in
// ingestionworker.RuleCatalog. Dropping any of these would silently
// re-enable them on the first built-in toggle.
func TestFindingChecksForProviderReturnsFullSet(t *testing.T) {
	for _, provider := range []string{"GITHUB", "SLACK", "OKTA", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "SALESFORCE"} {
		got := compatFindingChecksForProvider(provider)
		def := findConnectorDefinition(provider)
		if def == nil {
			t.Fatalf("provider %s has no connector definition", provider)
		}
		if len(got) != len(def.FindingChecks) {
			t.Fatalf("provider %s: compatFindingChecksForProvider returned %d entries, want %d (full FindingChecks set)", provider, len(got), len(def.FindingChecks))
		}
		gotKeys := map[string]bool{}
		for _, c := range got {
			gotKeys[c.Key] = true
		}
		for _, defaultDisabled := range compatDefaultDisabledChecks(provider) {
			if !gotKeys[defaultDisabled] {
				t.Errorf("provider %s: default-disabled check %q missing from compatFindingChecksForProvider (would be silently re-enabled on next built-in toggle)", provider, defaultDisabled)
			}
		}
	}
}

func TestFindingCheckStatusesOverlayDisabledSet(t *testing.T) {
	statuses := compatFindingCheckStatuses("GITHUB", []string{"github.public_repository_created"})
	github := findConnectorDefinition("GITHUB")
	if len(statuses) != len(github.FindingChecks) {
		t.Fatalf("expected %d statuses, got %d", len(github.FindingChecks), len(statuses))
	}
	for _, status := range statuses {
		if status.Key == "github.public_repository_created" && status.Enabled {
			t.Fatal("expected explicitly disabled check to report enabled=false")
		}
		if status.Key == "github.branch_protection_disabled" && !status.Enabled {
			t.Fatal("expected non-disabled check to report enabled=true")
		}
	}
}
