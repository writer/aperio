package ingestionworker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRuleCatalogMatchesEvaluators pins the cross-file contract that the
// UI-facing RuleCatalog stays in lockstep with the Evaluate() switch in
// worker.go. Drift would either hide a real rule from the toggle UI (so
// users see findings they can't disable) or surface a phantom rule (so
// users disable something that never produces findings). Both regressions
// caused real ops noise in similar systems we've seen.
//
// The test scans worker.go for every `disabled["..."]` lookup inside
// Evaluate and asserts each one has a matching RuleCatalog entry, and
// vice versa.
func TestRuleCatalogMatchesEvaluators(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("worker.go"))
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	re := regexp.MustCompile(`disabled\["([a-z0-9_.]+)"\]`)
	gateMatches := re.FindAllStringSubmatch(string(source), -1)
	seen := map[string]bool{}
	for _, m := range gateMatches {
		seen[m[1]] = true
	}
	for ruleID := range seen {
		found := false
		for _, entry := range RuleCatalog {
			if entry.ID == ruleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("worker.go gates rule %q via disabled[] but RuleCatalog has no entry (UI will hide a real rule)", ruleID)
		}
	}
	for _, entry := range RuleCatalog {
		if !seen[entry.ID] {
			t.Errorf("RuleCatalog declares %q but worker.go never gates it (UI lists a phantom toggle)", entry.ID)
		}
	}
}

// TestRuleCatalogSeveritiesAndEventTypesMatchEvaluators tightens the
// catalog ↔ evaluator parity check beyond rule IDs. The previous
// guardrail only pinned IDs, so the catalog could (and did) drift:
// severities the worker never produced were rendered in the UI, and
// event types that never fired were advertised as triggers. Both
// regressions made operators triage and toggle against metadata the
// pipeline never agreed with. For each catalog entry we locate the
// `RuleID: "<id>"` line in worker.go and assert:
//
//   - The `Severity:` literal at the next few lines matches the catalog
//     Severity. Rules with a runtime-computed severity (e.g.
//     risky_oauth_grant where severity escalates with scope risk) are
//     skipped — the catalog represents the dominant/baseline level only.
//   - The event-type gating immediately preceding the RuleID line — be
//     it a `switch normalizeEventType(...) { case "X","Y": }` block or
//     a `normalized != "X" && normalized != "Y"` guard or a single
//     `== "X"` check — is a superset of the catalog EventTypes, so the
//     UI never advertises an event type the worker won't recognize.
func TestRuleCatalogSeveritiesAndEventTypesMatchEvaluators(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("worker.go"))
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	src := string(source)
	severityLiteralRE := regexp.MustCompile(`Severity:\s+"([A-Z]+)"`)
	caseRE := regexp.MustCompile(`case\s+((?:"[A-Z_]+"\s*,?\s*)+)\s*:`)
	equalsEventRE := regexp.MustCompile(`(?:normalizeEventType\([^)]*\)|normalized)\s*==\s*"([A-Z_]+)"`)
	notEqualsEventRE := regexp.MustCompile(`(?:normalizeEventType\([^)]*\)|normalized)\s*!=\s*"([A-Z_]+)"`)
	for _, entry := range RuleCatalog {
		ruleLitRE := regexp.MustCompile(`RuleID:\s+"` + regexp.QuoteMeta(entry.ID) + `"`)
		loc := ruleLitRE.FindStringIndex(src)
		if loc == nil {
			continue
		}
		windowEnd := loc[1] + 400
		if windowEnd > len(src) {
			windowEnd = len(src)
		}
		if sevMatch := severityLiteralRE.FindStringSubmatch(src[loc[1]:windowEnd]); sevMatch != nil {
			if sevMatch[1] != entry.Severity {
				t.Errorf("rule %q severity drift: catalog=%q evaluator=%q (UI would render a severity the worker never emits)", entry.ID, entry.Severity, sevMatch[1])
			}
		}
		// Look back up to ~2KB for the gating block immediately preceding
		// the RuleID line; that's enough to span an evaluator function's
		// guard clauses without leaking into the previous evaluator.
		windowStart := loc[0] - 2048
		if windowStart < 0 {
			windowStart = 0
		}
		preceding := src[windowStart:loc[0]]
		gated := map[string]bool{}
		for _, m := range caseRE.FindAllStringSubmatch(preceding, -1) {
			for _, part := range strings.Split(m[1], ",") {
				gated[strings.Trim(strings.TrimSpace(part), `"`)] = true
			}
		}
		for _, m := range equalsEventRE.FindAllStringSubmatch(preceding, -1) {
			gated[m[1]] = true
		}
		for _, m := range notEqualsEventRE.FindAllStringSubmatch(preceding, -1) {
			gated[m[1]] = true
		}
		for _, et := range entry.EventTypes {
			if !gated[et] {
				t.Errorf("rule %q event-type drift: catalog advertises %q but worker.go's switch never matches it (UI lists a trigger the worker never recognizes)", entry.ID, et)
			}
		}
	}
}

// TestRuleCatalogProvidersAreKnown defends against a typo in Provider
// classifying a rule under a SaaS provider the connectors UI does not
// surface, which would orphan the toggle.
func TestRuleCatalogProvidersAreKnown(t *testing.T) {
	known := map[string]bool{
		"GITHUB":           true,
		"SLACK":            true,
		"OKTA":             true,
		"GOOGLE_WORKSPACE": true,
		"MICROSOFT_365":    true,
		"ATLASSIAN":        true,
		"SALESFORCE":       true,
	}
	for _, entry := range RuleCatalog {
		if !known[entry.Provider] {
			t.Errorf("rule %q has unknown provider %q", entry.ID, entry.Provider)
		}
	}
}

// TestRuleCatalogForProviderFiltersDeterministically pins the helper used
// by the API so the UI shows a stable order.
func TestRuleCatalogForProviderFiltersDeterministically(t *testing.T) {
	got := RuleCatalogForProvider("GOOGLE_WORKSPACE")
	if len(got) < 6 {
		t.Fatalf("expected Google rules to be present, got %d", len(got))
	}
	for i := 0; i < len(got)-1; i++ {
		if got[i].Provider != "GOOGLE_WORKSPACE" {
			t.Fatalf("filter leaked non-Google rule at %d: %s", i, got[i].ID)
		}
	}
	// Sanity-check that the IDs follow the convention "<provider>.<slug>"
	// so the UI can group by prefix without an extra lookup table.
	for _, entry := range got {
		if !strings.HasPrefix(entry.ID, "google_workspace.") {
			t.Errorf("Google rule id should start with google_workspace.: %s", entry.ID)
		}
	}
}
