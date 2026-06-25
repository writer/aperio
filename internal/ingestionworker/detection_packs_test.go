package ingestionworker

import (
	"regexp"
	"testing"
)

// TestDetectionPackRegistryShape pins the registry's invariants the
// connectors UI and the ListDetectionPacks RPC depend on: unique IDs,
// known providers, populated names, and semver-shaped versions. A drift
// here would break operator-facing pack pages.
func TestDetectionPackRegistryShape(t *testing.T) {
	if len(DetectionPacks) == 0 {
		t.Fatal("DetectionPacks must not be empty")
	}
	knownProviders := map[string]bool{
		"GITHUB":           true,
		"SLACK":            true,
		"OKTA":             true,
		"GOOGLE_WORKSPACE": true,
		"MICROSOFT_365":    true,
		"ATLASSIAN":        true,
		"SALESFORCE":       true,
	}
	semver := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	seen := map[string]bool{}
	for _, pack := range DetectionPacks {
		if seen[pack.ID] {
			t.Errorf("duplicate pack id %q", pack.ID)
		}
		seen[pack.ID] = true
		if !knownProviders[pack.Provider] {
			t.Errorf("pack %q has unknown provider %q", pack.ID, pack.Provider)
		}
		if pack.Name == "" {
			t.Errorf("pack %q missing Name", pack.ID)
		}
		if pack.Description == "" {
			t.Errorf("pack %q missing Description", pack.ID)
		}
		if !semver.MatchString(pack.Version) {
			t.Errorf("pack %q version %q is not semver (MAJOR.MINOR.PATCH)", pack.ID, pack.Version)
		}
	}
}

// TestRuleCatalogPackLinkage guarantees that every RuleCatalog entry
// carries pack metadata and that the referenced pack actually exists.
// This also enforces that the rule's provider matches the pack's
// provider, so an operator filtering by provider cannot end up with a
// pack containing a rule from a different SaaS.
func TestRuleCatalogPackLinkage(t *testing.T) {
	for _, entry := range RuleCatalog {
		if entry.PackID == "" {
			t.Errorf("rule %q is missing PackID", entry.ID)
			continue
		}
		pack, ok := DetectionPackByID(entry.PackID)
		if !ok {
			t.Errorf("rule %q references unknown pack %q", entry.ID, entry.PackID)
			continue
		}
		if pack.Provider != entry.Provider {
			t.Errorf("rule %q (provider=%s) is in pack %q (provider=%s)", entry.ID, entry.Provider, pack.ID, pack.Provider)
		}
		if entry.Intent == "" {
			t.Errorf("rule %q is missing Intent", entry.ID)
		}
		if len(entry.MitreTechniques) == 0 {
			t.Errorf("rule %q is missing MitreTechniques", entry.ID)
		}
		if len(entry.Tags) == 0 {
			t.Errorf("rule %q is missing Tags", entry.ID)
		}
	}
}

// TestRuleCatalogMitreTechniqueShape pins the MITRE technique id shape
// so an analyst can mechanically cross-reference attack.mitre.org. We
// accept top-level techniques (Txxxx) and one-level sub-techniques
// (Txxxx.yyy). Anything else is almost certainly a typo.
func TestRuleCatalogMitreTechniqueShape(t *testing.T) {
	techniqueRE := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	for _, entry := range RuleCatalog {
		for _, technique := range entry.MitreTechniques {
			if !techniqueRE.MatchString(technique) {
				t.Errorf("rule %q has malformed MITRE technique %q (want Txxxx or Txxxx.yyy)", entry.ID, technique)
			}
		}
	}
}

// TestRuleCatalogTagsAreCanonical asserts every catalog Tag is a tag
// the worker actually recognizes. Adding a tag elsewhere without
// registering it in tags.go would silently route findings into an
// orphan bucket the UI cannot filter on.
func TestRuleCatalogTagsAreCanonical(t *testing.T) {
	canonical := map[string]bool{}
	for _, tag := range AllTags {
		canonical[tag] = true
	}
	for _, entry := range RuleCatalog {
		for _, tag := range entry.Tags {
			if !canonical[tag] {
				t.Errorf("rule %q references non-canonical tag %q (add it to tags.go or use an existing tag)", entry.ID, tag)
			}
		}
	}
}

// TestRulesInPackPreservesCatalogOrder pins the helper used to render
// each pack's rule list in the UI; alphabetical resort would scramble
// the carefully-chosen display order in RuleCatalog.
func TestRulesInPackPreservesCatalogOrder(t *testing.T) {
	gotIDs := []string{}
	for _, entry := range RulesInPack("aperio.google_workspace.mail.v1") {
		gotIDs = append(gotIDs, entry.ID)
	}
	if len(gotIDs) == 0 {
		t.Fatal("expected at least one rule in the mail pack")
	}
	wantIDs := []string{}
	for _, entry := range RuleCatalog {
		if entry.PackID == "aperio.google_workspace.mail.v1" {
			wantIDs = append(wantIDs, entry.ID)
		}
	}
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("rules-in-pack length mismatch: got %d want %d", len(gotIDs), len(wantIDs))
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Errorf("rules-in-pack order drift at %d: got %s want %s", i, gotIDs[i], wantIDs[i])
		}
	}
}
