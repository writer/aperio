package bootstrap

import (
	"testing"

	"github.com/writer/aperio/internal/ingestionworker"
)

// TestDetectionPackProtoHydratesRules pins the API surface: every pack
// returned to the UI must carry its full rule metadata so the catalog
// page can render in one shot. Drift here would either drop pack-level
// fields the UI relies on or leave rule arrays empty.
func TestDetectionPackProtoHydratesRules(t *testing.T) {
	for _, pack := range ingestionworker.DetectionPacks {
		got := detectionPackProto(pack)
		if got.Id != pack.ID {
			t.Errorf("pack %q: proto Id = %q", pack.ID, got.Id)
		}
		if got.Provider != pack.Provider {
			t.Errorf("pack %q: proto Provider = %q", pack.ID, got.Provider)
		}
		if got.Version != pack.Version {
			t.Errorf("pack %q: proto Version = %q", pack.ID, got.Version)
		}
		if got.Name == "" {
			t.Errorf("pack %q: proto Name empty", pack.ID)
		}
		wantRules := ingestionworker.RulesInPack(pack.ID)
		if len(got.Rules) != len(wantRules) {
			t.Errorf("pack %q: rule count = %d, want %d", pack.ID, len(got.Rules), len(wantRules))
		}
		for i, rule := range got.Rules {
			if i >= len(wantRules) {
				break
			}
			want := wantRules[i]
			if rule.Id != want.ID {
				t.Errorf("pack %q rule[%d]: Id = %q want %q", pack.ID, i, rule.Id, want.ID)
			}
			if rule.Severity != want.Severity {
				t.Errorf("pack %q rule[%d]: Severity = %q want %q", pack.ID, i, rule.Severity, want.Severity)
			}
			if rule.Intent == "" {
				t.Errorf("pack %q rule[%d]: Intent empty", pack.ID, i)
			}
			if len(rule.MitreTechniques) == 0 {
				t.Errorf("pack %q rule[%d]: MitreTechniques empty", pack.ID, i)
			}
			if len(rule.Tags) == 0 {
				t.Errorf("pack %q rule[%d]: Tags empty", pack.ID, i)
			}
		}
	}
}
