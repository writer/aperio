package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPackRejectsUnknownFieldsAndDuplicateVersions(t *testing.T) {
	dir := t.TempDir()
	valid := `id: example.rule
version: 1.0.0
name: Example rule
severity: HIGH
risk_score: 75
source:
  provider: GITHUB
  event_types: [EVENT]
when:
  expression: event.payload.ok == true
dedupe:
  target_template: "{{ event.payload.id }}"
finding:
  title: Example
  description: Example description
`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err != nil {
		t.Fatalf("valid pack rejected: %v", err)
	}
	unknown := strings.Replace(valid, "name: Example rule", "name: Example rule\nunknown: true", 1)
	if err := os.WriteFile(filepath.Join(dir, "unknown.yaml"), []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestValidateRulesRejectsInvalidVersionsAndDuplicateIDs(t *testing.T) {
	rules, err := LoadEmbeddedPack(BuiltinFS, "rules/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(append([]Rule(nil), rules...), rules[0])
	if _, err := ValidateRules(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate rule") {
		t.Fatalf("duplicate error = %v", err)
	}
	otherVersion := rules[0]
	otherVersion.Version = "2.0.0"
	if _, err := ValidateRules([]Rule{rules[0], otherVersion}); err == nil || !strings.Contains(err.Error(), "cannot be active together") {
		t.Fatalf("duplicate id across versions error = %v", err)
	}
	invalid := rules[0]
	invalid.Version = "1.0"
	if _, err := ValidateRules([]Rule{invalid}); err == nil || !strings.Contains(err.Error(), "semantic version") {
		t.Fatalf("version error = %v", err)
	}
}
