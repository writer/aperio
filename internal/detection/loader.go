package detection

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxRuleBytes       = 128 * 1024
	maxExpressionBytes = 16 * 1024
	maxTemplateBytes   = 8 * 1024
)

var (
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{1,159}$`)
)

// BuiltinFS contains the reviewed P1 rules shipped with Aperio. Callers can
// use LoadPack on a filesystem for operator-supplied packs; production worker
// startup uses BuiltinEngine so it does not depend on the process cwd.
//
//go:embed rules/*.yaml
var BuiltinFS embed.FS

// LoadPack reads and validates all YAML rule files directly in dir. Nested
// directories are not walked implicitly: packs are versioned directories and
// callers must choose the exact provider pack they intend to activate.
func LoadPack(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rule pack %q: %w", dir, err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("rule pack %q contains no YAML files", dir)
	}
	rules := make([]Rule, 0, len(paths))
	for _, path := range paths {
		rule, err := loadRuleFile(path, os.ReadFile)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return ValidateRules(rules)
}

// LoadEmbeddedPack loads YAML rules from an fs.FS, which makes the built-in
// rules easy to test without relying on the machine filesystem.
func LoadEmbeddedPack(source fs.FS, pattern string) ([]Rule, error) {
	paths, err := fs.Glob(source, pattern)
	if err != nil {
		return nil, fmt.Errorf("glob embedded rule pack %q: %w", pattern, err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("embedded rule pack %q contains no YAML files", pattern)
	}
	rules := make([]Rule, 0, len(paths))
	for _, path := range paths {
		rule, err := loadRuleFile(path, func(name string) ([]byte, error) {
			return fs.ReadFile(source, name)
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return ValidateRules(rules)
}

func loadRuleFile(path string, readFile func(string) ([]byte, error)) (Rule, error) {
	raw, err := readFile(path)
	if err != nil {
		return Rule{}, fmt.Errorf("read rule %q: %w", path, err)
	}
	if len(raw) == 0 || len(raw) > maxRuleBytes {
		return Rule{}, fmt.Errorf("rule %q must be between 1 and %d bytes", path, maxRuleBytes)
	}
	var rule Rule
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rule); err != nil {
		return Rule{}, fmt.Errorf("decode rule %q: %w", path, err)
	}
	if err := validateRule(rule); err != nil {
		return Rule{}, fmt.Errorf("validate rule %q: %w", path, err)
	}
	return rule, nil
}

// ValidateRules validates a complete pack and rejects duplicate rule IDs.
// There is one active version per ID in an Engine; a version change is a
// replacement that must be rolled out deliberately rather than two programs
// competing for the same persisted finding key. Returning a fresh slice also
// makes a caller's subsequent append unable to mutate the loader's registry
// accidentally.
func ValidateRules(rules []Rule) ([]Rule, error) {
	if len(rules) == 0 {
		return nil, errors.New("rule pack is empty")
	}
	seen := make(map[string]string, len(rules))
	out := make([]Rule, len(rules))
	copy(out, rules)
	for index, rule := range out {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("rule %d: %w", index, err)
		}
		normalized := rule
		normalized.ID = strings.TrimSpace(rule.ID)
		normalized.Version = strings.TrimSpace(rule.Version)
		normalized.Name = strings.TrimSpace(rule.Name)
		normalized.Severity = strings.ToUpper(strings.TrimSpace(rule.Severity))
		normalized.Source.Provider = strings.ToUpper(strings.TrimSpace(rule.Source.Provider))
		normalized.Source.EventTypes = append([]string(nil), rule.Source.EventTypes...)
		for eventIndex, eventType := range normalized.Source.EventTypes {
			normalized.Source.EventTypes[eventIndex] = strings.TrimSpace(eventType)
		}
		normalized.Tags = append([]string(nil), rule.Tags...)
		normalized.Finding.RemediationSteps = append([]string(nil), rule.Finding.RemediationSteps...)
		if rule.Finding.Evidence != nil {
			normalized.Finding.Evidence = make(map[string]string, len(rule.Finding.Evidence))
			for key, value := range rule.Finding.Evidence {
				normalized.Finding.Evidence[key] = value
			}
		}
		out[index] = normalized
		if previousVersion, duplicate := seen[normalized.ID]; duplicate {
			return nil, fmt.Errorf("duplicate rule id %s (versions %s and %s cannot be active together)", normalized.ID, previousVersion, normalized.Version)
		}
		seen[normalized.ID] = normalized.Version
	}
	return out, nil
}

func validateRule(rule Rule) error {
	if !ruleIDPattern.MatchString(strings.TrimSpace(rule.ID)) {
		return fmt.Errorf("id must match %s", ruleIDPattern.String())
	}
	if !semverPattern.MatchString(strings.TrimSpace(rule.Version)) {
		return errors.New("version must be semantic version X.Y.Z")
	}
	if strings.TrimSpace(rule.Name) == "" || len(rule.Name) > 220 {
		return errors.New("name is required and must be at most 220 characters")
	}
	rule.Severity = strings.ToUpper(strings.TrimSpace(rule.Severity))
	if !validSeverity(rule.Severity) {
		return fmt.Errorf("severity %q is not one of CRITICAL, HIGH, MEDIUM, LOW, INFO", rule.Severity)
	}
	if rule.RiskScore < 0 || rule.RiskScore > 100 {
		return errors.New("risk_score must be between 0 and 100")
	}
	provider := strings.ToUpper(strings.TrimSpace(rule.Source.Provider))
	if provider == "" {
		return errors.New("source.provider is required")
	}
	if len(rule.Source.EventTypes) == 0 {
		return errors.New("source.event_types must contain at least one event type")
	}
	for index, eventType := range rule.Source.EventTypes {
		if strings.TrimSpace(eventType) == "" {
			return fmt.Errorf("source.event_types[%d] is empty", index)
		}
	}
	if err := validateExpression("when.expression", rule.When.Expression); err != nil {
		return err
	}
	if strings.TrimSpace(rule.Dedupe.TargetTemplate) == "" {
		return errors.New("dedupe.target_template is required")
	}
	if len(rule.Dedupe.TargetTemplate) > maxTemplateBytes {
		return fmt.Errorf("dedupe.target_template must be at most %d bytes", maxTemplateBytes)
	}
	if strings.TrimSpace(rule.Finding.Title) == "" || len(rule.Finding.Title) > 220 {
		return errors.New("finding.title is required and must be at most 220 characters")
	}
	if len(rule.Finding.TargetTemplate) > maxTemplateBytes {
		return fmt.Errorf("finding.target_template must be at most %d bytes", maxTemplateBytes)
	}
	if strings.TrimSpace(rule.Finding.Description) == "" {
		return errors.New("finding.description is required")
	}
	for index, step := range rule.Finding.RemediationSteps {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("finding.remediation_steps[%d] is empty", index)
		}
		if len(step) > maxTemplateBytes {
			return fmt.Errorf("finding.remediation_steps[%d] is too long", index)
		}
	}
	for key, value := range rule.Finding.Evidence {
		if strings.TrimSpace(key) == "" {
			return errors.New("finding.evidence contains an empty key")
		}
		if len(value) > maxTemplateBytes {
			return fmt.Errorf("finding.evidence[%q] is too long", key)
		}
	}
	if rule.AutoResolveWhen != nil {
		if err := validateExpression("auto_resolve_when.expression", rule.AutoResolveWhen.Expression); err != nil {
			return err
		}
	}
	return nil
}

func validateExpression(name, expression string) error {
	if strings.TrimSpace(expression) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(expression) > maxExpressionBytes {
		return fmt.Errorf("%s must be at most %d bytes", name, maxExpressionBytes)
	}
	return nil
}

func validSeverity(value string) bool {
	switch value {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return true
	default:
		return false
	}
}

func normalizeEventType(value string) string {
	var builder strings.Builder
	separator := false
	for _, char := range strings.ToUpper(strings.TrimSpace(value)) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
			separator = false
			continue
		}
		if !separator {
			builder.WriteByte('_')
			separator = true
		}
	}
	return strings.Trim(builder.String(), "_")
}
