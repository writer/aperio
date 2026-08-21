package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
)

const maxBacktestSamples = 20

var templatePattern = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

type compiledRule struct {
	rule        Rule
	when        cel.Program
	autoResolve cel.Program
}

// Engine compiles a rule pack once and evaluates it without I/O. CEL's
// standard environment is intentionally limited to three dynamic bindings;
// rules cannot call Go functions or access process state.
type Engine struct {
	rules []compiledRule
}

// NewEngine validates and compiles rules. Compilation is the trust boundary:
// callers should refuse to activate a pack when this returns an error.
func NewEngine(rules []Rule) (*Engine, error) {
	rules, err := ValidateRules(rules)
	if err != nil {
		return nil, err
	}
	env, err := cel.NewEnv(
		cel.Variable("event", cel.DynType),
		cel.Variable("org", cel.DynType),
		cel.Variable("now", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		when, err := compileExpression(env, rule.ID, rule.When.Expression)
		if err != nil {
			return nil, err
		}
		var autoResolve cel.Program
		if rule.AutoResolveWhen != nil {
			autoResolve, err = compileExpression(env, rule.ID+" auto_resolve_when", rule.AutoResolveWhen.Expression)
			if err != nil {
				return nil, err
			}
		}
		compiled = append(compiled, compiledRule{rule: rule, when: when, autoResolve: autoResolve})
	}
	return &Engine{rules: compiled}, nil
}

func compileExpression(env *cel.Env, name, expression string) (cel.Program, error) {
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile rule %q expression: %w", name, issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("build rule %q program: %w", name, err)
	}
	return program, nil
}

// Rules returns a stable copy of the compiled pack metadata.
func (e *Engine) Rules() []Rule {
	if e == nil {
		return nil
	}
	out := make([]Rule, 0, len(e.rules))
	for _, item := range e.rules {
		out = append(out, item.rule)
	}
	return out
}

// Evaluate produces one draft per matching rule. Event type filtering and
// tenant overrides happen before CEL evaluation. A runtime expression error
// is returned rather than treated as a match; callers can fail closed and
// preserve an error/metrics record for operators.
func (e *Engine) Evaluate(event Event, org OrgContext, overrides Overrides) ([]FindingDraft, error) {
	if e == nil {
		return nil, errors.New("detection engine is nil")
	}
	if event.Payload == nil {
		event.Payload = map[string]any{}
	}
	now := event.OccurredAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := make([]FindingDraft, 0, 2)
	for _, item := range e.rules {
		rule := item.rule
		if strings.TrimSpace(event.Provider) == "" || !strings.EqualFold(strings.TrimSpace(event.Provider), strings.TrimSpace(rule.Source.Provider)) {
			continue
		}
		if !matchesEventType(rule.Source.EventTypes, event.EventType) {
			continue
		}
		if overrides.Disabled != nil && overrides.Disabled[rule.ID] {
			continue
		}
		matched, err := evaluateBoolean(item.when, event, org, now)
		if err != nil {
			return nil, fmt.Errorf("evaluate rule %s: %w", rule.ID, err)
		}
		if !matched {
			continue
		}
		target, err := renderTemplate(rule.Dedupe.TargetTemplate, event, org, now, true)
		if err != nil {
			return nil, fmt.Errorf("render rule %s dedupe target: %w", rule.ID, err)
		}
		findingTarget := target
		if strings.TrimSpace(rule.Finding.TargetTemplate) != "" {
			findingTarget, err = renderTemplate(rule.Finding.TargetTemplate, event, org, now, true)
			if err != nil {
				return nil, fmt.Errorf("render rule %s finding target: %w", rule.ID, err)
			}
		}
		title, err := renderTemplate(rule.Finding.Title, event, org, now, false)
		if err != nil {
			return nil, fmt.Errorf("render rule %s title: %w", rule.ID, err)
		}
		description, err := renderTemplate(rule.Finding.Description, event, org, now, false)
		if err != nil {
			return nil, fmt.Errorf("render rule %s description: %w", rule.ID, err)
		}
		steps := make([]string, 0, len(rule.Finding.RemediationSteps))
		for _, step := range rule.Finding.RemediationSteps {
			rendered, err := renderTemplate(step, event, org, now, false)
			if err != nil {
				return nil, fmt.Errorf("render rule %s remediation step: %w", rule.ID, err)
			}
			steps = append(steps, rendered)
		}
		evidence := make(map[string]any, len(rule.Finding.Evidence))
		for key, template := range rule.Finding.Evidence {
			rendered, err := renderTemplate(template, event, org, now, false)
			if err != nil {
				return nil, fmt.Errorf("render rule %s evidence %q: %w", rule.ID, key, err)
			}
			evidence[key] = rendered
		}
		severity := strings.ToUpper(strings.TrimSpace(rule.Severity))
		if override := strings.TrimSpace(overrides.SeverityOverrides[rule.ID]); override != "" {
			severity = strings.ToUpper(override)
			if !validSeverity(severity) {
				return nil, fmt.Errorf("severity override for %s is invalid: %q", rule.ID, override)
			}
		}
		out = append(out, FindingDraft{
			RuleID:           rule.ID,
			RuleVersion:      rule.Version,
			Title:            title,
			Description:      description,
			Severity:         severity,
			RiskScore:        clampRiskScore(severity, rule.RiskScore),
			Tags:             append([]string(nil), rule.Tags...),
			RemediationSteps: steps,
			Target:           findingTarget,
			DedupeTarget:     target,
			Evidence:         evidence,
		})
	}
	return out, nil
}

// AutoResolve evaluates clean-event predicates for open finding state. It
// does not mutate storage; the ingestion worker must perform the scoped
// transition using the returned rule ID and target.
func (e *Engine) AutoResolve(event Event, org OrgContext, overrides Overrides) ([]ResolutionDraft, error) {
	if e == nil {
		return nil, errors.New("detection engine is nil")
	}
	now := event.OccurredAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := make([]ResolutionDraft, 0, 1)
	for _, item := range e.rules {
		rule := item.rule
		if item.autoResolve == nil || strings.TrimSpace(event.Provider) == "" || !strings.EqualFold(strings.TrimSpace(event.Provider), strings.TrimSpace(rule.Source.Provider)) {
			continue
		}
		if !matchesEventType(rule.Source.EventTypes, event.EventType) {
			continue
		}
		if overrides.Disabled != nil && overrides.Disabled[rule.ID] {
			continue
		}
		matched, err := evaluateBoolean(item.autoResolve, event, org, now)
		if err != nil {
			return nil, fmt.Errorf("evaluate auto-resolve rule %s: %w", rule.ID, err)
		}
		if !matched {
			continue
		}
		target, err := renderTemplate(rule.Dedupe.TargetTemplate, event, org, now, true)
		if err != nil {
			// A clean event without a stable subject must never resolve an
			// unrelated finding. Fail closed for this rule.
			continue
		}
		out = append(out, ResolutionDraft{
			RuleID:       rule.ID,
			RuleVersion:  rule.Version,
			DedupeTarget: target,
			Evidence: map[string]any{
				"ruleId":      rule.ID,
				"ruleVersion": rule.Version,
				"subject":     target,
				"resolution":  "auto_resolve_when",
				"eventType":   event.EventType,
			},
		})
	}
	return out, nil
}

// Backtest replays events through one rule. It is intentionally in-memory so
// callers can use fixture events in CI or a bounded database query without
// granting the evaluator database access.
func (e *Engine) Backtest(ruleID string, events []Event, org OrgContext, overrides Overrides) (BacktestReport, error) {
	item, ok := e.findRule(ruleID)
	if !ok {
		return BacktestReport{}, fmt.Errorf("rule %q is not loaded", ruleID)
	}
	report := BacktestReport{RuleID: item.rule.ID, RuleVersion: item.rule.Version, Events: len(events)}
	for _, event := range events {
		if !strings.EqualFold(strings.TrimSpace(event.Provider), strings.TrimSpace(item.rule.Source.Provider)) || !matchesEventType(item.rule.Source.EventTypes, event.EventType) {
			continue
		}
		report.Candidates++
		findings, err := e.Evaluate(event, org, overrides)
		if err != nil {
			return report, err
		}
		for _, finding := range findings {
			if finding.RuleID != item.rule.ID {
				continue
			}
			report.Matches++
			if len(report.MatchSamples) < maxBacktestSamples {
				report.MatchSamples = append(report.MatchSamples, BacktestMatch{
					EventType:    event.EventType,
					OccurredAt:   event.OccurredAt.UTC().Format(time.RFC3339Nano),
					Target:       finding.Target,
					DedupeTarget: finding.DedupeTarget,
					Severity:     finding.Severity,
				})
			}
		}
		resolutions, err := e.AutoResolve(event, org, overrides)
		if err != nil {
			return report, err
		}
		for _, resolution := range resolutions {
			if resolution.RuleID != item.rule.ID {
				continue
			}
			report.Resolutions++
			if len(report.MatchSamples) < maxBacktestSamples {
				report.MatchSamples = append(report.MatchSamples, BacktestMatch{
					EventType:    event.EventType,
					OccurredAt:   event.OccurredAt.UTC().Format(time.RFC3339Nano),
					DedupeTarget: resolution.DedupeTarget,
					Resolution:   true,
				})
			}
		}
	}
	return report, nil
}

func (e *Engine) findRule(id string) (compiledRule, bool) {
	for _, item := range e.rules {
		if item.rule.ID == id {
			return item, true
		}
	}
	return compiledRule{}, false
}

func evaluateBoolean(program cel.Program, event Event, org OrgContext, now time.Time) (bool, error) {
	activation := map[string]any{
		"event": map[string]any{
			"organization_id":       event.OrganizationID,
			"integration_id":        event.IntegrationID,
			"provider":              event.Provider,
			"event_type":            event.EventType,
			"event_type_normalized": normalizeEventType(event.EventType),
			"source":                event.Source,
			"actor":                 event.Actor,
			"occurred_at":           event.OccurredAt.UTC().Format(time.RFC3339Nano),
			"payload":               event.Payload,
		},
		"org": map[string]any{
			"config":     org.Config,
			"allowlists": org.Allowlists,
		},
		"now": now.UTC().Format(time.RFC3339Nano),
	}
	value, _, err := program.Eval(activation)
	if err != nil {
		return false, err
	}
	boolean, ok := value.(types.Bool)
	if !ok {
		return false, fmt.Errorf("expression returned %s, want bool", value.Type().TypeName())
	}
	return bool(boolean), nil
}

func renderTemplate(template string, event Event, org OrgContext, now time.Time, required bool) (string, error) {
	trimmed := strings.TrimSpace(template)
	if trimmed == "" {
		if required {
			return "", errors.New("template is empty")
		}
		return "", nil
	}
	activation := map[string]any{
		"event": map[string]any{
			"organization_id":       event.OrganizationID,
			"integration_id":        event.IntegrationID,
			"provider":              event.Provider,
			"event_type":            event.EventType,
			"event_type_normalized": normalizeEventType(event.EventType),
			"source":                event.Source,
			"actor":                 event.Actor,
			"occurred_at":           event.OccurredAt.UTC().Format(time.RFC3339Nano),
			"payload":               event.Payload,
		},
		"org": map[string]any{
			"config":     org.Config,
			"allowlists": org.Allowlists,
		},
		"now": now.UTC().Format(time.RFC3339Nano),
	}
	missing := ""
	result := templatePattern.ReplaceAllStringFunc(template, func(match string) string {
		parts := templatePattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			missing = match
			return ""
		}
		value, ok := resolveTemplateValue(strings.TrimSpace(parts[1]), activation)
		if !ok || value == nil {
			missing = parts[1]
			return ""
		}
		return fmt.Sprint(value)
	})
	if missing != "" && required {
		return "", fmt.Errorf("template path %q is missing", missing)
	}
	if required && strings.TrimSpace(result) == "" {
		return "", errors.New("template rendered an empty value")
	}
	return result, nil
}

// resolveTemplateValue supports a deliberately tiny, logic-free template
// vocabulary. Plain dotted paths cover most rules. first_nonempty(...) is
// useful when a provider emits the same field under two documented payload
// shapes. external_recipient(...) selects the first email outside the owner
// domain and handles either a scalar or a JSON array. No loops, conditionals,
// functions, or arbitrary CEL are accepted here.
func resolveTemplateValue(expression string, activation map[string]any) (any, bool) {
	if strings.HasPrefix(expression, "first_nonempty(") && strings.HasSuffix(expression, ")") {
		args := splitTemplateArgs(strings.TrimSuffix(strings.TrimPrefix(expression, "first_nonempty("), ")"))
		for _, arg := range args {
			value, ok := resolvePath(activation, strings.TrimSpace(arg))
			if ok && !isEmptyTemplateValue(value) {
				return value, true
			}
		}
		return nil, false
	}
	if strings.HasPrefix(expression, "external_recipient(") && strings.HasSuffix(expression, ")") {
		args := splitTemplateArgs(strings.TrimSuffix(strings.TrimPrefix(expression, "external_recipient("), ")"))
		ownerDomain := ""
		if len(args) > 0 {
			if value, ok := resolvePath(activation, strings.TrimSpace(args[len(args)-1])); ok {
				ownerDomain = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
			}
			if index := strings.LastIndex(ownerDomain, "@"); index >= 0 {
				ownerDomain = ownerDomain[index+1:]
			}
		}
		for _, arg := range args[:max(0, len(args)-1)] {
			value, ok := resolvePath(activation, strings.TrimSpace(arg))
			if !ok {
				continue
			}
			for _, candidate := range flattenTemplateValues(value) {
				email := strings.TrimSpace(fmt.Sprint(candidate))
				if email == "" || !strings.Contains(email, "@") {
					continue
				}
				at := strings.LastIndex(email, "@")
				if ownerDomain == "" || !strings.EqualFold(email[at+1:], ownerDomain) {
					return email, true
				}
			}
		}
		return nil, false
	}
	return resolvePath(activation, expression)
}

func splitTemplateArgs(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, strings.TrimSpace(part))
		}
	}
	return out
}

func flattenTemplateValues(value any) []any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, flattenTemplateValues(item)...)
		}
		return out
	case []string:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	default:
		return []any{value}
	}
}

func isEmptyTemplateValue(value any) bool {
	if value == nil {
		return true
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) == ""
	}
	return false
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func resolvePath(root map[string]any, path string) (any, bool) {
	var current any = root
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func matchesEventType(allowed []string, actual string) bool {
	normalized := normalizeEventType(actual)
	for _, candidate := range allowed {
		if normalized == normalizeEventType(candidate) {
			return true
		}
	}
	return false
}

func clampRiskScore(severity string, score int) int {
	if score == 0 {
		score = map[string]int{"CRITICAL": 90, "HIGH": 75, "MEDIUM": 55, "LOW": 30, "INFO": 10}[severity]
	}
	floor, ceiling := 1, 100
	switch severity {
	case "CRITICAL":
		floor = 90
	case "HIGH":
		floor, ceiling = 60, 89
	case "MEDIUM":
		floor, ceiling = 40, 74
	case "LOW":
		floor, ceiling = 20, 54
	case "INFO":
		floor, ceiling = 1, 29
	}
	if score < floor {
		return floor
	}
	if score > ceiling {
		return ceiling
	}
	return score
}

// DedupeMaterial is provided for callers that need to inspect the exact
// versioned material without duplicating the hash implementation.
func DedupeMaterial(rule Rule, target string) string {
	return rule.ID + "@" + rule.Version + ":" + target
}

// VersionedDedupeHash returns a stable content hash for external backtest
// reports and future version-aware persistence. The current worker keeps the
// legacy ID-plus-target persisted key so existing findings do not fork during
// this migration, and stores RuleVersion in finding provenance.
func VersionedDedupeHash(rule Rule, target string) string {
	digest := sha256.Sum256([]byte(DedupeMaterial(rule, target)))
	return hex.EncodeToString(digest[:])
}

// SortedRuleIDs is useful for support-matrix and diagnostics output.
func SortedRuleIDs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.ID)
	}
	sort.Strings(out)
	return out
}
