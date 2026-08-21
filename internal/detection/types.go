// Package detection evaluates versioned, declarative detection rules.
//
// The package deliberately owns no database or provider credentials. A rule
// receives an immutable event and organization context and returns finding
// drafts. Persistence, deduplication against SecurityFinding, and provider
// remediation remain in the ingestion worker. This keeps rule evaluation
// deterministic and makes the same engine usable by backtests and tests.
package detection

import "time"

// Rule is the YAML representation of one stateless detection rule.
//
// Rule IDs and versions are public contracts. A rule version changes when its
// predicate, finding semantics, or dedupe target changes; callers can retain
// the old version while evaluating a new one during a controlled migration.
type Rule struct {
	ID              string      `yaml:"id" json:"id"`
	Version         string      `yaml:"version" json:"version"`
	Name            string      `yaml:"name" json:"name"`
	Severity        string      `yaml:"severity" json:"severity"`
	RiskScore       int         `yaml:"risk_score" json:"riskScore"`
	Tags            []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
	Source          Source      `yaml:"source" json:"source"`
	When            Condition   `yaml:"when" json:"when"`
	Dedupe          DedupeSpec  `yaml:"dedupe" json:"dedupe"`
	Finding         FindingSpec `yaml:"finding" json:"finding"`
	AutoResolveWhen *Condition  `yaml:"auto_resolve_when,omitempty" json:"autoResolveWhen,omitempty"`
}

// Source restricts evaluation before CEL runs. Event types are normalized in
// the same way as ingestion worker event types, so providers can use either
// audit-log names (for example repository.publicized) or canonical names.
type Source struct {
	Provider   string   `yaml:"provider" json:"provider"`
	EventTypes []string `yaml:"event_types" json:"eventTypes"`
}

// Condition is intentionally only an expression string. CEL is compiled at
// pack-load time and executes without access to Go functions, I/O, or a
// database.
type Condition struct {
	Expression string `yaml:"expression" json:"expression"`
}

// DedupeSpec defines the stable subject used by the worker's tenant-scoped
// dedupe key. Templates are deliberately logic-free.
type DedupeSpec struct {
	TargetTemplate string `yaml:"target_template" json:"targetTemplate"`
}

// FindingSpec is the operator-facing output of a rule.
type FindingSpec struct {
	TargetTemplate   string            `yaml:"target_template,omitempty" json:"targetTemplate,omitempty"`
	Title            string            `yaml:"title" json:"title"`
	Description      string            `yaml:"description" json:"description"`
	RemediationSteps []string          `yaml:"remediation_steps" json:"remediationSteps"`
	Evidence         map[string]string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

// Event is the provider-neutral input to the evaluator.
type Event struct {
	OrganizationID string
	IntegrationID  string
	Provider       string
	EventType      string
	Source         string
	Actor          string
	OccurredAt     time.Time
	Payload        map[string]any
}

// OrgContext contains non-secret tenant configuration explicitly made
// available to a rule. It is kept as data rather than a callback so a rule
// cannot perform I/O or escape the evaluator sandbox.
type OrgContext struct {
	Config     map[string]any
	Allowlists map[string]any
}

// Overrides are applied after a rule is selected. Disabled is the existing
// integration disabled_checks mechanism. SeverityOverrides is intentionally a
// separate map so a caller can preserve disabled-check expiry metadata while
// adding a severity policy in the same integration configuration JSON.
type Overrides struct {
	Disabled          map[string]bool
	SeverityOverrides map[string]string
}

// FindingDraft is pure evaluator output. DedupeTarget is the rendered,
// version-stable subject; the worker adds organization/integration identity
// before hashing the persisted dedupe key and records RuleVersion alongside
// the finding for migration-safe provenance.
type FindingDraft struct {
	RuleID           string
	RuleVersion      string
	Title            string
	Description      string
	Severity         string
	RiskScore        int
	Tags             []string
	RemediationSteps []string
	Target           string
	DedupeTarget     string
	Evidence         map[string]any
}

// ResolutionDraft identifies an open finding that a later clean event should
// resolve. The worker owns the state transition and must scope it by tenant,
// integration, rule ID, and rendered target.
type ResolutionDraft struct {
	RuleID       string
	RuleVersion  string
	DedupeTarget string
	Evidence     map[string]any
}

// BacktestReport summarizes deterministic replay over a fixture/event slice.
type BacktestReport struct {
	RuleID       string          `json:"ruleId"`
	RuleVersion  string          `json:"ruleVersion"`
	Events       int             `json:"events"`
	Candidates   int             `json:"candidates"`
	Matches      int             `json:"matches"`
	Resolutions  int             `json:"resolutions"`
	MatchSamples []BacktestMatch `json:"matchSamples,omitempty"`
}

// BacktestMatch is a small evidence sample suitable for CLI/API rendering.
type BacktestMatch struct {
	EventType    string `json:"eventType"`
	OccurredAt   string `json:"occurredAt"`
	Target       string `json:"target"`
	DedupeTarget string `json:"dedupeTarget"`
	Severity     string `json:"severity,omitempty"`
	Resolution   bool   `json:"resolution,omitempty"`
}
