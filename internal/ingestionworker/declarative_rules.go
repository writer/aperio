package ingestionworker

import (
	"sync"

	"github.com/writer/aperio/internal/detection"
)

type declarativeResolution struct {
	RuleID       string
	RuleVersion  string
	DedupeTarget string
}

var (
	builtinDetectionOnce   sync.Once
	builtinDetectionEngine *detection.Engine
	builtinDetectionErr    error

	// These rules are the first migration slice. The hardcoded evaluators stay
	// in worker.go as a fail-closed fallback if a pack cannot compile, but are
	// not run when the reviewed declarative engine is healthy.
	declarativeRuleIDs = map[string]bool{
		"github.public_repository_created":          true,
		"slack.mfa_disabled":                        true,
		"slack.external_shared_channel_created":     true,
		"google_workspace.external_sharing_enabled": true,
	}
)

func builtinDetection() (*detection.Engine, error) {
	builtinDetectionOnce.Do(func() {
		var rules []detection.Rule
		rules, builtinDetectionErr = detection.LoadEmbeddedPack(detection.BuiltinFS, "rules/*.yaml")
		if builtinDetectionErr != nil {
			return
		}
		builtinDetectionEngine, builtinDetectionErr = detection.NewEngine(rules)
	})
	return builtinDetectionEngine, builtinDetectionErr
}

func evaluateDeclarativeRules(payload JobPayload, disabledChecks []string, severityOverrides map[string]string) ([]Finding, bool) {
	engine, err := builtinDetection()
	if err != nil {
		return nil, false
	}
	disabled := make(map[string]bool, len(disabledChecks))
	for _, key := range disabledChecks {
		disabled[key] = true
	}
	drafts, err := engine.Evaluate(toDetectionEvent(payload), detection.OrgContext{}, detection.Overrides{
		Disabled:          disabled,
		SeverityOverrides: severityOverrides,
	})
	if err != nil {
		// A malformed provider payload must not suppress the established
		// evaluator. Keep the migration fail-closed and let the caller use
		// the hardcoded parity implementation for this event.
		return nil, false
	}
	out := make([]Finding, 0, len(drafts))
	for _, draft := range drafts {
		out = append(out, Finding{
			RuleID:           draft.RuleID,
			RuleVersion:      draft.RuleVersion,
			Title:            draft.Title,
			Description:      draft.Description,
			Severity:         draft.Severity,
			RiskScore:        draft.RiskScore,
			RemediationSteps: draft.RemediationSteps,
			Target:           draft.Target,
			DedupeTarget:     draft.DedupeTarget,
			Evidence:         draft.Evidence,
			Tags:             draft.Tags,
		})
	}
	return out, true
}

// DeclarativeAutoResolutions is intentionally pure. The worker or a future
// backtest/API caller supplies the returned rule/target pair to its own
// tenant-scoped state transition. No database access occurs here.
func DeclarativeAutoResolutions(payload JobPayload, disabledChecks []string) ([]detection.ResolutionDraft, bool) {
	engine, err := builtinDetection()
	if err != nil {
		return nil, false
	}
	disabled := make(map[string]bool, len(disabledChecks))
	for _, key := range disabledChecks {
		disabled[key] = true
	}
	resolutions, err := engine.AutoResolve(toDetectionEvent(payload), detection.OrgContext{}, detection.Overrides{Disabled: disabled})
	if err != nil {
		return nil, false
	}
	return resolutions, true
}

func declarativeResolutionTargets(payload JobPayload, disabledChecks []string) ([]declarativeResolution, bool) {
	drafts, loaded := DeclarativeAutoResolutions(payload, disabledChecks)
	if !loaded {
		return nil, false
	}
	out := make([]declarativeResolution, 0, len(drafts))
	for _, draft := range drafts {
		out = append(out, declarativeResolution{
			RuleID:       draft.RuleID,
			RuleVersion:  draft.RuleVersion,
			DedupeTarget: draft.DedupeTarget,
		})
	}
	return out, true
}

func toDetectionEvent(payload JobPayload) detection.Event {
	return detection.Event{
		OrganizationID: payload.OrganizationID,
		IntegrationID:  payload.IntegrationID,
		Provider:       payload.Provider,
		EventType:      payload.EventType,
		Source:         payload.Source,
		Actor:          payload.Actor,
		OccurredAt:     payload.OccurredAt,
		Payload:        payload.Payload,
	}
}
