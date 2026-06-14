package ingestionworker

import "strings"

// Canonical severity strings used everywhere a Finding is produced. They
// match the database "Severity" enum and the API contract so the same
// literal flows untouched from a rule emitter through the DB and out to
// the UI without case folding at the boundary.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// baseRiskScore is the canonical starting score for a given severity. The
// table is intentionally small (5 buckets) so every evaluator picks the
// same base number for a given severity instead of free-handing 86, 88,
// or 92. Aggravators tune within the bucket without leaking up into
// neighboring severities — see RiskScoreFor.
//
//	CRITICAL  90  (max 100)
//	HIGH      75  (max 89)
//	MEDIUM    55  (max 74)
//	LOW       30  (max 54)
//	INFO      10  (max 29)
//
// The bucket *ceilings* are enforced by clampToSeverityBand so an
// over-zealous aggravator on a HIGH finding can never silently promote
// it to CRITICAL — that requires the rule to set the severity itself.
func baseRiskScore(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 90
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 55
	case SeverityLow:
		return 30
	case SeverityInfo:
		return 10
	default:
		return 50
	}
}

func severityCeiling(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 89
	case SeverityMedium:
		return 74
	case SeverityLow:
		return 54
	case SeverityInfo:
		return 29
	default:
		return 100
	}
}

func severityFloor(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case SeverityCritical:
		return 90
	case SeverityHigh:
		return 60
	case SeverityMedium:
		return 40
	case SeverityLow:
		return 20
	case SeverityInfo:
		return 1
	default:
		return 1
	}
}

// RiskScoreFor returns the canonical risk score for a finding of the given
// severity, optionally adjusted by aggravators. Result is clamped to the
// severity's own band so additive nudges never silently cross severity
// boundaries — bump the severity explicitly if a finding deserves a
// higher bucket. Negative aggravators are allowed for de-escalations
// (e.g. "MFA enrolled but not enforced" is less dangerous than "MFA not
// enrolled at all").
//
// Existing call sites with hand-picked numbers are replaced by
//
//	RiskScoreFor("CRITICAL")             // 90
//	RiskScoreFor("CRITICAL", 5)          // 95
//	RiskScoreFor("HIGH", 7)              // 82 (clamped to <= 89)
//	RiskScoreFor("HIGH", -4)             // 71
//	RiskScoreFor("HIGH", 50)             // 89 (clamped, severity unchanged)
func RiskScoreFor(severity string, aggravators ...int) int {
	score := baseRiskScore(severity)
	for _, a := range aggravators {
		score += a
	}
	return clampToSeverityBand(severity, score)
}

func clampToSeverityBand(severity string, score int) int {
	floor := severityFloor(severity)
	ceiling := severityCeiling(severity)
	if score < floor {
		return floor
	}
	if score > ceiling {
		return ceiling
	}
	return score
}
