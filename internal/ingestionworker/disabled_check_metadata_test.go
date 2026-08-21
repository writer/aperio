package ingestionworker

import (
	"reflect"
	"testing"
	"time"
)

func TestApplyDisabledCheckExpiry(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	got := applyDisabledCheckExpiry(
		[]string{"slack.a", "slack.b", "slack.c"},
		map[string]disabledCheckMetadataEntry{
			"slack.a": {Reason: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
			"slack.b": {Reason: "expired", ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)},
			"slack.c": {Reason: "invalid", ExpiresAt: "not-a-time"},
		},
		now,
	)
	want := []string{"slack.a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effective disabled checks = %v, want %v", got, want)
	}
}

func TestSeverityOverridesFromMetadata(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	got := severityOverridesFromMetadata(map[string]disabledCheckMetadataEntry{
		"slack.mfa_disabled":               {Severity: "high", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		"github.public_repository_created": {Severity: "LOW"},
		"slack.expired":                    {Severity: "CRITICAL", ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)},
		"slack.invalid":                    {Severity: "urgent"},
	}, now)
	want := map[string]string{
		"slack.mfa_disabled":               SeverityHigh,
		"github.public_repository_created": SeverityLow,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("severity overrides = %#v, want %#v", got, want)
	}
}
