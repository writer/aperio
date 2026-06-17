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
