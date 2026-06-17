package bootstrap

import (
	"reflect"
	"testing"
	"time"
)

func TestApplyDisabledCheckExpiry(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	disabled := []string{"slack.a", "slack.b", "slack.c"}
	metadata := map[string]disabledCheckMetadataEntry{
		"slack.a": {
			Reason:    "temporary suppression",
			ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
		},
		"slack.b": {
			Reason:    "expired suppression",
			ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		"slack.c": {
			Reason:    "malformed",
			ExpiresAt: "not-a-time",
		},
	}

	effective, normalized, expired := applyDisabledCheckExpiry(disabled, metadata, now)
	if got, want := effective, []string{"slack.a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("effective disabled = %v, want %v", got, want)
	}
	if got, want := expired, []string{"slack.b", "slack.c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expired disabled = %v, want %v", got, want)
	}
	entry, ok := normalized["slack.a"]
	if !ok {
		t.Fatalf("normalized metadata missing slack.a: %+v", normalized)
	}
	if entry.ExpiresAt != now.Add(2*time.Hour).Format(time.RFC3339) {
		t.Fatalf("normalized expiry = %q, want %q", entry.ExpiresAt, now.Add(2*time.Hour).Format(time.RFC3339))
	}
}

func TestDecodeEncodeDisabledCheckMetadata(t *testing.T) {
	decoded := decodeDisabledCheckMetadata(`{"slack.a":{"reason":"ok","expiresAt":"2026-06-17T00:00:00Z"}}`)
	if len(decoded) != 1 {
		t.Fatalf("decoded entries = %d, want 1", len(decoded))
	}
	if got := encodeDisabledCheckMetadata(decoded); got == "" || got == "{}" {
		t.Fatalf("encoded metadata = %q, want non-empty JSON object", got)
	}
	if got := decodeDisabledCheckMetadata("not-json"); len(got) != 0 {
		t.Fatalf("decode invalid JSON = %v, want empty map", got)
	}
}
