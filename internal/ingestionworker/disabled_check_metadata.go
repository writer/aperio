package ingestionworker

import (
	"encoding/json"
	"strings"
	"time"
)

type disabledCheckMetadataEntry struct {
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expiresAt"`
	Severity  string `json:"severity,omitempty"`
}

func decodeDisabledCheckMetadata(raw string) map[string]disabledCheckMetadataEntry {
	if strings.TrimSpace(raw) == "" {
		return map[string]disabledCheckMetadataEntry{}
	}
	out := map[string]disabledCheckMetadataEntry{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]disabledCheckMetadataEntry{}
	}
	if out == nil {
		return map[string]disabledCheckMetadataEntry{}
	}
	return out
}

func applyDisabledCheckExpiry(disabled []string, metadata map[string]disabledCheckMetadataEntry, now time.Time) []string {
	effective := make([]string, 0, len(disabled))
	seen := make(map[string]struct{}, len(disabled))
	for _, raw := range disabled {
		key := strings.TrimSpace(raw)
		if key == "" {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		entry, ok := metadata[key]
		if !ok {
			effective = append(effective, key)
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresAt))
		if err != nil || !expiresAt.After(now) {
			continue
		}
		effective = append(effective, key)
	}
	return effective
}

// severityOverridesFromMetadata reads the optional severity policy stored
// alongside disabled_checks. It intentionally accepts only canonical finding
// severities and ignores expired/invalid entries so a malformed tenant policy
// cannot make the worker fail or emit an invalid database enum.
func severityOverridesFromMetadata(metadata map[string]disabledCheckMetadataEntry, now time.Time) map[string]string {
	out := make(map[string]string)
	for key, entry := range metadata {
		severity := strings.ToUpper(strings.TrimSpace(entry.Severity))
		if key == "" || !validFindingSeverity(severity) {
			continue
		}
		if expiresAt := strings.TrimSpace(entry.ExpiresAt); expiresAt != "" {
			expires, err := time.Parse(time.RFC3339, expiresAt)
			if err != nil || !expires.After(now) {
				continue
			}
		}
		out[key] = severity
	}
	return out
}
