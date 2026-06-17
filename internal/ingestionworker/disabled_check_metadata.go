package ingestionworker

import (
	"encoding/json"
	"strings"
	"time"
)

type disabledCheckMetadataEntry struct {
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expiresAt"`
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
