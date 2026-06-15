package syncstate

import (
	"strings"
	"time"
)

const BackfillQueuedPrefix = "backfill queued; waiting for worker confirmation"

func BackfillQueuedMessage(from time.Time) string {
	return BackfillQueuedPrefix + " from " + from.UTC().Format(time.RFC3339Nano)
}

func IsBackfillQueued(lastErr string) bool {
	return strings.HasPrefix(strings.TrimSpace(lastErr), BackfillQueuedPrefix)
}
