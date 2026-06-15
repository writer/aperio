package syncwake

import "strings"

const (
	separator                   = "\t"
	ModeOAuthAfterDirectorySync = "oauth_after_directory_sync"
)

func Encode(integrationID, streamName string) string {
	id := strings.TrimSpace(integrationID)
	stream := strings.TrimSpace(streamName)
	if stream == "" {
		return id
	}
	return id + separator + stream
}

func Decode(payload string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(payload), separator, 2)
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}
