package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/writer/aperio/internal/apiclient"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "aperioctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	baseURL := strings.TrimSpace(os.Getenv("APERIO_URL"))
	if baseURL == "" {
		baseURL = "http://localhost:4100"
	}
	client, err := apiclient.New(baseURL, os.Getenv("APERIO_API_TOKEN"))
	if err != nil {
		return err
	}
	var result any
	switch strings.Join(args, " ") {
	case "doctor":
		result, err = client.Health(ctx)
	case "finding list":
		result, err = client.RPC(ctx, "ListFindings", map[string]any{"limit": 100})
	case "connector list":
		result, err = client.RPC(ctx, "ListIntegrations", map[string]any{})
	case "siem status":
		result, err = client.RPC(ctx, "ListSiemDestinations", map[string]any{})
	case "token list":
		result, err = client.Compat(ctx, "GET", "/api/v1/admin/api-tokens", nil)
	default:
		if len(args) == 3 && args[0] == "connector" && args[1] == "sync" && strings.TrimSpace(args[2]) != "" {
			result, err = client.RPC(ctx, "ForceSyncIntegration", map[string]any{"integrationId": args[2]})
		} else if len(args) >= 3 && len(args) <= 4 && args[0] == "token" && args[1] == "create" {
			scope := "READ"
			if len(args) == 4 {
				scope = strings.ToUpper(args[3])
			}
			result, err = client.Compat(ctx, "POST", "/api/v1/admin/api-tokens", map[string]any{
				"name": args[2], "scopes": []string{scope},
			})
		} else if len(args) == 3 && args[0] == "token" && args[1] == "revoke" {
			result, err = client.Compat(ctx, "DELETE", "/api/v1/admin/api-tokens/"+args[2], nil)
		} else {
			return usageError()
		}
	}
	if err != nil {
		return err
	}
	return writeJSON(result)
}

func writeJSON(value any) error {
	var decoded any
	switch typed := value.(type) {
	case json.RawMessage:
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return err
		}
	default:
		decoded = value
	}
	output, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func usageError() error {
	return errors.New("usage: aperioctl doctor | finding list | connector list | connector sync ID | siem status | token list | token create NAME [READ|WRITE|ADMIN] | token revoke ID")
}
