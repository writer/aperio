package mcpbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestServerLifecycleAndErrorFrames(t *testing.T) {
	input := joinFrames(t,
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}},
		map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"},
		map[string]any{"jsonrpc": "2.0", "id": "ping-1", "method": "ping"},
		map[string]any{"jsonrpc": "2.0", "id": "missing", "method": "aperio/unknown"},
	) + "Content-Length: 7\r\n\r\n{\"bad\":"
	input += frameString(t, map[string]any{"jsonrpc": "2.0", "id": "ping-2", "method": "ping"})

	stdout := runServer(t, NewServer(fakeRunner{}), strings.NewReader(input))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 5 {
		t.Fatalf("frame count = %d, want 5: %#v", len(frames), frames)
	}

	initialize := frames[0]["result"].(map[string]any)
	if frames[0]["id"].(float64) != 1 || initialize["protocolVersion"] != ProtocolVersion {
		t.Fatalf("initialize response drifted: %#v", frames[0])
	}
	serverInfo := initialize["serverInfo"].(map[string]any)
	if serverInfo["name"] != ServerName {
		t.Fatalf("serverInfo = %#v", serverInfo)
	}
	if serverInfo["title"] != ServerTitle {
		t.Fatalf("serverInfo missing title: %#v", serverInfo)
	}
	capabilities := initialize["capabilities"].(map[string]any)
	tools, ok := capabilities["tools"].(map[string]any)
	if !ok || tools["listChanged"] != false {
		t.Fatalf("initialize tools capability drifted: %#v", initialize)
	}
	resources, ok := capabilities["resources"].(map[string]any)
	if !ok || resources["subscribe"] != false || resources["listChanged"] != false {
		t.Fatalf("initialize capabilities missing resources: %#v", initialize)
	}
	if _, ok := capabilities["prompts"]; ok {
		t.Fatalf("initialize advertised unimplemented prompts capability: %#v", initialize)
	}

	if result := frames[1]["result"].(map[string]any); len(result) != 0 || frames[1]["id"] != "ping-1" {
		t.Fatalf("ping response drifted: %#v", frames[1])
	}
	unknownErr := frames[2]["error"].(map[string]any)
	if unknownErr["code"].(float64) != -32601 {
		t.Fatalf("unknown method error = %#v", unknownErr)
	}
	parseErr := frames[3]["error"].(map[string]any)
	if parseErr["code"].(float64) != -32700 || frames[3]["id"] != nil {
		t.Fatalf("parse error = %#v", frames[3])
	}
	if frames[4]["id"] != "ping-2" {
		t.Fatalf("broker did not recover for ping after malformed JSON: %#v", frames[4])
	}
}

func TestServerToolsListAndUTF8Framing(t *testing.T) {
	stdout := runServer(t, NewServer(fakeRunner{}), strings.NewReader(joinFrames(t,
		map[string]any{"jsonrpc": "2.0", "id": "工具", "method": "tools/list"},
	)))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("frame count = %d, want 1", len(frames))
	}
	if frames[0]["id"] != "工具" {
		t.Fatalf("multibyte id was not preserved: %#v", frames[0])
	}
	tools := frames[0]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("tools/list returned %d tools, want 11", len(tools))
	}
	for index, expected := range []string{
		"aperio.register_agent",
		"aperio.create_task",
		"aperio.send_message",
		"aperio.list_tasks",
		"aperio.propose_remediation",
		"aperio.enqueue_siem_payload",
		"aperio.list_cerebro_incidents",
		"aperio.get_cerebro_incident_context",
		"aperio.list_cerebro_findings",
		"aperio.get_cerebro_finding_context",
		"aperio.propose_cerebro_response",
	} {
		tool := tools[index].(map[string]any)
		if tool["name"] != expected {
			t.Fatalf("tool[%d] = %#v, want %s", index, tool["name"], expected)
		}
		if tool["description"] == "" || tool["inputSchema"] == nil {
			t.Fatalf("tool[%d] missing description or schema: %#v", index, tool)
		}
	}
}

func TestServerResourcesListTemplatesAndRead(t *testing.T) {
	runner := &resourceFakeRunner{}
	stdout := runServer(t, NewServer(runner), strings.NewReader(joinFrames(t,
		map[string]any{"jsonrpc": "2.0", "id": "resources", "method": "resources/list"},
		map[string]any{"jsonrpc": "2.0", "id": "templates", "method": "resources/templates/list"},
		resourceRead("read", "cerebro://aperio/org_1/incidents/inc_1", "secret-token"),
		map[string]any{"jsonrpc": "2.0", "id": "invalid", "method": "resources/read", "params": map[string]any{}},
	)))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 4 {
		t.Fatalf("frame count = %d, want 4: %#v", len(frames), frames)
	}

	resources := frames[0]["result"].(map[string]any)["resources"].([]any)
	if len(resources) != 0 {
		t.Fatalf("resources/list returned static resources: %#v", resources)
	}

	templates := frames[1]["result"].(map[string]any)["resourceTemplates"].([]any)
	if len(templates) != 3 {
		t.Fatalf("resourceTemplates count = %d, want 3", len(templates))
	}
	firstTemplate := templates[0].(map[string]any)
	if firstTemplate["uriTemplate"] != "cerebro://aperio/{organizationId}/incidents/{incidentId}" ||
		firstTemplate["mimeType"] != cerebroIncidentMimeType {
		t.Fatalf("incident resource template drifted: %#v", firstTemplate)
	}

	read := frames[2]["result"].(map[string]any)
	contents := read["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("resources/read contents = %#v, want one content item", contents)
	}
	content := contents[0].(map[string]any)
	if content["uri"] != "cerebro://aperio/org_1/incidents/inc_1" || content["mimeType"] != cerebroIncidentMimeType {
		t.Fatalf("resources/read content drifted: %#v", content)
	}
	if runner.params.URI != "cerebro://aperio/org_1/incidents/inc_1" || runner.params.AuthToken != "secret-token" {
		t.Fatalf("resource read params drifted: %#v", runner.params)
	}

	invalidErr := frames[3]["error"].(map[string]any)
	if invalidErr["code"].(float64) != -32602 {
		t.Fatalf("invalid resources/read error = %#v", invalidErr)
	}
}

func TestServerRecoversFromSplitMissingAndTruncatedFrames(t *testing.T) {
	validPing := frameString(t, map[string]any{"jsonrpc": "2.0", "id": "after-missing", "method": "ping"})
	truncated := "Content-Length: 20\r\n\r\n{\"jsonrpc\":\"2.0\""
	reader := chunkedReader{
		chunks: [][]byte{
			[]byte("Content-Type: application/json\r\n\r\n"),
			[]byte(validPing[:10]),
			[]byte(validPing[10:]),
			[]byte(truncated),
		},
	}
	stdout := runServer(t, NewServer(fakeRunner{}), &reader)
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3: %#v", len(frames), frames)
	}
	if code := frames[0]["error"].(map[string]any)["code"].(float64); code != -32700 {
		t.Fatalf("missing Content-Length code = %v", code)
	}
	if frames[1]["id"] != "after-missing" {
		t.Fatalf("did not recover valid ping after missing header: %#v", frames[1])
	}
	if code := frames[2]["error"].(map[string]any)["code"].(float64); code != -32700 {
		t.Fatalf("truncated frame code = %v", code)
	}
}

func TestToolsCallSuccessErrorsAndNotifications(t *testing.T) {
	runner := &validatingFakeRunner{}
	server := NewServer(runner)
	input := joinFrames(t,
		toolCall("register", "aperio.register_agent", map[string]any{
			"organizationId": "org_1",
			"key":            "agent",
			"name":           "Agent",
		}),
		toolCall("invalid", "aperio.register_agent", map[string]any{
			"organizationId": "org_1",
			"key":            "agent",
			"name":           "Agent",
			"extra":          true,
		}),
		toolCall("unknown", "aperio.unknown", map[string]any{"organizationId": "org_1"}),
		map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]any{
				"name": "aperio.register_agent",
				"arguments": map[string]any{
					"organizationId": "org_1",
					"key":            "notify",
					"name":           "Notify",
				},
			},
		},
	)
	stdout := runServer(t, server, strings.NewReader(input))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3: %#v", len(frames), frames)
	}
	success := frames[0]["result"].(map[string]any)
	content := success["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("success content text is not JSON: %v", err)
	}
	if parsed["tool"] != "aperio.register_agent" {
		t.Fatalf("success payload drifted: %#v", parsed)
	}
	for _, frame := range frames[1:] {
		result := frame["result"].(map[string]any)
		if result["isError"] != true {
			t.Fatalf("invalid tool call did not return isError result: %#v", frame)
		}
		errorContent := result["content"].([]any)
		if errorContent[0].(map[string]any)["text"] == "" {
			t.Fatalf("tool error text is empty: %#v", frame)
		}
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want only the valid request; notification must not execute", runner.calls)
	}
}

func TestEveryApprovedToolHasAClientSafeSuccessEnvelope(t *testing.T) {
	runner := &validatingFakeRunner{}
	requests := []map[string]any{
		toolCall("register", "aperio.register_agent", map[string]any{"organizationId": "org", "key": "agent", "name": "Agent"}),
		toolCall("create", "aperio.create_task", map[string]any{"organizationId": "org", "taskType": "scan", "title": "Scan"}),
		toolCall("message", "aperio.send_message", map[string]any{"organizationId": "org", "content": map[string]any{"body": "ok"}}),
		toolCall("list", "aperio.list_tasks", map[string]any{"organizationId": "org"}),
		toolCall("proposal", "aperio.propose_remediation", map[string]any{"organizationId": "org", "action": "disable", "rationale": "Required by policy", "payload": map[string]any{"target": "user"}}),
		toolCall("siem", "aperio.enqueue_siem_payload", map[string]any{"organizationId": "org", "record": map[string]any{"id": "finding"}}),
		toolCall("cerebro-list", "aperio.list_cerebro_incidents", map[string]any{"organizationId": "org"}),
		toolCall("cerebro-get", "aperio.get_cerebro_incident_context", map[string]any{"organizationId": "org", "incidentId": "inc"}),
		toolCall("cerebro-findings", "aperio.list_cerebro_findings", map[string]any{"organizationId": "org"}),
		toolCall("cerebro-finding-get", "aperio.get_cerebro_finding_context", map[string]any{"organizationId": "org", "findingId": "fnd"}),
		toolCall("cerebro-response", "aperio.propose_cerebro_response", map[string]any{"organizationId": "org", "incidentId": "inc", "action": "REVOKE_OAUTH_GRANT", "targetType": "oauth_app", "targetIdentifier": "Vendor App", "rationale": "Required by Cerebro graph context"}),
	}
	stdout := runServer(t, NewServer(runner), strings.NewReader(joinFrames(t, requests...)))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != len(requests) {
		t.Fatalf("frame count = %d, want %d", len(frames), len(requests))
	}
	for _, frame := range frames {
		result := frame["result"].(map[string]any)
		content := result["content"].([]any)
		text := content[0].(map[string]any)["text"].(string)
		var parsed map[string]any
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("tool %v returned non-JSON text %q: %v", frame["id"], text, err)
		}
		if result["isError"] == true {
			t.Fatalf("tool %v unexpectedly returned isError: %#v", frame["id"], result)
		}
	}
}

func runServer(t *testing.T, server *Server, input io.Reader) []byte {
	t.Helper()
	var stdout bytes.Buffer
	if err := server.Run(context.Background(), input, &stdout); err != nil {
		t.Fatalf("server run failed: %v", err)
	}
	return stdout.Bytes()
}

func joinFrames(t *testing.T, messages ...map[string]any) string {
	t.Helper()
	var builder strings.Builder
	for _, message := range messages {
		builder.WriteString(frameString(t, message))
	}
	return builder.String()
}

func frameString(t *testing.T, message map[string]any) string {
	t.Helper()
	frame, err := EncodeFrame(message)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return string(frame)
}

func toolCall(id string, name string, args map[string]any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
}

func resourceRead(id string, uri string, authToken ...string) map[string]any {
	params := map[string]any{"uri": uri}
	if len(authToken) > 0 {
		params["authToken"] = authToken[0]
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "resources/read",
		"params":  params,
	}
}

func decodeOutputFrames(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	remaining := raw
	frames := []map[string]any{}
	for len(remaining) > 0 {
		separator := bytes.Index(remaining, []byte("\r\n\r\n"))
		if separator == -1 {
			t.Fatalf("stdout contains non-frame bytes: %q", string(remaining))
		}
		header := string(remaining[:separator])
		var length int
		if _, err := fmt.Sscanf(header, "Content-Length: %d", &length); err != nil {
			t.Fatalf("invalid frame header %q in stdout %q", header, string(raw))
		}
		bodyStart := separator + 4
		bodyEnd := bodyStart + length
		if len(remaining) < bodyEnd {
			t.Fatalf("truncated stdout frame: header %q total %d", header, len(remaining))
		}
		body := remaining[bodyStart:bodyEnd]
		if len(body) != length {
			t.Fatalf("byte length mismatch got %d want %d", len(body), length)
		}
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("invalid JSON frame body %q: %v", string(body), err)
		}
		frames = append(frames, decoded)
		remaining = remaining[bodyEnd:]
	}
	return frames
}

type fakeRunner struct{}

func (fakeRunner) CallTool(context.Context, string, any) (any, error) {
	return map[string]any{"ok": true}, nil
}

type resourceFakeRunner struct {
	fakeRunner
	params ResourceReadParams
}

func (r *resourceFakeRunner) ReadResource(_ context.Context, params ResourceReadParams) (ResourceContent, error) {
	r.params = params
	return ResourceContent{
		URI:      params.URI,
		MimeType: cerebroIncidentMimeType,
		Text:     `{"ok":true}`,
	}, nil
}

type validatingFakeRunner struct {
	calls int
}

func (r *validatingFakeRunner) CallTool(_ context.Context, name string, args any) (any, error) {
	normalized, err := ValidateToolArguments(name, args, timeForTests())
	if err != nil {
		return nil, err
	}
	r.calls++
	return map[string]any{"tool": name, "arguments": normalized}, nil
}

func timeForTests() time.Time {
	return time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
}

type chunkedReader struct {
	chunks [][]byte
	index  int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	r.index++
	copy(p, chunk)
	return len(chunk), nil
}
