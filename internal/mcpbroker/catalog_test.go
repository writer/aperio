package mcpbroker

import (
	"testing"
	"time"
)

func TestApprovedToolsCatalog(t *testing.T) {
	tools := ApprovedTools()
	wantNames := []string{
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
	}
	if len(tools) != len(wantNames) {
		t.Fatalf("tool count = %d, want %d", len(tools), len(wantNames))
	}
	for index, wantName := range wantNames {
		tool := tools[index]
		if tool.Name != wantName {
			t.Fatalf("tool[%d].Name = %q, want %q", index, tool.Name, wantName)
		}
		if tool.Description == "" {
			t.Fatalf("%s missing description", tool.Name)
		}
		if got := tool.InputSchema["additionalProperties"]; got != false {
			t.Fatalf("%s additionalProperties = %v, want false", tool.Name, got)
		}
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("%s schema type = %v, want object", tool.Name, tool.InputSchema["type"])
		}
	}

	required := map[string][]any{}
	for _, tool := range tools {
		required[tool.Name], _ = tool.InputSchema["required"].([]any)
	}
	assertRequired(t, required["aperio.register_agent"], "organizationId", "key", "name")
	assertRequired(t, required["aperio.create_task"], "organizationId", "taskType", "title")
	assertRequired(t, required["aperio.send_message"], "organizationId", "content")
	assertRequired(t, required["aperio.list_tasks"], "organizationId")
	assertRequired(t, required["aperio.propose_remediation"], "organizationId", "action", "rationale", "payload")
	assertRequired(t, required["aperio.enqueue_siem_payload"], "organizationId", "record")
	assertRequired(t, required["aperio.list_cerebro_incidents"], "organizationId")
	assertRequired(t, required["aperio.get_cerebro_incident_context"], "organizationId", "incidentId")
	assertRequired(t, required["aperio.list_cerebro_findings"], "organizationId")
	assertRequired(t, required["aperio.get_cerebro_finding_context"], "organizationId", "findingId")
	assertRequired(t, required["aperio.propose_cerebro_response"], "organizationId", "incidentId", "action", "targetType", "targetIdentifier", "rationale")

	registerProps := tools[0].InputSchema["properties"].(map[string]any)
	if registerProps["kind"].(map[string]any)["default"] != "CUSTOM" {
		t.Fatalf("register_agent kind default drifted")
	}
	if registerProps["status"].(map[string]any)["default"] != "ACTIVE" {
		t.Fatalf("register_agent status default drifted")
	}
	sendProps := tools[2].InputSchema["properties"].(map[string]any)
	if sendProps["messageType"].(map[string]any)["default"] != "a2a.message.v1" {
		t.Fatalf("send_message messageType default drifted")
	}
	enqueueProps := tools[5].InputSchema["properties"].(map[string]any)
	if enqueueProps["kind"].(map[string]any)["default"] != "finding" {
		t.Fatalf("enqueue kind default drifted")
	}
	if enqueueProps["occurredAt"].(map[string]any)["format"] != "date-time" {
		t.Fatalf("enqueue occurredAt must advertise date-time format")
	}
	cerebroListProps := tools[6].InputSchema["properties"].(map[string]any)
	if cerebroListProps["limit"].(map[string]any)["default"] != 25 {
		t.Fatalf("list_cerebro_incidents limit default drifted")
	}
	cerebroFindingListProps := tools[8].InputSchema["properties"].(map[string]any)
	if cerebroFindingListProps["limit"].(map[string]any)["default"] != 25 {
		t.Fatalf("list_cerebro_findings limit default drifted")
	}
	cerebroResponseProps := tools[10].InputSchema["properties"].(map[string]any)
	if cerebroResponseProps["approvalRequired"].(map[string]any)["default"] != true {
		t.Fatalf("propose_cerebro_response approval default drifted")
	}
}

func TestValidateToolArgumentsDefaultsAndTrimming(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 13, 14, 15, time.UTC)
	register, err := ValidateToolArguments("aperio.register_agent", map[string]any{
		"organizationId": " org_1 ",
		"key":            " worker ",
		"name":           " MCP Worker ",
		"capabilities":   []any{" scan ", "remediate"},
	}, now)
	if err != nil {
		t.Fatalf("register validation failed: %v", err)
	}
	if register["organizationId"] != "org_1" || register["key"] != "worker" || register["name"] != "MCP Worker" {
		t.Fatalf("register trimming/defaults wrong: %#v", register)
	}
	if register["kind"] != "CUSTOM" || register["status"] != "ACTIVE" {
		t.Fatalf("register enum defaults wrong: %#v", register)
	}
	if got := register["capabilities"].([]string); len(got) != 2 || got[0] != "scan" || got[1] != "remediate" {
		t.Fatalf("capabilities = %#v", got)
	}

	task, err := ValidateToolArguments("aperio.create_task", map[string]any{
		"organizationId": "org_1",
		"taskType":       "analysis",
		"title":          "Review alert",
	}, now)
	if err != nil {
		t.Fatalf("create_task validation failed: %v", err)
	}
	if input := task["input"].(map[string]any); len(input) != 0 {
		t.Fatalf("create_task input default = %#v", input)
	}

	message, err := ValidateToolArguments("aperio.send_message", map[string]any{
		"organizationId": "org_1",
		"content":        map[string]any{"text": "hello"},
	}, now)
	if err != nil {
		t.Fatalf("send_message validation failed: %v", err)
	}
	if message["role"] != "AGENT" || message["messageType"] != "a2a.message.v1" {
		t.Fatalf("send_message defaults wrong: %#v", message)
	}

	enqueue, err := ValidateToolArguments("aperio.enqueue_siem_payload", map[string]any{
		"organizationId": "org_1",
		"record":         map[string]any{"id": "finding_1"},
	}, now)
	if err != nil {
		t.Fatalf("enqueue validation failed: %v", err)
	}
	if enqueue["kind"] != "finding" || enqueue["occurredAt"] != now.Format(time.RFC3339Nano) {
		t.Fatalf("enqueue defaults wrong: %#v", enqueue)
	}

	cerebroList, err := ValidateToolArguments("aperio.list_cerebro_incidents", map[string]any{
		"organizationId": " org_1 ",
	}, now)
	if err != nil {
		t.Fatalf("list_cerebro_incidents validation failed: %v", err)
	}
	if cerebroList["organizationId"] != "org_1" || cerebroList["limit"] != 25 {
		t.Fatalf("list_cerebro_incidents defaults wrong: %#v", cerebroList)
	}

	cerebroFindings, err := ValidateToolArguments("aperio.list_cerebro_findings", map[string]any{
		"organizationId": " org_1 ",
		"provider":       "SLACK",
	}, now)
	if err != nil {
		t.Fatalf("list_cerebro_findings validation failed: %v", err)
	}
	if cerebroFindings["organizationId"] != "org_1" || cerebroFindings["provider"] != "SLACK" || cerebroFindings["limit"] != 25 {
		t.Fatalf("list_cerebro_findings defaults wrong: %#v", cerebroFindings)
	}

	cerebroFinding, err := ValidateToolArguments("aperio.get_cerebro_finding_context", map[string]any{
		"organizationId": "org_1",
		"findingId":      " fnd_1 ",
	}, now)
	if err != nil {
		t.Fatalf("get_cerebro_finding_context validation failed: %v", err)
	}
	if cerebroFinding["findingId"] != "fnd_1" {
		t.Fatalf("get_cerebro_finding_context trimming wrong: %#v", cerebroFinding)
	}

	cerebroResponse, err := ValidateToolArguments("aperio.propose_cerebro_response", map[string]any{
		"organizationId":     "org_1",
		"incidentId":         " inc_1 ",
		"action":             "REVOKE_OAUTH_GRANT",
		"targetType":         " oauth_app ",
		"targetIdentifier":   " Vendor App ",
		"rationale":          " Required by Cerebro graph context. ",
		"proposedByAgentKey": " planner ",
	}, now)
	if err != nil {
		t.Fatalf("propose_cerebro_response validation failed: %v", err)
	}
	if cerebroResponse["approvalRequired"] != true ||
		cerebroResponse["incidentId"] != "inc_1" ||
		cerebroResponse["targetIdentifier"] != "Vendor App" ||
		cerebroResponse["proposedByAgentKey"] != "planner" {
		t.Fatalf("propose_cerebro_response defaults/trimming wrong: %#v", cerebroResponse)
	}
}

func TestValidateToolArgumentsRejectsInvalidInputs(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 13, 14, 0, time.UTC)
	cases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{
			name: "unknown property",
			tool: "aperio.register_agent",
			args: map[string]any{"organizationId": "org", "key": "agent", "name": "Agent", "extra": true},
		},
		{
			name: "invalid enum",
			tool: "aperio.register_agent",
			args: map[string]any{"organizationId": "org", "key": "agent", "name": "Agent", "kind": "BOT"},
		},
		{
			name: "invalid url",
			tool: "aperio.register_agent",
			args: map[string]any{"organizationId": "org", "key": "agent", "name": "Agent", "endpointUrl": "not a url"},
		},
		{
			name: "invalid datetime",
			tool: "aperio.enqueue_siem_payload",
			args: map[string]any{"organizationId": "org", "record": map[string]any{"id": "1"}, "occurredAt": "yesterday"},
		},
		{
			name: "record must be object",
			tool: "aperio.enqueue_siem_payload",
			args: map[string]any{"organizationId": "org", "record": []any{"bad"}},
		},
		{
			name: "invalid cerebro limit",
			tool: "aperio.list_cerebro_incidents",
			args: map[string]any{"organizationId": "org", "limit": 101},
		},
		{
			name: "invalid cerebro finding status",
			tool: "aperio.list_cerebro_findings",
			args: map[string]any{"organizationId": "org", "status": "INVESTIGATING"},
		},
		{
			name: "invalid cerebro action",
			tool: "aperio.propose_cerebro_response",
			args: map[string]any{"organizationId": "org", "incidentId": "inc", "action": "DELETE_TENANT", "targetType": "app", "targetIdentifier": "app", "rationale": "bad"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateToolArguments(tc.tool, tc.args, now); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func assertRequired(t *testing.T, got []any, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("required = %#v, want %#v", got, want)
	}
	for index, value := range want {
		if got[index] != value {
			t.Fatalf("required[%d] = %v, want %s (all %#v)", index, got[index], value, got)
		}
	}
}
