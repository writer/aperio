package mcpbroker

const (
	ProtocolVersion = "2024-11-05"
	ServerName      = "aperio-a2a-broker"
	ServerVersion   = "0.1.0"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

func ApprovedTools() []Tool {
	tools := make([]Tool, len(approvedTools))
	copy(tools, approvedTools)
	return tools
}

func ApprovedResources() []Resource {
	return []Resource{}
}

func ApprovedResourceTemplates() []ResourceTemplate {
	templates := make([]ResourceTemplate, len(approvedResourceTemplates))
	copy(templates, approvedResourceTemplates)
	return templates
}

var approvedResourceTemplates = []ResourceTemplate{
	{
		URITemplate: "cerebro://aperio/{organizationId}/incidents/{incidentId}",
		Name:        "Aperio Cerebro incident",
		Description: "Tenant-scoped Cerebro graph context for a SaaS incident in Aperio.",
		MimeType:    cerebroIncidentMimeType,
	},
	{
		URITemplate: "cerebro://aperio/{organizationId}/findings/{findingId}",
		Name:        "Aperio Cerebro finding",
		Description: "Tenant-scoped Cerebro finding context with evidence, incident links, and response actions.",
		MimeType:    cerebroFindingMimeType,
	},
	{
		URITemplate: "cerebro://aperio/{organizationId}/security/overview",
		Name:        "Aperio Cerebro security overview",
		Description: "Tenant-scoped Cerebro security posture overview with linked incident and finding resources.",
		MimeType:    cerebroSecurityOverviewMimeType,
	},
}

var approvedTools = []Tool{
	{
		Name:        "aperio.register_agent",
		Description: "Register or heartbeat an A2A-capable agent in Aperio.",
		InputSchema: objectSchema(
			[]string{"organizationId", "key", "name"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"key":            stringSchema(2, 120),
				"name":           stringSchema(2, 160),
				"kind": map[string]any{
					"type":    "string",
					"enum":    []any{"MCP_BROKER", "SSPM_SCANNER", "SIEM_DISPATCHER", "REMEDIATION_PLANNER", "HUMAN_REVIEW", "CUSTOM"},
					"default": "CUSTOM",
				},
				"capabilities": map[string]any{
					"type":    "array",
					"items":   stringSchema(1, 120),
					"default": []any{},
				},
				"endpointUrl":  urlSchema(500),
				"mcpServerUrl": urlSchema(500),
				"status": map[string]any{
					"type":    "string",
					"enum":    []any{"ACTIVE", "PAUSED", "ERROR"},
					"default": "ACTIVE",
				},
			},
		),
	},
	{
		Name:        "aperio.create_task",
		Description: "Create an ADLC task for an agent or sub-agent.",
		InputSchema: objectSchema(
			[]string{"organizationId", "taskType", "title"},
			map[string]any{
				"organizationId":    stringSchema(1, 0),
				"authToken":         stringSchema(1, 0),
				"taskType":          stringSchema(2, 120),
				"title":             stringSchema(2, 220),
				"input":             recordSchemaWithDefault(),
				"createdByAgentKey": stringSchema(2, 120),
				"assignedAgentKey":  stringSchema(2, 120),
				"parentTaskId":      stringSchema(1, 0),
			},
		),
	},
	{
		Name:        "aperio.send_message",
		Description: "Send a task-scoped A2A message between registered agents.",
		InputSchema: objectSchema(
			[]string{"organizationId", "content"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"taskId":         stringSchema(1, 0),
				"fromAgentKey":   stringSchema(2, 120),
				"toAgentKey":     stringSchema(2, 120),
				"role": map[string]any{
					"type":    "string",
					"enum":    []any{"SYSTEM", "AGENT", "USER", "TOOL"},
					"default": "AGENT",
				},
				"messageType":   stringSchemaWithDefault(2, 120, "a2a.message.v1"),
				"correlationId": stringSchema(1, 160),
				"content":       recordSchema(),
			},
		),
	},
	{
		Name:        "aperio.list_tasks",
		Description: "List recent ADLC tasks by status or assigned agent.",
		InputSchema: objectSchema(
			[]string{"organizationId"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"status": map[string]any{
					"type": "string",
					"enum": []any{"QUEUED", "RUNNING", "WAITING_FOR_APPROVAL", "SUCCEEDED", "FAILED", "CANCELLED"},
				},
				"assignedAgentKey": stringSchema(2, 120),
			},
		),
	},
	{
		Name:        "aperio.propose_remediation",
		Description: "Create a human-gated remediation proposal from an agent.",
		InputSchema: objectSchema(
			[]string{"organizationId", "action", "rationale", "payload"},
			map[string]any{
				"organizationId":     stringSchema(1, 0),
				"authToken":          stringSchema(1, 0),
				"taskId":             stringSchema(1, 0),
				"findingId":          stringSchema(1, 0),
				"proposedByAgentKey": stringSchema(2, 120),
				"action":             stringSchema(2, 160),
				"rationale":          stringSchema(2, 4000),
				"payload":            recordSchema(),
			},
		),
	},
	{
		Name:        "aperio.enqueue_siem_payload",
		Description: "Durably enqueue a canonical Aperio SIEM payload.",
		InputSchema: objectSchema(
			[]string{"organizationId", "record"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"kind": map[string]any{
					"type":    "string",
					"enum":    []any{"finding", "event", "audit_log"},
					"default": "finding",
				},
				"occurredAt": datetimeSchema(),
				"record":     recordSchema(),
			},
		),
	},
	{
		Name:        "aperio.list_cerebro_incidents",
		Description: "List Cerebro-backed posture incident MCP resources for a tenant.",
		InputSchema: objectSchema(
			[]string{"organizationId"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"status": map[string]any{
					"type": "string",
					"enum": []any{"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "ALL"},
				},
				"severity": map[string]any{
					"type": "string",
					"enum": []any{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
				},
				"limit": integerSchemaWithDefault(1, 100, 25),
			},
		),
	},
	{
		Name:        "aperio.get_cerebro_incident_context",
		Description: "Fetch one incident as a Cerebro MCP graph-context resource with findings, timeline, and response actions.",
		InputSchema: objectSchema(
			[]string{"organizationId", "incidentId"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"incidentId":     stringSchema(1, 0),
			},
		),
	},
	{
		Name:        "aperio.list_cerebro_findings",
		Description: "List Cerebro-backed finding MCP resources for a tenant.",
		InputSchema: objectSchema(
			[]string{"organizationId"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"status": map[string]any{
					"type": "string",
					"enum": []any{"OPEN", "RESOLVED", "MUTED", "ALL"},
				},
				"severity": map[string]any{
					"type": "string",
					"enum": []any{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
				},
				"provider": map[string]any{
					"type": "string",
					"enum": []any{"GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE"},
				},
				"limit": integerSchemaWithDefault(1, 100, 25),
			},
		),
	},
	{
		Name:        "aperio.get_cerebro_finding_context",
		Description: "Fetch one finding as a Cerebro MCP graph-context resource with evidence, incident links, and response actions.",
		InputSchema: objectSchema(
			[]string{"organizationId", "findingId"},
			map[string]any{
				"organizationId": stringSchema(1, 0),
				"authToken":      stringSchema(1, 0),
				"findingId":      stringSchema(1, 0),
			},
		),
	},
	{
		Name:        "aperio.propose_cerebro_response",
		Description: "Create a human-gated SaaS incident response action from Cerebro MCP graph context.",
		InputSchema: objectSchema(
			[]string{"organizationId", "incidentId", "action", "targetType", "targetIdentifier", "rationale"},
			map[string]any{
				"organizationId":     stringSchema(1, 0),
				"authToken":          stringSchema(1, 0),
				"incidentId":         stringSchema(1, 0),
				"findingId":          stringSchema(1, 0),
				"taskId":             stringSchema(1, 0),
				"proposedByAgentKey": stringSchema(2, 120),
				"action": map[string]any{
					"type": "string",
					"enum": []any{"REVOKE_OAUTH_GRANT", "SUSPEND_USER", "RESET_MFA", "REVOKE_SESSION", "REMOVE_EXTERNAL_SHARE", "DISABLE_FORWARDING", "REMOVE_ADMIN_ROLE", "QUARANTINE_APP", "OPEN_TICKET", "NOTIFY_SECOPS"},
				},
				"provider": map[string]any{
					"type": "string",
					"enum": []any{"GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE"},
				},
				"targetType":       stringSchema(1, 120),
				"targetIdentifier": stringSchema(1, 255),
				"rationale":        stringSchema(2, 4000),
				"approvalRequired": map[string]any{
					"type":    "boolean",
					"default": true,
				},
			},
		),
	},
}

func objectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"required":             stringSliceToAny(required),
		"additionalProperties": false,
		"properties":           properties,
	}
}

func stringSchema(minLength int, maxLength int) map[string]any {
	schema := map[string]any{"type": "string"}
	if minLength > 0 {
		schema["minLength"] = minLength
	}
	if maxLength > 0 {
		schema["maxLength"] = maxLength
	}
	return schema
}

func stringSchemaWithDefault(minLength int, maxLength int, defaultValue string) map[string]any {
	schema := stringSchema(minLength, maxLength)
	schema["default"] = defaultValue
	return schema
}

func urlSchema(maxLength int) map[string]any {
	schema := stringSchema(1, maxLength)
	schema["format"] = "uri"
	return schema
}

func datetimeSchema() map[string]any {
	return map[string]any{
		"type":   "string",
		"format": "date-time",
	}
}

func integerSchemaWithDefault(minimum int, maximum int, defaultValue int) map[string]any {
	return map[string]any{
		"type":    "integer",
		"minimum": minimum,
		"maximum": maximum,
		"default": defaultValue,
	}
}

func recordSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": true,
	}
}

func recordSchemaWithDefault() map[string]any {
	schema := recordSchema()
	schema["default"] = map[string]any{}
	return schema
}

func stringSliceToAny(values []string) []any {
	converted := make([]any, len(values))
	for index, value := range values {
		converted[index] = value
	}
	return converted
}
