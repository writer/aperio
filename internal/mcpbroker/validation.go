package mcpbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	agentKinds       = stringSet("MCP_BROKER", "SSPM_SCANNER", "SIEM_DISPATCHER", "REMEDIATION_PLANNER", "HUMAN_REVIEW", "CUSTOM")
	agentStatuses    = stringSet("ACTIVE", "PAUSED", "ERROR")
	taskStatuses     = stringSet("QUEUED", "RUNNING", "WAITING_FOR_APPROVAL", "SUCCEEDED", "FAILED", "CANCELLED")
	messageRoles     = stringSet("SYSTEM", "AGENT", "USER", "TOOL")
	siemKinds        = stringSet("finding", "event", "audit_log")
	incidentStatuses = stringSet("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "ALL")
	findingStatuses  = stringSet("OPEN", "RESOLVED", "MUTED", "ALL")
	severities       = stringSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
	saasProviders    = stringSet("GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE")
	saasActions      = stringSet("REVOKE_OAUTH_GRANT", "SUSPEND_USER", "RESET_MFA", "REVOKE_SESSION", "REMOVE_EXTERNAL_SHARE", "DISABLE_FORWARDING", "REMOVE_ADMIN_ROLE", "QUARANTINE_APP", "OPEN_TICKET", "NOTIFY_SECOPS")
)

func ValidateToolArguments(name string, args any, now time.Time) (map[string]any, error) {
	if now.IsZero() {
		now = time.Now()
	}
	input, err := objectArgument(args)
	if err != nil {
		return nil, err
	}
	switch name {
	case "aperio.register_agent":
		return validateRegisterAgent(input)
	case "aperio.create_task":
		return validateCreateTask(input)
	case "aperio.send_message":
		return validateSendMessage(input)
	case "aperio.list_tasks":
		return validateListTasks(input)
	case "aperio.propose_remediation":
		return validateProposal(input)
	case "aperio.enqueue_siem_payload":
		return validateEnqueueSIEMPayload(input, now)
	case "aperio.list_cerebro_incidents":
		return validateListCerebroIncidents(input)
	case "aperio.get_cerebro_incident_context":
		return validateGetCerebroIncidentContext(input)
	case "aperio.list_cerebro_findings":
		return validateListCerebroFindings(input)
	case "aperio.get_cerebro_finding_context":
		return validateGetCerebroFindingContext(input)
	case "aperio.propose_cerebro_response":
		return validateProposeCerebroResponse(input)
	default:
		return nil, fmt.Errorf("Unknown tool: %s", name)
	}
}

func validateRegisterAgent(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "key", "name", "kind", "capabilities", "endpointUrl", "mcpServerUrl", "status")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["key"], err = requiredString(input, "key", 2, 120); err != nil {
		return nil, err
	}
	if out["name"], err = requiredString(input, "name", 2, 160); err != nil {
		return nil, err
	}
	if out["kind"], err = optionalEnum(input, "kind", agentKinds, "CUSTOM"); err != nil {
		return nil, err
	}
	if out["capabilities"], err = optionalStringArray(input, "capabilities"); err != nil {
		return nil, err
	}
	if value, ok, err := optionalURL(input, "endpointUrl", 500); err != nil {
		return nil, err
	} else if ok {
		out["endpointUrl"] = value
	}
	if value, ok, err := optionalURL(input, "mcpServerUrl", 500); err != nil {
		return nil, err
	} else if ok {
		out["mcpServerUrl"] = value
	}
	if out["status"], err = optionalEnum(input, "status", agentStatuses, "ACTIVE"); err != nil {
		return nil, err
	}
	return out, nil
}

func validateCreateTask(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "taskType", "title", "input", "createdByAgentKey", "assignedAgentKey", "parentTaskId")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["taskType"], err = requiredString(input, "taskType", 2, 120); err != nil {
		return nil, err
	}
	if out["title"], err = requiredString(input, "title", 2, 220); err != nil {
		return nil, err
	}
	if out["input"], err = optionalRecord(input, "input", true); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name string
		min  int
		max  int
	}{
		{"createdByAgentKey", 2, 120},
		{"assignedAgentKey", 2, 120},
		{"parentTaskId", 1, 0},
	} {
		if value, ok, err := optionalString(input, field.name, field.min, field.max); err != nil {
			return nil, err
		} else if ok {
			out[field.name] = value
		}
	}
	return out, nil
}

func validateSendMessage(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "taskId", "fromAgentKey", "toAgentKey", "role", "messageType", "correlationId", "content")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name string
		min  int
		max  int
	}{
		{"taskId", 1, 0},
		{"fromAgentKey", 2, 120},
		{"toAgentKey", 2, 120},
		{"correlationId", 1, 160},
	} {
		if value, ok, err := optionalString(input, field.name, field.min, field.max); err != nil {
			return nil, err
		} else if ok {
			out[field.name] = value
		}
	}
	if out["role"], err = optionalEnum(input, "role", messageRoles, "AGENT"); err != nil {
		return nil, err
	}
	if out["messageType"], err = optionalStringDefault(input, "messageType", 2, 120, "a2a.message.v1"); err != nil {
		return nil, err
	}
	if out["content"], err = requiredRecord(input, "content"); err != nil {
		return nil, err
	}
	return out, nil
}

func validateListTasks(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "status", "assignedAgentKey")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if value, ok, err := optionalEnumNoDefault(input, "status", taskStatuses); err != nil {
		return nil, err
	} else if ok {
		out["status"] = value
	}
	if value, ok, err := optionalString(input, "assignedAgentKey", 2, 120); err != nil {
		return nil, err
	} else if ok {
		out["assignedAgentKey"] = value
	}
	return out, nil
}

func validateProposal(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "taskId", "findingId", "proposedByAgentKey", "action", "rationale", "payload")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name string
		min  int
		max  int
	}{
		{"taskId", 1, 0},
		{"findingId", 1, 0},
		{"proposedByAgentKey", 2, 120},
	} {
		if value, ok, err := optionalString(input, field.name, field.min, field.max); err != nil {
			return nil, err
		} else if ok {
			out[field.name] = value
		}
	}
	if out["action"], err = requiredString(input, "action", 2, 160); err != nil {
		return nil, err
	}
	if out["rationale"], err = requiredString(input, "rationale", 2, 4000); err != nil {
		return nil, err
	}
	if out["payload"], err = requiredRecord(input, "payload"); err != nil {
		return nil, err
	}
	return out, nil
}

func validateEnqueueSIEMPayload(input map[string]any, now time.Time) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "kind", "occurredAt", "record")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["kind"], err = optionalEnum(input, "kind", siemKinds, "finding"); err != nil {
		return nil, err
	}
	if value, ok, err := optionalDateTime(input, "occurredAt"); err != nil {
		return nil, err
	} else if ok {
		out["occurredAt"] = value
	} else {
		out["occurredAt"] = now.UTC().Format(time.RFC3339Nano)
	}
	if out["record"], err = requiredRecord(input, "record"); err != nil {
		return nil, err
	}
	return out, nil
}

func validateListCerebroIncidents(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "status", "severity", "limit")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if value, ok, err := optionalEnumNoDefault(input, "status", incidentStatuses); err != nil {
		return nil, err
	} else if ok {
		out["status"] = value
	}
	if value, ok, err := optionalEnumNoDefault(input, "severity", severities); err != nil {
		return nil, err
	} else if ok {
		out["severity"] = value
	}
	limit, err := optionalIntDefault(input, "limit", 1, 100, 25)
	if err != nil {
		return nil, err
	}
	out["limit"] = limit
	return out, nil
}

func validateGetCerebroIncidentContext(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "incidentId")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["incidentId"], err = requiredString(input, "incidentId", 1, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func validateListCerebroFindings(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "status", "severity", "provider", "limit")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if value, ok, err := optionalEnumNoDefault(input, "status", findingStatuses); err != nil {
		return nil, err
	} else if ok {
		out["status"] = value
	}
	if value, ok, err := optionalEnumNoDefault(input, "severity", severities); err != nil {
		return nil, err
	} else if ok {
		out["severity"] = value
	}
	if value, ok, err := optionalEnumNoDefault(input, "provider", saasProviders); err != nil {
		return nil, err
	} else if ok {
		out["provider"] = value
	}
	limit, err := optionalIntDefault(input, "limit", 1, 100, 25)
	if err != nil {
		return nil, err
	}
	out["limit"] = limit
	return out, nil
}

func validateGetCerebroFindingContext(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "findingId")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["findingId"], err = requiredString(input, "findingId", 1, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func validateProposeCerebroResponse(input map[string]any) (map[string]any, error) {
	allowed := stringSet("organizationId", "authToken", "incidentId", "findingId", "taskId", "proposedByAgentKey", "action", "provider", "targetType", "targetIdentifier", "rationale", "approvalRequired", "dryRun")
	if err := rejectUnknown(input, allowed); err != nil {
		return nil, err
	}
	out, err := scopedFields(input)
	if err != nil {
		return nil, err
	}
	if out["incidentId"], err = requiredString(input, "incidentId", 1, 0); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		name string
		min  int
		max  int
	}{
		{"findingId", 1, 0},
		{"taskId", 1, 0},
		{"proposedByAgentKey", 2, 120},
	} {
		if value, ok, err := optionalString(input, field.name, field.min, field.max); err != nil {
			return nil, err
		} else if ok {
			out[field.name] = value
		}
	}
	if out["action"], err = requiredEnum(input, "action", saasActions); err != nil {
		return nil, err
	}
	if value, ok, err := optionalEnumNoDefault(input, "provider", saasProviders); err != nil {
		return nil, err
	} else if ok {
		out["provider"] = value
	}
	if out["targetType"], err = requiredString(input, "targetType", 1, 120); err != nil {
		return nil, err
	}
	if out["targetIdentifier"], err = requiredString(input, "targetIdentifier", 1, 255); err != nil {
		return nil, err
	}
	if out["rationale"], err = requiredString(input, "rationale", 2, 4000); err != nil {
		return nil, err
	}
	if out["approvalRequired"], err = optionalBoolDefault(input, "approvalRequired", true); err != nil {
		return nil, err
	}
	if out["dryRun"], err = optionalBoolDefault(input, "dryRun", true); err != nil {
		return nil, err
	}
	return out, nil
}

func objectArgument(args any) (map[string]any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	object, ok := args.(map[string]any)
	if !ok {
		return nil, errors.New("arguments must be an object")
	}
	copy := make(map[string]any, len(object))
	for key, value := range object {
		copy[key] = value
	}
	return copy, nil
}

func scopedFields(input map[string]any) (map[string]any, error) {
	out := map[string]any{}
	org, err := requiredString(input, "organizationId", 1, 0)
	if err != nil {
		return nil, err
	}
	out["organizationId"] = org
	if token, ok, err := optionalString(input, "authToken", 1, 0); err != nil {
		return nil, err
	} else if ok {
		out["authToken"] = token
	}
	return out, nil
}

func rejectUnknown(input map[string]any, allowed map[string]struct{}) error {
	for field := range input {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("unknown property: %s", field)
		}
	}
	return nil
}

func requiredString(input map[string]any, field string, minLength int, maxLength int) (string, error) {
	value, ok := input[field]
	if !ok {
		return "", fmt.Errorf("%s is required", field)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", field)
	}
	return validateString(field, text, minLength, maxLength)
}

func optionalString(input map[string]any, field string, minLength int, maxLength int) (string, bool, error) {
	value, ok := input[field]
	if !ok {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("%s must be a string", field)
	}
	trimmed, err := validateString(field, text, minLength, maxLength)
	return trimmed, true, err
}

func optionalStringDefault(input map[string]any, field string, minLength int, maxLength int, fallback string) (string, error) {
	value, ok, err := optionalString(input, field, minLength, maxLength)
	if err != nil {
		return "", err
	}
	if !ok {
		return fallback, nil
	}
	return value, nil
}

func validateString(field string, value string, minLength int, maxLength int) (string, error) {
	trimmed := strings.TrimSpace(value)
	length := utf8.RuneCountInString(trimmed)
	if minLength > 0 && length < minLength {
		return "", fmt.Errorf("%s must be at least %d characters", field, minLength)
	}
	if maxLength > 0 && length > maxLength {
		return "", fmt.Errorf("%s must be at most %d characters", field, maxLength)
	}
	return trimmed, nil
}

func optionalURL(input map[string]any, field string, maxLength int) (string, bool, error) {
	value, ok, err := optionalString(input, field, 1, maxLength)
	if err != nil || !ok {
		return "", ok, err
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false, fmt.Errorf("%s must be a valid URL", field)
	}
	return value, true, nil
}

func optionalDateTime(input map[string]any, field string) (string, bool, error) {
	value, ok, err := optionalString(input, field, 1, 0)
	if err != nil || !ok {
		return "", ok, err
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return "", false, fmt.Errorf("%s must be an RFC3339 datetime", field)
	}
	return value, true, nil
}

func optionalEnum(input map[string]any, field string, allowed map[string]struct{}, fallback string) (string, error) {
	value, ok, err := optionalEnumNoDefault(input, field, allowed)
	if err != nil {
		return "", err
	}
	if !ok {
		return fallback, nil
	}
	return value, nil
}

func requiredEnum(input map[string]any, field string, allowed map[string]struct{}) (string, error) {
	value, err := requiredString(input, field, 1, 0)
	if err != nil {
		return "", err
	}
	if _, valid := allowed[value]; !valid {
		return "", fmt.Errorf("%s must be one of the approved values", field)
	}
	return value, nil
}

func optionalEnumNoDefault(input map[string]any, field string, allowed map[string]struct{}) (string, bool, error) {
	value, ok, err := optionalString(input, field, 1, 0)
	if err != nil || !ok {
		return "", ok, err
	}
	if _, valid := allowed[value]; !valid {
		return "", false, fmt.Errorf("%s must be one of the approved values", field)
	}
	return value, true, nil
}

func optionalBoolDefault(input map[string]any, field string, fallback bool) (bool, error) {
	value, ok := input[field]
	if !ok {
		return fallback, nil
	}
	typed, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", field)
	}
	return typed, nil
}

func optionalIntDefault(input map[string]any, field string, minimum int, maximum int, fallback int) (int, error) {
	value, ok := input[field]
	if !ok {
		return fallback, nil
	}
	var parsed int
	switch typed := value.(type) {
	case int:
		parsed = typed
	case int64:
		parsed = int(typed)
	case float64:
		if typed != float64(int(typed)) {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		parsed = int(typed)
	case json.Number:
		intValue, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", field)
		}
		parsed = int(intValue)
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
	if parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", field, minimum, maximum)
	}
	return parsed, nil
}

func optionalStringArray(input map[string]any, field string) ([]string, error) {
	value, ok := input[field]
	if !ok {
		return []string{}, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	out := make([]string, len(values))
	for index, item := range values {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", field, index)
		}
		trimmed, err := validateString(fmt.Sprintf("%s[%d]", field, index), text, 1, 120)
		if err != nil {
			return nil, err
		}
		out[index] = trimmed
	}
	return out, nil
}

func optionalRecord(input map[string]any, field string, defaultEmpty bool) (map[string]any, error) {
	value, ok := input[field]
	if !ok {
		if defaultEmpty {
			return map[string]any{}, nil
		}
		return nil, nil
	}
	return recordValue(field, value)
}

func requiredRecord(input map[string]any, field string) (map[string]any, error) {
	value, ok := input[field]
	if !ok {
		return nil, fmt.Errorf("%s is required", field)
	}
	return recordValue(field, value)
}

func recordValue(field string, value any) (map[string]any, error) {
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	copy := make(map[string]any, len(record))
	for key, entry := range record {
		copy[key] = normalizeJSONValue(entry)
	}
	return copy, nil
}

func normalizeJSONValue(value any) any {
	switch typed := value.(type) {
	case json.Number:
		if intValue, err := typed.Int64(); err == nil {
			return intValue
		}
		if floatValue, err := typed.Float64(); err == nil {
			return floatValue
		}
	case map[string]any:
		copy := make(map[string]any, len(typed))
		for key, entry := range typed {
			copy[key] = normalizeJSONValue(entry)
		}
		return copy
	case []any:
		copy := make([]any, len(typed))
		for index, entry := range typed {
			copy[index] = normalizeJSONValue(entry)
		}
		return copy
	}
	return value
}

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
