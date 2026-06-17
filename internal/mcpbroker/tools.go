package mcpbroker

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/writer/aperio/internal/siemdispatcher"
)

type ToolService struct {
	db                    *sql.DB
	now                   func() time.Time
	allowedOrganizationID string
	sharedSecret          string
}

func NewToolService(db *sql.DB) *ToolService {
	return &ToolService{
		db:                    db,
		now:                   time.Now,
		allowedOrganizationID: strings.TrimSpace(getenv("APERIO_MCP_ORGANIZATION_ID")),
		sharedSecret:          strings.TrimSpace(getenv("APERIO_MCP_SHARED_SECRET")),
	}
}

func (s *ToolService) SetNowForTesting(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *ToolService) CallTool(ctx context.Context, name string, args any) (any, error) {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	scoped, err := ValidateToolArguments(name, args, now)
	if err != nil {
		return nil, err
	}
	if err := s.assertScope(scoped); err != nil {
		return nil, err
	}
	delete(scoped, "authToken")
	if s.db == nil {
		return nil, fmt.Errorf("database is not configured for MCP tool calls")
	}
	switch name {
	case "aperio.register_agent":
		return s.registerAgent(ctx, scoped)
	case "aperio.create_task":
		return s.createTask(ctx, scoped)
	case "aperio.send_message":
		return s.sendMessage(ctx, scoped)
	case "aperio.list_tasks":
		return s.listTasks(ctx, scoped)
	case "aperio.propose_remediation":
		return s.proposeRemediation(ctx, scoped)
	case "aperio.enqueue_siem_payload":
		return s.enqueueSIEMPayload(ctx, scoped)
	case "aperio.list_cerebro_incidents":
		return s.listCerebroIncidents(ctx, scoped)
	case "aperio.get_cerebro_incident_context":
		return s.getCerebroIncidentContext(ctx, scoped)
	case "aperio.propose_cerebro_response":
		return s.proposeCerebroResponse(ctx, scoped)
	default:
		return nil, fmt.Errorf("Unknown tool: %s", name)
	}
}

func (s *ToolService) assertScope(input map[string]any) error {
	organizationID, _ := input["organizationId"].(string)
	if s.allowedOrganizationID == "" && s.sharedSecret == "" {
		return fmt.Errorf("MCP broker requires APERIO_MCP_SHARED_SECRET or APERIO_MCP_ORGANIZATION_ID")
	}
	if s.allowedOrganizationID != "" && organizationID != s.allowedOrganizationID {
		return fmt.Errorf("Organization is not allowed for this MCP broker")
	}
	if s.sharedSecret != "" && !safeEqual(stringValue(input["authToken"]), s.sharedSecret) {
		return fmt.Errorf("Invalid MCP broker token")
	}
	return nil
}

func (s *ToolService) registerAgent(ctx context.Context, input map[string]any) (any, error) {
	capabilities := input["capabilities"].([]string)
	var endpointURL any
	if value, ok := input["endpointUrl"].(string); ok {
		endpointURL = value
	}
	var mcpServerURL any
	if value, ok := input["mcpServerUrl"].(string); ok {
		mcpServerURL = value
	}
	var agentID, key, status string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO agents (
			id, organization_id, key, name, kind, capabilities, endpoint_url, mcp_server_url,
			status, last_seen_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5::"AgentKind", $6::text[], $7, $8, $9::"AgentStatus", NOW(), NOW(), NOW())
		ON CONFLICT (organization_id, key) DO UPDATE SET
			name = EXCLUDED.name,
			kind = EXCLUDED.kind,
			capabilities = EXCLUDED.capabilities,
			endpoint_url = EXCLUDED.endpoint_url,
			mcp_server_url = EXCLUDED.mcp_server_url,
			status = EXCLUDED.status,
			last_seen_at = NOW(),
			updated_at = NOW()
		RETURNING id, key, status::text
	`, prefixedID("agt"), input["organizationId"], input["key"], input["name"], input["kind"], postgresTextArray(capabilities), endpointURL, mcpServerURL, input["status"]).Scan(&agentID, &key, &status)
	if err != nil {
		return nil, err
	}
	return map[string]any{"agentId": agentID, "key": key, "status": status}, nil
}

func (s *ToolService) createTask(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	createdByAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["createdByAgentKey"]))
	if err != nil {
		return nil, err
	}
	assignedAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["assignedAgentKey"]))
	if err != nil {
		return nil, err
	}
	parentTaskID, err := s.ensureTaskID(ctx, organizationID, stringValue(input["parentTaskId"]))
	if err != nil {
		return nil, err
	}
	inputJSON, err := json.Marshal(input["input"])
	if err != nil {
		return nil, err
	}
	taskID := prefixedID("task")
	var status string
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO agent_tasks (
			id, organization_id, task_type, title, input, created_by_agent_id, assigned_agent_id,
			parent_task_id, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, NOW(), NOW())
		RETURNING status::text
	`, taskID, organizationID, input["taskType"], input["title"], string(inputJSON), nullableString(createdByAgentID), nullableString(assignedAgentID), nullableString(parentTaskID)).Scan(&status)
	if err != nil {
		return nil, err
	}
	return map[string]any{"taskId": taskID, "status": status}, nil
}

func (s *ToolService) sendMessage(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	fromAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["fromAgentKey"]))
	if err != nil {
		return nil, err
	}
	toAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["toAgentKey"]))
	if err != nil {
		return nil, err
	}
	taskID, err := s.ensureTaskID(ctx, organizationID, stringValue(input["taskId"]))
	if err != nil {
		return nil, err
	}
	contentJSON, err := json.Marshal(input["content"])
	if err != nil {
		return nil, err
	}
	messageID := prefixedID("msg")
	var createdAt time.Time
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO agent_messages (
			id, organization_id, task_id, from_agent_id, to_agent_id, role, message_type,
			correlation_id, content, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6::"AgentMessageRole", $7, $8, $9::jsonb, NOW())
		RETURNING created_at
	`, messageID, organizationID, nullableString(taskID), nullableString(fromAgentID), nullableString(toAgentID), input["role"], input["messageType"], nullableString(stringValue(input["correlationId"])), string(contentJSON)).Scan(&createdAt)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messageId": messageID, "createdAt": formatMCPTime(createdAt)}, nil
}

func (s *ToolService) listTasks(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	assignedAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["assignedAgentKey"]))
	if err != nil {
		return nil, err
	}
	statusFilter := stringValue(input["status"])
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.organization_id, t.task_type, t.title, t.status::text, t.input, t.output,
		       t.error, t.created_by_agent_id, t.assigned_agent_id, t.parent_task_id,
		       t.lease_expires_at, t.started_at, t.completed_at, t.created_at, t.updated_at,
		       created.key, created.name, created.kind::text,
		       assigned.key, assigned.name, assigned.kind::text
		FROM agent_tasks t
		LEFT JOIN agents created ON created.id = t.created_by_agent_id AND created.organization_id = t.organization_id
		LEFT JOIN agents assigned ON assigned.id = t.assigned_agent_id AND assigned.organization_id = t.organization_id
		WHERE t.organization_id = $1
		  AND ($2 = '' OR t.status = $2::"AgentTaskStatus")
		  AND ($3 = '' OR t.assigned_agent_id = $3)
		ORDER BY t.created_at DESC
		LIMIT 50
	`, organizationID, statusFilter, assignedAgentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []map[string]any{}
	for rows.Next() {
		var task agentTaskRow
		if err := rows.Scan(
			&task.ID, &task.OrganizationID, &task.TaskType, &task.Title, &task.Status, &task.Input, &task.Output,
			&task.Error, &task.CreatedByAgentID, &task.AssignedAgentID, &task.ParentTaskID,
			&task.LeaseExpiresAt, &task.StartedAt, &task.CompletedAt, &task.CreatedAt, &task.UpdatedAt,
			&task.CreatedByKey, &task.CreatedByName, &task.CreatedByKind,
			&task.AssignedKey, &task.AssignedName, &task.AssignedKind,
		); err != nil {
			return nil, err
		}
		tasks = append(tasks, task.toJSON())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{"tasks": tasks}, nil
}

func (s *ToolService) proposeRemediation(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	proposedByAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["proposedByAgentKey"]))
	if err != nil {
		return nil, err
	}
	taskID, err := s.ensureTaskID(ctx, organizationID, stringValue(input["taskId"]))
	if err != nil {
		return nil, err
	}
	findingID, err := s.ensureFindingID(ctx, organizationID, stringValue(input["findingId"]))
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(input["payload"])
	if err != nil {
		return nil, err
	}
	proposalID := prefixedID("aprop")
	var status string
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO agent_proposals (
			id, organization_id, task_id, finding_id, proposed_by_agent_id, action,
			rationale, payload, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW(), NOW())
		RETURNING status::text
	`, proposalID, organizationID, nullableString(taskID), nullableString(findingID), nullableString(proposedByAgentID), input["action"], input["rationale"], string(payloadJSON)).Scan(&status)
	if err != nil {
		return nil, err
	}
	return map[string]any{"proposalId": proposalID, "status": status}, nil
}

func (s *ToolService) enqueueSIEMPayload(ctx context.Context, input map[string]any) (any, error) {
	payload := siemdispatcher.Payload{
		Kind:           stringValue(input["kind"]),
		OrganizationID: stringValue(input["organizationId"]),
		OccurredAt:     stringValue(input["occurredAt"]),
		Record:         input["record"].(map[string]any),
	}
	stream, err := siemdispatcher.StreamForKind(payload.Kind)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id
		FROM siem_destinations
		WHERE organization_id = $1
		  AND status IN ('ACTIVE', 'ERROR')
		  AND $2::"SiemStreamType" = ANY(streams)
	`, payload.OrganizationID, stream)
	if err != nil {
		return nil, err
	}
	destinationIDs := []string{}
	for rows.Next() {
		var destinationID string
		if err := rows.Scan(&destinationID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		destinationIDs = append(destinationIDs, destinationID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	created := int64(0)
	for _, destinationID := range destinationIDs {
		result, err := s.db.ExecContext(ctx, `
			INSERT INTO siem_deliveries (
				id, organization_id, destination_id, stream, dedupe_key, payload, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4::"SiemStreamType", $5, $6::jsonb, NOW(), NOW())
			ON CONFLICT (organization_id, destination_id, stream, dedupe_key) DO NOTHING
		`, prefixedID("sdel"), payload.OrganizationID, destinationID, stream, siemdispatcher.StableDeliveryKey(payload, destinationID, stream), string(payloadJSON))
		if err != nil {
			return nil, err
		}
		if rowsAffected, err := result.RowsAffected(); err == nil {
			created += rowsAffected
		}
	}
	return map[string]any{"enqueued": created}, nil
}

func (s *ToolService) getAgentID(ctx context.Context, organizationID string, key string) (string, error) {
	if key == "" {
		return "", nil
	}
	var id string
	if err := s.db.QueryRowContext(ctx, `
		SELECT id FROM agents WHERE organization_id = $1 AND key = $2
	`, organizationID, key).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("Agent not found: %s", key)
		}
		return "", err
	}
	return id, nil
}

func (s *ToolService) ensureTaskID(ctx context.Context, organizationID string, taskID string) (string, error) {
	if taskID == "" {
		return "", nil
	}
	var id string
	if err := s.db.QueryRowContext(ctx, `
		SELECT id FROM agent_tasks WHERE id = $1 AND organization_id = $2
	`, taskID, organizationID).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("Task not found: %s", taskID)
		}
		return "", err
	}
	return id, nil
}

func (s *ToolService) ensureFindingID(ctx context.Context, organizationID string, findingID string) (string, error) {
	if findingID == "" {
		return "", nil
	}
	var id string
	if err := s.db.QueryRowContext(ctx, `
		SELECT id FROM security_findings WHERE id = $1 AND organization_id = $2
	`, findingID, organizationID).Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("Finding not found: %s", findingID)
		}
		return "", err
	}
	return id, nil
}

type agentTaskRow struct {
	ID               string
	OrganizationID   string
	TaskType         string
	Title            string
	Status           string
	Input            []byte
	Output           []byte
	Error            sql.NullString
	CreatedByAgentID sql.NullString
	AssignedAgentID  sql.NullString
	ParentTaskID     sql.NullString
	LeaseExpiresAt   sql.NullTime
	StartedAt        sql.NullTime
	CompletedAt      sql.NullTime
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CreatedByKey     sql.NullString
	CreatedByName    sql.NullString
	CreatedByKind    sql.NullString
	AssignedKey      sql.NullString
	AssignedName     sql.NullString
	AssignedKind     sql.NullString
}

func (r agentTaskRow) toJSON() map[string]any {
	item := map[string]any{
		"id":               r.ID,
		"organizationId":   r.OrganizationID,
		"taskType":         r.TaskType,
		"title":            r.Title,
		"status":           r.Status,
		"input":            decodeJSON(r.Input),
		"output":           nullableJSON(r.Output),
		"error":            nullableValue(r.Error),
		"createdByAgentId": nullableValue(r.CreatedByAgentID),
		"assignedAgentId":  nullableValue(r.AssignedAgentID),
		"parentTaskId":     nullableValue(r.ParentTaskID),
		"leaseExpiresAt":   nullableTime(r.LeaseExpiresAt),
		"startedAt":        nullableTime(r.StartedAt),
		"completedAt":      nullableTime(r.CompletedAt),
		"createdAt":        formatMCPTime(r.CreatedAt),
		"updatedAt":        formatMCPTime(r.UpdatedAt),
		"createdByAgent":   agentSummary(r.CreatedByKey, r.CreatedByName, r.CreatedByKind),
		"assignedAgent":    agentSummary(r.AssignedKey, r.AssignedName, r.AssignedKind),
	}
	return item
}

func agentSummary(key sql.NullString, name sql.NullString, kind sql.NullString) any {
	if !key.Valid {
		return nil
	}
	return map[string]any{
		"key":  key.String,
		"name": name.String,
		"kind": kind.String,
	}
}

func decodeJSON(raw []byte) any {
	var value any
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return map[string]any{}
	}
	return value
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return decodeJSON(raw)
}

func nullableValue(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return formatMCPTime(value.Time)
}

func formatMCPTime(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func safeEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func postgresTextArray(values []string) string {
	var builder strings.Builder
	builder.WriteByte('{')
	for index, value := range values {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('"')
		for _, char := range value {
			if char == '\\' || char == '"' {
				builder.WriteByte('\\')
			}
			builder.WriteRune(char)
		}
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func prefixedID(prefix string) string {
	return prefix + "_" + randomID()
}

func randomID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

var getenv = func(key string) string {
	return strings.TrimSpace(strings.Trim(os.Getenv(key), "\x00"))
}
