package mcpbroker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/writer/aperio/internal/siemdispatcher"
)

func TestDBBackedAgentTaskMessageToolsPreserveSeededBehavior(t *testing.T) {
	db := openMCPToolTestDB(t)
	ctx := context.Background()
	orgID := seedMCPToolOrganization(t, db, "MCP Tools Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Other Org")
	service := newAuthenticatedTestToolService(t, db)

	register := callMCPToolFrame(t, service, "register-1", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "scanner",
		"name":           "Scanner Agent",
		"capabilities":   []any{" posture.scan "},
	})
	agentID := requireStringField(t, register, "agentId")
	if register["key"] != "scanner" || register["status"] != "ACTIVE" {
		t.Fatalf("register result drifted: %#v", register)
	}

	updatedRegister := callMCPToolFrame(t, service, "register-2", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "scanner",
		"name":           "Scanner Agent Renamed",
		"kind":           "SSPM_SCANNER",
		"capabilities":   []any{"posture.scan", "remediate.plan"},
		"endpointUrl":    "https://agents.example.test/scanner",
		"mcpServerUrl":   "https://agents.example.test/mcp",
		"status":         "PAUSED",
	})
	if updatedRegister["agentId"] != agentID {
		t.Fatalf("register_agent duplicate call changed id: first=%s second=%v", agentID, updatedRegister["agentId"])
	}
	if count := queryMCPInt(t, db, `SELECT COUNT(*) FROM agents WHERE organization_id = $1 AND key = 'scanner'`, orgID); count != 1 {
		t.Fatalf("register_agent created %d scanner rows, want 1", count)
	}
	assertAgentFields(t, db, agentID, "Scanner Agent Renamed", "SSPM_SCANNER", []string{"posture.scan", "remediate.plan"}, "PAUSED")

	assignee := callMCPToolFrame(t, service, "register-assignee", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "assignee",
		"name":           "Assignee Agent",
		"kind":           "REMEDIATION_PLANNER",
	})
	assigneeID := requireStringField(t, assignee, "agentId")
	otherAgent := callMCPToolFrame(t, service, "register-other-agent", "aperio.register_agent", map[string]any{
		"organizationId": otherOrgID,
		"key":            "scanner",
		"name":           "Other Tenant Scanner",
	})
	if otherAgent["agentId"] == agentID {
		t.Fatalf("same agent key in another tenant reused id %s", agentID)
	}
	_ = callMCPToolFrame(t, service, "register-other-only", "aperio.register_agent", map[string]any{
		"organizationId": otherOrgID,
		"key":            "foreign-only",
		"name":           "Foreign Only Agent",
	})

	parent := callMCPToolFrame(t, service, "create-parent", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "review",
		"title":             "Review finding",
		"input":             map[string]any{"phase": "parent"},
		"createdByAgentKey": "scanner",
		"assignedAgentKey":  "assignee",
	})
	parentID := requireStringField(t, parent, "taskId")
	if parent["status"] != "QUEUED" {
		t.Fatalf("parent task status = %v, want QUEUED", parent["status"])
	}
	child := callMCPToolFrame(t, service, "create-child", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "remediate",
		"title":             "Plan remediation",
		"input":             map[string]any{"phase": "child", "attempt": 1},
		"createdByAgentKey": "scanner",
		"assignedAgentKey":  "assignee",
		"parentTaskId":      parentID,
	})
	childID := requireStringField(t, child, "taskId")
	assertTaskReferences(t, db, childID, orgID, agentID, assigneeID, parentID)

	otherTask := callMCPToolFrame(t, service, "create-other-task", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"taskType":       "other",
		"title":          "Other tenant task",
	})
	otherTaskID := requireStringField(t, otherTask, "taskId")

	message := callMCPToolFrame(t, service, "send-message", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"taskId":         childID,
		"fromAgentKey":   "scanner",
		"toAgentKey":     "assignee",
		"correlationId":  "corr-1",
		"content":        map[string]any{"body": "ready", "ok": true},
	})
	messageID := requireStringField(t, message, "messageId")
	assertMCPISOTime(t, message["createdAt"])
	assertMessageReferences(t, db, messageID, orgID, childID, agentID, assigneeID)

	if _, err := db.ExecContext(ctx, `
		UPDATE agent_tasks
		SET status = 'SUCCEEDED'::"AgentTaskStatus", created_at = NOW() - INTERVAL '2 seconds', updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, parentID, orgID); err != nil {
		t.Fatalf("age parent task: %v", err)
	}

	all := callMCPToolFrame(t, service, "list-all", "aperio.list_tasks", map[string]any{"organizationId": orgID})
	allTasks := requireTaskList(t, all, 2)
	if allTasks[0]["id"] != childID || allTasks[1]["id"] != parentID {
		t.Fatalf("list_tasks ordering drifted: got first=%v second=%v want child=%s parent=%s", allTasks[0]["id"], allTasks[1]["id"], childID, parentID)
	}
	assertTaskResultShape(t, allTasks[0], childID, orgID, "remediate", "Plan remediation", "QUEUED", "scanner", "assignee", parentID)
	assertMCPISOTime(t, allTasks[0]["createdAt"])
	assertMCPISOTime(t, allTasks[0]["updatedAt"])

	queued := callMCPToolFrame(t, service, "list-queued-assignee", "aperio.list_tasks", map[string]any{
		"organizationId":   orgID,
		"status":           "QUEUED",
		"assignedAgentKey": "assignee",
	})
	queuedTasks := requireTaskList(t, queued, 1)
	if queuedTasks[0]["id"] != childID {
		t.Fatalf("list_tasks status/assigned filter returned %#v, want child task %s", queuedTasks, childID)
	}

	succeeded := callMCPToolFrame(t, service, "list-succeeded", "aperio.list_tasks", map[string]any{
		"organizationId": orgID,
		"status":         "SUCCEEDED",
	})
	succeededTasks := requireTaskList(t, succeeded, 1)
	if succeededTasks[0]["id"] != parentID {
		t.Fatalf("list_tasks status filter returned %#v, want parent task %s", succeededTasks, parentID)
	}

	if tasks := callMCPToolFrame(t, service, "list-other-org", "aperio.list_tasks", map[string]any{"organizationId": otherOrgID})["tasks"].([]any); len(tasks) != 1 || tasks[0].(map[string]any)["id"] != otherTaskID {
		t.Fatalf("cross-tenant task data leaked or disappeared: %#v", tasks)
	}

	beforeTasks := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_tasks WHERE organization_id = $1`, orgID)
	beforeMessages := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_messages WHERE organization_id = $1`, orgID)
	expectMCPToolErrorFrame(t, service, "bad-cross-agent", "aperio.create_task", map[string]any{
		"organizationId":   orgID,
		"taskType":         "review",
		"title":            "Bad cross tenant assignment",
		"assignedAgentKey": "foreign-only",
	})
	expectMCPToolErrorFrame(t, service, "bad-cross-task", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"taskId":         otherTaskID,
		"content":        map[string]any{"body": "must fail"},
	})
	expectMCPToolErrorFrame(t, service, "bad-list-cross-agent", "aperio.list_tasks", map[string]any{
		"organizationId":   orgID,
		"assignedAgentKey": "foreign-only",
	})
	if afterTasks := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_tasks WHERE organization_id = $1`, orgID); afterTasks != beforeTasks {
		t.Fatalf("invalid cross-tenant task reference changed task count from %d to %d", beforeTasks, afterTasks)
	}
	if afterMessages := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_messages WHERE organization_id = $1`, orgID); afterMessages != beforeMessages {
		t.Fatalf("invalid cross-tenant task reference changed message count from %d to %d", beforeMessages, afterMessages)
	}
}

func TestDBBackedRemediationProposalsStayHumanGated(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Proposal Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Proposal Other Org")
	service := newAuthenticatedTestToolService(t, db)

	agent := callMCPToolFrame(t, service, "proposal-agent", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "planner",
		"name":           "Planner Agent",
	})
	agentID := requireStringField(t, agent, "agentId")
	task := callMCPToolFrame(t, service, "proposal-task", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "remediation",
		"title":             "Draft remediation",
		"createdByAgentKey": "planner",
	})
	taskID := requireStringField(t, task, "taskId")
	_, findingID := seedMCPFinding(t, db, orgID, "proposal")
	_, otherFindingID := seedMCPFinding(t, db, otherOrgID, "other-proposal")
	otherTask := callMCPToolFrame(t, service, "other-proposal-task", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"taskType":       "other",
		"title":          "Other proposal task",
	})
	otherTaskID := requireStringField(t, otherTask, "taskId")

	beforeProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id = $1`, orgID)
	beforeAuditLogs := queryMCPInt(t, db, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1`, orgID)
	proposal := callMCPToolFrame(t, service, "proposal", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          findingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Human approval required before revoking the app.",
		"payload":            map[string]any{"appId": "A123", "dryRun": true},
	})
	proposalID := requireStringField(t, proposal, "proposalId")
	if proposal["status"] != "PROPOSED" {
		t.Fatalf("proposal status = %v, want PROPOSED", proposal["status"])
	}
	assertProposalHumanGated(t, db, proposalID, orgID, taskID, findingID, agentID)
	if afterProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id = $1`, orgID); afterProposals != beforeProposals+1 {
		t.Fatalf("proposal count = %d, want %d", afterProposals, beforeProposals+1)
	}
	if afterAuditLogs := queryMCPInt(t, db, `SELECT COUNT(*) FROM tenant_audit_logs WHERE organization_id = $1`, orgID); afterAuditLogs != beforeAuditLogs {
		t.Fatalf("proposal tool produced provider/audit side effects: before=%d after=%d", beforeAuditLogs, afterAuditLogs)
	}

	beforeAllProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id IN ($1, $2)`, orgID, otherOrgID)
	expectMCPToolErrorFrame(t, service, "proposal-cross-task", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             otherTaskID,
		"findingId":          findingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for cross-tenant task.",
		"payload":            map[string]any{"appId": "A123"},
	})
	expectMCPToolErrorFrame(t, service, "proposal-cross-finding", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          otherFindingID,
		"proposedByAgentKey": "planner",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for cross-tenant finding.",
		"payload":            map[string]any{"appId": "A123"},
	})
	expectMCPToolErrorFrame(t, service, "proposal-missing-agent", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"taskId":             taskID,
		"findingId":          findingID,
		"proposedByAgentKey": "missing-agent",
		"action":             "slack.revoke_app_install",
		"rationale":          "Must fail for missing proposing agent.",
		"payload":            map[string]any{"appId": "A123"},
	})
	if afterAllProposals := queryMCPInt(t, db, `SELECT COUNT(*) FROM agent_proposals WHERE organization_id IN ($1, $2)`, orgID, otherOrgID); afterAllProposals != beforeAllProposals {
		t.Fatalf("invalid proposal references changed proposal count from %d to %d", beforeAllProposals, afterAllProposals)
	}
}

func TestDBBackedCerebroIncidentToolsExposeGraphContextAndGateResponses(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Cerebro Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Cerebro Other Org")
	_, findingID := seedMCPFinding(t, db, orgID, "cerebro")
	_, otherFindingID := seedMCPFinding(t, db, otherOrgID, "other-cerebro")
	incidentID := seedMCPCerebroIncident(t, db, orgID, findingID, "primary")
	otherIncidentID := seedMCPCerebroIncident(t, db, otherOrgID, otherFindingID, "other")
	service := newAuthenticatedTestToolService(t, db)
	service.SetNowForTesting(func() time.Time {
		return time.Date(2026, 6, 7, 14, 0, 0, 0, time.UTC)
	})

	_ = callMCPToolFrame(t, service, "cerebro-agent", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "cerebro-planner",
		"name":           "Cerebro Planner",
		"kind":           "REMEDIATION_PLANNER",
	})
	task := callMCPToolFrame(t, service, "cerebro-task", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"taskType":          "cerebro.incident.response",
		"title":             "Plan Cerebro response",
		"createdByAgentKey": "cerebro-planner",
	})
	taskID := requireStringField(t, task, "taskId")

	list := callMCPToolFrame(t, service, "cerebro-list", "aperio.list_cerebro_incidents", map[string]any{
		"organizationId": orgID,
		"status":         "INVESTIGATING",
		"limit":          10,
	})
	resources := list["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("list_cerebro_incidents resources = %#v, want one tenant-local incident", resources)
	}
	resource := resources[0].(map[string]any)
	if resource["id"] != incidentID || resource["title"] == "" {
		t.Fatalf("list_cerebro_incidents resource drifted: %#v", resource)
	}
	if got := resource["resource"].(map[string]any)["uri"]; got != cerebroIncidentResourceURI(orgID, incidentID) {
		t.Fatalf("resource uri = %v, want %s", got, cerebroIncidentResourceURI(orgID, incidentID))
	}
	cerebro := resource["cerebro"].(map[string]any)
	if cerebro["mode"] != "claim-fanout" || cerebro["graphSignalCount"].(float64) != 1 {
		t.Fatalf("Cerebro summary drifted: %#v", cerebro)
	}

	detail := callMCPToolFrame(t, service, "cerebro-get", "aperio.get_cerebro_incident_context", map[string]any{
		"organizationId": orgID,
		"incidentId":     incidentID,
	})
	if detail["server"] != ServerName {
		t.Fatalf("get_cerebro_incident_context server = %#v", detail["server"])
	}
	if detail["resource"].(map[string]any)["mimeType"] != cerebroIncidentMimeType {
		t.Fatalf("detail resource drifted: %#v", detail["resource"])
	}
	incident := detail["incident"].(map[string]any)
	context := incident["cerebroContext"].(map[string]any)
	if context["sourceRuntimeId"] != "writer-aperio-sspm" || context["findingContract"] != "cerebro.v1.Finding" {
		t.Fatalf("detail Cerebro context drifted: %#v", context)
	}
	if findings := detail["findings"].([]any); len(findings) != 1 || findings[0].(map[string]any)["id"] != findingID {
		t.Fatalf("detail findings drifted: %#v", findings)
	}

	beforeActions := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_response_actions WHERE organization_id = $1`, orgID)
	beforeTimeline := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_incident_timeline_events WHERE organization_id = $1`, orgID)
	proposal := callMCPToolFrame(t, service, "cerebro-propose", "aperio.propose_cerebro_response", map[string]any{
		"organizationId":     orgID,
		"incidentId":         incidentID,
		"findingId":          findingID,
		"taskId":             taskID,
		"proposedByAgentKey": "cerebro-planner",
		"action":             "REVOKE_OAUTH_GRANT",
		"provider":           "GOOGLE_WORKSPACE",
		"targetType":         "oauth_app",
		"targetIdentifier":   "Vendor Analytics Add-on",
		"rationale":          "Cerebro graph path shows the vendor app can reach restricted board materials.",
	})
	actionID := requireStringField(t, proposal, "responseActionId")
	if proposal["status"] != "PROPOSED" || proposal["resourceUri"] != cerebroIncidentResourceURI(orgID, incidentID) {
		t.Fatalf("propose_cerebro_response result drifted: %#v", proposal)
	}
	if afterActions := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_response_actions WHERE organization_id = $1`, orgID); afterActions != beforeActions+1 {
		t.Fatalf("response action count = %d, want %d", afterActions, beforeActions+1)
	}
	if afterTimeline := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_incident_timeline_events WHERE organization_id = $1`, orgID); afterTimeline != beforeTimeline+1 {
		t.Fatalf("timeline count = %d, want %d", afterTimeline, beforeTimeline+1)
	}
	assertCerebroResponseAction(t, db, orgID, actionID, incidentID, findingID)

	beforeInvalid := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_response_actions WHERE organization_id IN ($1, $2)`, orgID, otherOrgID)
	expectMCPToolErrorFrame(t, service, "cerebro-cross-incident", "aperio.get_cerebro_incident_context", map[string]any{
		"organizationId": orgID,
		"incidentId":     otherIncidentID,
	})
	expectMCPToolErrorFrame(t, service, "cerebro-cross-finding", "aperio.propose_cerebro_response", map[string]any{
		"organizationId":   orgID,
		"incidentId":       incidentID,
		"findingId":        otherFindingID,
		"action":           "REVOKE_OAUTH_GRANT",
		"targetType":       "oauth_app",
		"targetIdentifier": "Other app",
		"rationale":        "Must fail for a finding from another tenant.",
	})
	if afterInvalid := queryMCPInt(t, db, `SELECT COUNT(*) FROM saas_response_actions WHERE organization_id IN ($1, $2)`, orgID, otherOrgID); afterInvalid != beforeInvalid {
		t.Fatalf("invalid Cerebro MCP calls changed response action count from %d to %d", beforeInvalid, afterInvalid)
	}
}

func TestDBBackedCerebroFindingToolsExposeContextAndTenantBoundaries(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Cerebro Finding Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Cerebro Finding Other Org")
	_, findingID := seedMCPFinding(t, db, orgID, "finding-resource")
	_, otherFindingID := seedMCPFinding(t, db, otherOrgID, "finding-resource-other")
	incidentID := seedMCPCerebroIncident(t, db, orgID, findingID, "finding-resource")
	_ = seedMCPCerebroIncident(t, db, otherOrgID, otherFindingID, "finding-resource-other")
	service := newAuthenticatedTestToolService(t, db)

	before := mcpSideEffectCount(t, db, orgID)
	list := callMCPToolFrame(t, service, "cerebro-finding-list", "aperio.list_cerebro_findings", map[string]any{
		"organizationId": orgID,
		"status":         "OPEN",
		"severity":       "HIGH",
		"provider":       "SLACK",
		"limit":          10,
	})
	resources := list["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("list_cerebro_findings resources = %#v, want one tenant-local finding", resources)
	}
	resource := resources[0].(map[string]any)
	if resource["id"] != findingID || resource["title"] == "" {
		t.Fatalf("list_cerebro_findings resource drifted: %#v", resource)
	}
	if got := resource["resource"].(map[string]any)["uri"]; got != cerebroFindingResourceURI(orgID, findingID) {
		t.Fatalf("finding resource uri = %v, want %s", got, cerebroFindingResourceURI(orgID, findingID))
	}
	cerebro := resource["cerebro"].(map[string]any)
	if cerebro["source"] != "local-projection" || cerebro["mode"] != "not-configured" || cerebro["findingContract"] != "cerebro.v1.Finding" || cerebro["sourceEventId"] == nil {
		t.Fatalf("finding Cerebro summary drifted: %#v", cerebro)
	}

	detail := callMCPToolFrame(t, service, "cerebro-finding-get", "aperio.get_cerebro_finding_context", map[string]any{
		"organizationId": orgID,
		"findingId":      findingID,
	})
	if detail["server"] != ServerName {
		t.Fatalf("get_cerebro_finding_context server = %#v", detail["server"])
	}
	if detail["resource"].(map[string]any)["mimeType"] != cerebroFindingMimeType {
		t.Fatalf("detail finding resource drifted: %#v", detail["resource"])
	}
	finding := detail["finding"].(map[string]any)
	context := finding["cerebroContext"].(map[string]any)
	if context["source"] != "local-projection" || context["findingContract"] != "cerebro.v1.Finding" {
		t.Fatalf("detail finding Cerebro context drifted: %#v", context)
	}
	mcp := context["mcp"].(map[string]any)
	if mcp["resourceUri"] != cerebroFindingResourceURI(orgID, findingID) || mcp["mimeType"] != cerebroFindingMimeType {
		t.Fatalf("detail finding MCP context drifted: %#v", mcp)
	}
	if templates := mcp["resourceTemplates"].([]any); len(templates) != 3 {
		t.Fatalf("detail finding MCP resource templates = %#v, want three templates", templates)
	}
	incidents := detail["incidents"].([]any)
	if len(incidents) != 1 || incidents[0].(map[string]any)["id"] != incidentID {
		t.Fatalf("detail finding incidents drifted: %#v", incidents)
	}

	expectMCPToolErrorFrame(t, service, "cerebro-finding-cross-get", "aperio.get_cerebro_finding_context", map[string]any{
		"organizationId": orgID,
		"findingId":      otherFindingID,
	})
	if after := mcpSideEffectCount(t, db, orgID); after != before {
		t.Fatalf("finding MCP read tools changed side-effect count from %d to %d", before, after)
	}
}

func TestDBBackedCerebroResourceReadsUseAuthAndTenantScope(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Cerebro Resource Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Cerebro Resource Other Org")
	_, findingID := seedMCPFinding(t, db, orgID, "resource-read")
	_, otherFindingID := seedMCPFinding(t, db, otherOrgID, "resource-read-other")
	incidentID := seedMCPCerebroIncident(t, db, orgID, findingID, "resource-read")
	otherIncidentID := seedMCPCerebroIncident(t, db, otherOrgID, otherFindingID, "resource-read-other")
	secret := "resource-secret-" + randomID()
	t.Setenv("APERIO_MCP_ORGANIZATION_ID", orgID)
	t.Setenv("APERIO_MCP_SHARED_SECRET", secret)
	service := NewToolService(db)

	beforeOrg := mcpSideEffectCount(t, db, orgID)
	beforeOtherOrg := mcpSideEffectCount(t, db, otherOrgID)
	incident, incidentContent := callMCPResourceReadFrame(t, service, "read-incident", cerebroIncidentResourceURI(orgID, incidentID))
	if incidentContent["uri"] != cerebroIncidentResourceURI(orgID, incidentID) ||
		incidentContent["mimeType"] != cerebroIncidentMimeType {
		t.Fatalf("incident resource content drifted: %#v", incidentContent)
	}
	if incident["server"] != ServerName {
		t.Fatalf("incident resource server = %#v", incident["server"])
	}
	incidentResource := incident["resource"].(map[string]any)
	if incidentResource["uri"] != cerebroIncidentResourceURI(orgID, incidentID) {
		t.Fatalf("incident resource uri = %v, want %s", incidentResource["uri"], cerebroIncidentResourceURI(orgID, incidentID))
	}
	incidentDetail := incident["incident"].(map[string]any)
	if incidentDetail["id"] != incidentID {
		t.Fatalf("incident detail id = %v, want %s", incidentDetail["id"], incidentID)
	}

	finding, findingContent := callMCPResourceReadFrame(t, service, "read-finding", cerebroFindingResourceURI(orgID, findingID))
	if findingContent["uri"] != cerebroFindingResourceURI(orgID, findingID) ||
		findingContent["mimeType"] != cerebroFindingMimeType {
		t.Fatalf("finding resource content drifted: %#v", findingContent)
	}
	findingDetail := finding["finding"].(map[string]any)
	if findingDetail["id"] != findingID {
		t.Fatalf("finding detail id = %v, want %s", findingDetail["id"], findingID)
	}
	if incidents := finding["incidents"].([]any); len(incidents) != 1 || incidents[0].(map[string]any)["id"] != incidentID {
		t.Fatalf("finding linked incidents drifted: %#v", incidents)
	}

	security, securityContent := callMCPResourceReadFrame(t, service, "read-security-overview", cerebroSecurityOverviewResourceURI(orgID))
	if securityContent["uri"] != cerebroSecurityOverviewResourceURI(orgID) ||
		securityContent["mimeType"] != cerebroSecurityOverviewMimeType {
		t.Fatalf("security overview resource content drifted: %#v", securityContent)
	}
	summary := security["summary"].(map[string]any)
	if summary["openFindingCount"].(float64) != 1 ||
		summary["highFindingCount"].(float64) != 1 ||
		summary["activeIncidentCount"].(float64) != 1 {
		t.Fatalf("security overview summary drifted: %#v", summary)
	}
	if findings := security["findings"].([]any); len(findings) != 1 || findings[0].(map[string]any)["id"] != findingID {
		t.Fatalf("security overview findings drifted: %#v", findings)
	}
	if incidents := security["incidents"].([]any); len(incidents) != 1 || incidents[0].(map[string]any)["id"] != incidentID {
		t.Fatalf("security overview incidents drifted: %#v", incidents)
	}
	securityContext := security["cerebroContext"].(map[string]any)
	securityMCP := securityContext["mcp"].(map[string]any)
	if securityContext["mode"] != "mcp-resource" || securityMCP["resourceUri"] != cerebroSecurityOverviewResourceURI(orgID) {
		t.Fatalf("security overview Cerebro MCP context drifted: %#v", securityContext)
	}
	if templates := securityMCP["resourceTemplates"].([]any); len(templates) != 3 {
		t.Fatalf("security overview MCP resource templates = %#v, want three templates", templates)
	}

	missingTokenOutput := expectMCPResourceReadErrorFrame(t, service, "read-missing-token", cerebroIncidentResourceURI(orgID, incidentID))
	wrongOrgOutput := expectMCPResourceReadErrorFrame(t, service, "read-wrong-org", cerebroIncidentResourceURI(otherOrgID, otherIncidentID), secret)
	for label, output := range map[string][]byte{
		"missing token": missingTokenOutput,
		"wrong org":     wrongOrgOutput,
	} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("%s resource read error disclosed shared secret in stdout: %q", label, string(output))
		}
	}
	if afterOrg := mcpSideEffectCount(t, db, orgID); afterOrg != beforeOrg {
		t.Fatalf("resource reads changed scoped side effects from %d to %d", beforeOrg, afterOrg)
	}
	if afterOtherOrg := mcpSideEffectCount(t, db, otherOrgID); afterOtherOrg != beforeOtherOrg {
		t.Fatalf("wrong-organization resource read changed other tenant side effects from %d to %d", beforeOtherOrg, afterOtherOrg)
	}
}

func TestMCPSharedSecretAndTenantBoundariesRejectBeforeSideEffectsAndDoNotPersistSecrets(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Secret Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP Secret Other Org")
	_ = seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "ACTIVE", "secret-finding.jsonl")
	_ = seedMCPSIEMDestination(t, db, otherOrgID, "FINDINGS", "ACTIVE", "secret-other-finding.jsonl")
	secret := "mcp-secret-" + randomID()
	t.Setenv("APERIO_MCP_ORGANIZATION_ID", orgID)
	t.Setenv("APERIO_MCP_SHARED_SECRET", secret)
	service := newAuthenticatedTestToolService(t, db)

	beforeOrg := mcpSideEffectCount(t, db, orgID)
	beforeOtherOrg := mcpSideEffectCount(t, db, otherOrgID)
	missingTokenOutput := expectMCPToolErrorFrame(t, service, "missing-token", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"authToken":      "",
		"key":            "blocked",
		"name":           "Blocked Agent",
	})
	wrongTokenOutput := expectMCPToolErrorFrame(t, service, "wrong-token", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"authToken":      "wrong-" + randomID(),
		"key":            "blocked",
		"name":           "Blocked Agent",
	})
	wrongOrgOutput := expectMCPToolErrorFrame(t, service, "wrong-org", "aperio.create_task", map[string]any{
		"organizationId": otherOrgID,
		"authToken":      secret,
		"taskType":       "blocked",
		"title":          "Blocked task",
	})
	missingSIEMTokenOutput := expectMCPToolErrorFrame(t, service, "siem-missing-token", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"authToken":      "",
		"record":         map[string]any{"id": "blocked-siem"},
	})
	wrongSIEMOrgOutput := expectMCPToolErrorFrame(t, service, "siem-wrong-org", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": otherOrgID,
		"authToken":      secret,
		"record":         map[string]any{"id": "blocked-other-siem"},
	})
	for label, output := range map[string][]byte{
		"missing token":      missingTokenOutput,
		"wrong token":        wrongTokenOutput,
		"wrong org":          wrongOrgOutput,
		"siem missing token": missingSIEMTokenOutput,
		"siem wrong org":     wrongSIEMOrgOutput,
	} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("%s error frame disclosed shared secret in stdout: %q", label, string(output))
		}
	}
	if afterOrg := mcpSideEffectCount(t, db, orgID); afterOrg != beforeOrg {
		t.Fatalf("auth failures changed scoped side effects from %d to %d", beforeOrg, afterOrg)
	}
	if afterOtherOrg := mcpSideEffectCount(t, db, otherOrgID); afterOtherOrg != beforeOtherOrg {
		t.Fatalf("wrong-organization call changed other tenant side effects from %d to %d", beforeOtherOrg, afterOtherOrg)
	}

	agent := callMCPToolFrame(t, service, "secret-register", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"authToken":      secret,
		"key":            "secret-agent",
		"name":           "Secret Scoped Agent",
	})
	agentID := requireStringField(t, agent, "agentId")
	task := callMCPToolFrame(t, service, "secret-task", "aperio.create_task", map[string]any{
		"organizationId":    orgID,
		"authToken":         secret,
		"taskType":          "secret-safe",
		"title":             "Secret-safe task",
		"input":             map[string]any{"note": "auth token must not be copied"},
		"createdByAgentKey": "secret-agent",
	})
	taskID := requireStringField(t, task, "taskId")
	message := callMCPToolFrame(t, service, "secret-message", "aperio.send_message", map[string]any{
		"organizationId": orgID,
		"authToken":      secret,
		"taskId":         taskID,
		"fromAgentKey":   "secret-agent",
		"content":        map[string]any{"body": "safe content"},
	})
	_ = requireStringField(t, message, "messageId")
	proposal := callMCPToolFrame(t, service, "secret-proposal", "aperio.propose_remediation", map[string]any{
		"organizationId":     orgID,
		"authToken":          secret,
		"taskId":             taskID,
		"proposedByAgentKey": "secret-agent",
		"action":             "manual.review",
		"rationale":          "Human-gated proposal with no copied auth token.",
		"payload":            map[string]any{"ticket": "SEC-1"},
	})
	_ = requireStringField(t, proposal, "proposalId")
	siem := callMCPToolFrame(t, service, "secret-siem", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"authToken":      secret,
		"record":         map[string]any{"id": "secret-safe-siem", "sourceEventId": "evt-secret-safe"},
	})
	requireMCPEnqueued(t, siem, 1)
	if agentID == "" || taskID == "" {
		t.Fatalf("valid secret-scoped calls did not produce ids")
	}
	assertMCPSecretNotPersisted(t, db, orgID, secret)
}

func TestMCPBrokerRejectsDBToolsWhenScopeIsUnconfigured(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Unconfigured Org")
	service := NewToolService(db)

	before := mcpSideEffectCount(t, db, orgID)
	output := expectMCPToolErrorFrame(t, service, "unconfigured", "aperio.register_agent", map[string]any{
		"organizationId": orgID,
		"key":            "blocked",
		"name":           "Blocked Agent",
	})
	if !bytes.Contains(output, []byte("requires APERIO_MCP_SHARED_SECRET or APERIO_MCP_ORGANIZATION_ID")) {
		t.Fatalf("unconfigured broker error did not explain fail-closed requirement: %q", string(output))
	}
	if after := mcpSideEffectCount(t, db, orgID); after != before {
		t.Fatalf("unconfigured broker changed scoped side effects from %d to %d", before, after)
	}
}

func TestDBBackedMutatingToolNotificationsDoNotCreateSideEffects(t *testing.T) {
	db := openMCPToolTestDB(t)
	orgID := seedMCPToolOrganization(t, db, "MCP Notification Org")
	_ = seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "ACTIVE", "notification-finding.jsonl")
	service := newAuthenticatedTestToolService(t, db)

	before := mcpSideEffectCount(t, db, orgID)
	notification := func(name string, args map[string]any) map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]any{
				"name":      name,
				"arguments": args,
			},
		}
	}
	input := joinFrames(t,
		notification("aperio.register_agent", map[string]any{
			"organizationId": orgID,
			"key":            "notify-agent",
			"name":           "Notification Agent",
		}),
		notification("aperio.create_task", map[string]any{
			"organizationId": orgID,
			"taskType":       "notification",
			"title":          "Notification-created task",
		}),
		notification("aperio.send_message", map[string]any{
			"organizationId": orgID,
			"content":        map[string]any{"body": "notification message"},
		}),
		notification("aperio.propose_remediation", map[string]any{
			"organizationId": orgID,
			"action":         "manual.review",
			"rationale":      "This notification must not create a proposal.",
			"payload":        map[string]any{"source": "notification"},
		}),
		notification("aperio.enqueue_siem_payload", map[string]any{
			"organizationId": orgID,
			"record":         map[string]any{"id": "notification-finding", "sourceEventId": "evt-notification"},
		}),
		map[string]any{"jsonrpc": "2.0", "id": "after-notifications", "method": "ping"},
	)
	stdout := runServer(t, NewServer(service), strings.NewReader(input))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("notification sequence emitted %d response frames, want only the final ping: %#v", len(frames), frames)
	}
	if frames[0]["id"] != "after-notifications" {
		t.Fatalf("broker did not remain alive for ping after notifications: %#v", frames[0])
	}
	after := mcpSideEffectCount(t, db, orgID)
	if after != before {
		t.Fatalf("mutating notifications changed scoped side effects from %d to %d", before, after)
	}
}

func TestDBBackedSIEMEnqueueFansOutTenantLocalSubscribedDestinations(t *testing.T) {
	db := openMCPToolTestDB(t)
	ctx := context.Background()
	orgID := seedMCPToolOrganization(t, db, "MCP SIEM Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP SIEM Other Org")
	noDestinationOrgID := seedMCPToolOrganization(t, db, "MCP SIEM Empty Org")
	service := newAuthenticatedTestToolService(t, db)
	service.SetNowForTesting(func() time.Time {
		return time.Date(2026, 6, 7, 12, 30, 0, 0, time.UTC)
	})

	findingActiveDestinationID := seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "ACTIVE", "finding-active.jsonl")
	findingErrorDestinationID := seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "ERROR", "finding-error.jsonl")
	_ = seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "PAUSED", "finding-paused.jsonl")
	eventDestinationID := seedMCPSIEMDestination(t, db, orgID, "EVENTS", "ACTIVE", "event-active.jsonl")
	auditDestinationID := seedMCPSIEMDestination(t, db, orgID, "AUDIT_LOGS", "ACTIVE", "audit-active.jsonl")
	_ = seedMCPSIEMDestination(t, db, otherOrgID, "FINDINGS", "ACTIVE", "other-finding.jsonl")

	occurredAt := "2026-06-07T12:30:00Z"
	findingRecord := map[string]any{
		"findingId":     "fnd-mcp-1",
		"sourceEventId": "evt-mcp-1",
		"status":        "OPEN",
		"title":         "MCP finding payload",
	}
	findingResult := callMCPToolFrame(t, service, "siem-finding", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"kind":           "finding",
		"occurredAt":     occurredAt,
		"record":         findingRecord,
	})
	requireMCPEnqueued(t, findingResult, 2)
	repeatedFindingResult := callMCPToolFrame(t, service, "siem-finding-repeat", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"kind":           "finding",
		"occurredAt":     occurredAt,
		"record":         findingRecord,
	})
	requireMCPEnqueued(t, repeatedFindingResult, 0)

	eventResult := callMCPToolFrame(t, service, "siem-event", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"kind":           "event",
		"occurredAt":     occurredAt,
		"record": map[string]any{
			"id":            "event-mcp-1",
			"sourceEventId": "source-event-mcp-1",
			"eventType":     "user.login",
		},
	})
	requireMCPEnqueued(t, eventResult, 1)

	auditResult := callMCPToolFrame(t, service, "siem-audit", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"kind":           "audit_log",
		"occurredAt":     occurredAt,
		"record": map[string]any{
			"id":            "audit-mcp-1",
			"sourceEventId": "source-audit-mcp-1",
			"action":        "settings.update",
		},
	})
	requireMCPEnqueued(t, auditResult, 1)

	emptyResult := callMCPToolFrame(t, service, "siem-empty", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": noDestinationOrgID,
		"kind":           "finding",
		"record":         map[string]any{"id": "no-destination"},
	})
	requireMCPEnqueued(t, emptyResult, 0)
	if count := queryMCPInt(t, db, `SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1`, noDestinationOrgID); count != 0 {
		t.Fatalf("empty tenant created %d SIEM deliveries, want 0", count)
	}
	if otherCount := queryMCPInt(t, db, `SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1`, otherOrgID); otherCount != 0 {
		t.Fatalf("cross-tenant destination received %d SIEM deliveries, want 0", otherCount)
	}

	deliveries := mcpSIEMDeliveries(t, db, orgID)
	if len(deliveries) != 4 {
		t.Fatalf("tenant SIEM delivery count = %d, want 4: %#v", len(deliveries), deliveries)
	}
	expected := map[string]struct {
		stream string
		kind   string
	}{
		findingActiveDestinationID: {"FINDINGS", "finding"},
		findingErrorDestinationID:  {"FINDINGS", "finding"},
		eventDestinationID:         {"EVENTS", "event"},
		auditDestinationID:         {"AUDIT_LOGS", "audit_log"},
	}
	for _, delivery := range deliveries {
		want, ok := expected[delivery.DestinationID]
		if !ok {
			t.Fatalf("unexpected destination enqueued: %#v", delivery)
		}
		if delivery.OrganizationID != orgID || delivery.Stream != want.stream || delivery.Status != "PENDING" || delivery.Attempts != 0 || delivery.DeliveredAt.Valid {
			t.Fatalf("delivery row drifted for destination %s: %#v", delivery.DestinationID, delivery)
		}
		if delivery.Payload.OrganizationID != orgID || delivery.Payload.Kind != want.kind || delivery.Payload.OccurredAt == "" {
			t.Fatalf("delivery payload drifted for destination %s: %#v", delivery.DestinationID, delivery.Payload)
		}
		if got := siemdispatcher.StableDeliveryKey(delivery.Payload, delivery.DestinationID, delivery.Stream); delivery.DedupeKey != got {
			t.Fatalf("delivery dedupe key = %s, want %s for payload %#v", delivery.DedupeKey, got, delivery.Payload)
		}
		delete(expected, delivery.DestinationID)
	}
	if len(expected) != 0 {
		t.Fatalf("missing expected SIEM destinations: %#v", expected)
	}
	if count := queryMCPInt(t, db, `
		SELECT COUNT(*)
		FROM siem_deliveries
		WHERE organization_id = $1
		  AND destination_id IN (
		    SELECT id FROM siem_destinations
		    WHERE organization_id = $1 AND status = 'PAUSED'::"SiemStatus"
		  )
	`, orgID); count != 0 {
		t.Fatalf("paused destinations received %d deliveries, want 0", count)
	}
	if _, err := db.ExecContext(ctx, `SELECT 1`); err != nil {
		t.Fatalf("db liveness after SIEM enqueue fanout test: %v", err)
	}
}

func TestDBBackedSIEMEnqueueOnlyThenGoDispatcherDrainDelivers(t *testing.T) {
	db := openMCPToolTestDB(t)
	ctx := context.Background()
	orgID := seedMCPToolOrganization(t, db, "MCP SIEM Enqueue Only Org")
	otherOrgID := seedMCPToolOrganization(t, db, "MCP SIEM Enqueue Only Other Org")
	exportRoot := t.TempDir()
	t.Setenv("APERIO_SIEM_EXPORT_DIR", exportRoot)
	fileName := "mcp-enqueue-only.jsonl"
	filePath := filepath.Join(exportRoot, fileName)
	destinationID := seedMCPSIEMDestination(t, db, orgID, "FINDINGS", "ERROR", fileName)
	_ = seedMCPSIEMDestination(t, db, otherOrgID, "FINDINGS", "ACTIVE", "other-enqueue-only.jsonl")
	if _, err := db.ExecContext(ctx, `
		UPDATE siem_destinations
		SET deliveries_ok = 2,
		    deliveries_fail = 5,
		    last_error = 'previous delivery failure',
		    last_delivery_at = NULL,
		    updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, destinationID, orgID); err != nil {
		t.Fatalf("seed destination health: %v", err)
	}

	service := newAuthenticatedTestToolService(t, db)
	service.SetNowForTesting(func() time.Time {
		return time.Date(2026, 6, 7, 13, 0, 0, 0, time.UTC)
	})
	result := callMCPToolFrame(t, service, "siem-enqueue-only", "aperio.enqueue_siem_payload", map[string]any{
		"organizationId": orgID,
		"kind":           "finding",
		"record": map[string]any{
			"findingId":     "fnd-enqueue-only",
			"sourceEventId": "evt-enqueue-only",
			"status":        "OPEN",
			"title":         "Enqueue-only finding",
		},
	})
	requireMCPEnqueued(t, result, 1)

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("MCP enqueue wrote JSONL file before dispatcher drain: stat err=%v", err)
	}
	delivery := requireSingleMCPDelivery(t, db, orgID, destinationID)
	if delivery.Status != "PENDING" || delivery.Attempts != 0 || delivery.DeliveredAt.Valid {
		t.Fatalf("MCP enqueue drained or finalized delivery: %#v", delivery)
	}
	status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError := mcpSIEMDestinationHealth(t, db, orgID, destinationID)
	if status != "ERROR" || deliveriesOK != 2 || deliveriesFail != 5 || lastDeliveryAt.Valid || !lastError.Valid || lastError.String != "previous delivery failure" {
		t.Fatalf("MCP enqueue mutated destination health: status=%s ok=%d fail=%d lastDelivery=%v lastError=%v", status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError)
	}
	if otherCount := queryMCPInt(t, db, `SELECT COUNT(*) FROM siem_deliveries WHERE organization_id = $1`, otherOrgID); otherCount != 0 {
		t.Fatalf("MCP enqueue created %d rows for another tenant, want 0", otherCount)
	}

	dispatcher := siemdispatcher.New(db)
	dispatcher.SetOrganizationScope(orgID)
	drainResult, err := dispatcher.Drain(ctx, 1)
	if err != nil {
		t.Fatalf("drain MCP-enqueued delivery with Go dispatcher: %v", err)
	}
	if drainResult.Processed != 1 || drainResult.Delivered != 1 || drainResult.Failed != 0 {
		t.Fatalf("unexpected dispatcher drain result: %#v", drainResult)
	}
	delivered := requireSingleMCPDelivery(t, db, orgID, destinationID)
	if delivered.Status != "DELIVERED" || delivered.Attempts != 1 || !delivered.DeliveredAt.Valid {
		t.Fatalf("Go dispatcher did not deliver MCP-enqueued row: %#v", delivered)
	}
	status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError = mcpSIEMDestinationHealth(t, db, orgID, destinationID)
	if status != "ACTIVE" || deliveriesOK != 3 || deliveriesFail != 5 || !lastDeliveryAt.Valid || lastError.Valid {
		t.Fatalf("Go dispatcher did not update destination health after drain: status=%s ok=%d fail=%d lastDelivery=%v lastError=%v", status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError)
	}
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read dispatcher JSONL output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(fileBytes)), "\n")
	if len(lines) != 1 {
		t.Fatalf("JSONL line count = %d, want 1: %q", len(lines), string(fileBytes))
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &envelope); err != nil {
		t.Fatalf("decode dispatcher JSONL envelope: %v", err)
	}
	if envelope["schema_version"] != "aperio.finding.v1" ||
		envelope["destination_id"] != destinationID ||
		envelope["organization_id"] != orgID ||
		envelope["kind"] != "finding" {
		t.Fatalf("dispatcher envelope drifted: %#v", envelope)
	}
	record := envelope["record"].(map[string]any)
	if record["findingId"] != "fnd-enqueue-only" || record["sourceEventId"] != "evt-enqueue-only" {
		t.Fatalf("dispatcher envelope record drifted: %#v", record)
	}
}

func openMCPToolTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("APERIO_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("APERIO_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open MCP test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping MCP test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func seedMCPToolOrganization(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	orgID := prefixedID("org")
	slug := "mcp-tools-" + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO organizations (id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`, orgID, name, slug); err != nil {
		t.Fatalf("seed MCP organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID
}

func seedMCPFinding(t *testing.T, db *sql.DB, orgID string, suffix string) (string, string) {
	t.Helper()
	integrationID := prefixedID("int")
	findingID := prefixedID("fnd")
	evidenceJSON, err := json.Marshal(map[string]any{
		"subject":       "A123",
		"sourceEventId": "evt-" + suffix,
	})
	if err != nil {
		t.Fatalf("encode MCP finding evidence: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO integration_connections (
			id, organization_id, provider, display_name, external_account_id, scopes, disabled_checks,
			encrypted_access_token, status, mode, created_at, updated_at
		)
		VALUES (
			$1, $2, 'SLACK'::"SaaSProvider", $3, $4, ARRAY[]::text[], ARRAY[]::text[],
			'test-token-envelope', 'CONNECTED'::"IntegrationStatus", 'REMEDIATION'::"IntegrationMode", NOW(), NOW()
		)
	`, integrationID, orgID, "MCP Slack "+suffix, "mcp-"+suffix+"-"+strings.ToLower(randomID())); err != nil {
		t.Fatalf("seed MCP integration: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO security_findings (
			id, organization_id, integration_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, evidence, detected_at
		)
		VALUES (
			$1, $2, $3, $4, 'Seeded MCP finding', 'Seeded for MCP proposal tests',
			'HIGH'::"Severity", 'OPEN'::"FindingStatus", 70, ARRAY['Review manually']::text[],
			$5::jsonb, NOW()
		)
	`, findingID, orgID, integrationID, "mcp-"+suffix+"-"+strings.ToLower(randomID()), string(evidenceJSON)); err != nil {
		t.Fatalf("seed MCP finding: %v", err)
	}
	return integrationID, findingID
}

func seedMCPCerebroIncident(t *testing.T, db *sql.DB, orgID string, findingID string, suffix string) string {
	t.Helper()
	incidentID := prefixedID("inc")
	contextJSON, err := json.Marshal(map[string]any{
		"source":          "cerebro",
		"mode":            "claim-fanout",
		"sourceRuntimeId": "writer-aperio-sspm",
		"findingContract": "cerebro.v1.Finding",
		"claimCount":      3,
		"entities": []map[string]any{
			{
				"urn":   cerebroIncidentResourceURI(orgID, findingID),
				"type":  "finding",
				"label": "Seeded MCP finding",
			},
		},
		"graphSignals": []map[string]any{
			{
				"label":      "Seeded Cerebro graph signal",
				"predicate":  "affects",
				"confidence": 0.91,
				"entityUrn":  cerebroIncidentResourceURI(orgID, findingID),
			},
		},
		"graphPaths": []map[string]any{
			{
				"id":    "path_" + suffix,
				"title": "Seeded graph path",
				"nodes": []map[string]any{
					{
						"urn":   cerebroIncidentResourceURI(orgID, findingID),
						"type":  "finding",
						"label": "Seeded MCP finding",
					},
				},
			},
		},
		"claimSummaries": []map[string]any{
			{
				"claimType":  "relation",
				"predicate":  "affects",
				"subjectUrn": cerebroIncidentResourceURI(orgID, findingID),
			},
		},
		"responseHints": []string{"Keep response human-gated."},
	})
	if err != nil {
		t.Fatalf("marshal Cerebro context: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO saas_incidents (
			id, organization_id, title, summary, severity, status, confidence_score,
			owner_team, first_detected_at, last_activity_at, sla_due_at, cerebro_context,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, 'Seeded for Cerebro MCP tests',
			'HIGH'::"Severity", 'INVESTIGATING'::"SaasIncidentStatus", 88,
			'SecOps', NOW() - INTERVAL '1 hour', NOW(), NOW() + INTERVAL '4 hours',
			$4::jsonb, NOW(), NOW()
		)
	`, incidentID, orgID, "Seeded Cerebro MCP incident "+suffix, string(contextJSON)); err != nil {
		t.Fatalf("seed Cerebro incident: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO saas_incident_findings (id, organization_id, incident_id, finding_id, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, prefixedID("iln"), orgID, incidentID, findingID); err != nil {
		t.Fatalf("seed Cerebro incident finding: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO saas_incident_timeline_events (
			id, organization_id, incident_id, finding_id, kind, title, description,
			actor, source, evidence, occurred_at, created_at
		)
		VALUES (
			$1, $2, $3, $4, 'CEREBRO_CONTEXT'::"SaasIncidentTimelineKind",
			'Cerebro context attached', 'Seeded Cerebro graph context.',
			'cerebro', 'CEREBRO', '{"source":"cerebro"}'::jsonb, NOW(), NOW()
		)
	`, prefixedID("tle"), orgID, incidentID, findingID); err != nil {
		t.Fatalf("seed Cerebro incident timeline: %v", err)
	}
	return incidentID
}

func newAuthenticatedTestToolService(t *testing.T, db *sql.DB) *ToolService {
	t.Helper()
	if strings.TrimSpace(os.Getenv("APERIO_MCP_SHARED_SECRET")) == "" {
		t.Setenv("APERIO_MCP_SHARED_SECRET", "test-mcp-secret-"+randomID())
	}
	return NewToolService(db)
}

func assertCerebroResponseAction(t *testing.T, db *sql.DB, orgID string, actionID string, incidentID string, findingID string) {
	t.Helper()
	var status, action, provider, targetType, targetIdentifier string
	var approvalRequired bool
	var result []byte
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, action::text, COALESCE(provider::text, ''), target_type,
		       target_identifier, approval_required, result
		FROM saas_response_actions
		WHERE organization_id = $1 AND id = $2 AND incident_id = $3 AND finding_id = $4
	`, orgID, actionID, incidentID, findingID).Scan(&status, &action, &provider, &targetType, &targetIdentifier, &approvalRequired, &result); err != nil {
		t.Fatalf("load Cerebro response action: %v", err)
	}
	if status != "PROPOSED" || action != "REVOKE_OAUTH_GRANT" || provider != "GOOGLE_WORKSPACE" ||
		targetType != "oauth_app" || targetIdentifier != "Vendor Analytics Add-on" || !approvalRequired {
		t.Fatalf("Cerebro response action drifted: status=%s action=%s provider=%s target=%s:%s approval=%v", status, action, provider, targetType, targetIdentifier, approvalRequired)
	}
	var payload map[string]any
	if err := json.Unmarshal(result, &payload); err != nil {
		t.Fatalf("decode response action result: %v", err)
	}
	if payload["source"] != "cerebro_mcp" || payload["mcpResourceUri"] != cerebroIncidentResourceURI(orgID, incidentID) {
		t.Fatalf("response action result provenance drifted: %#v", payload)
	}
	var timelineCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*)::int
		FROM saas_incident_timeline_events
		WHERE organization_id = $1
		  AND incident_id = $2
		  AND response_action_id = $3
		  AND source = 'CEREBRO_MCP'
	`, orgID, incidentID, actionID).Scan(&timelineCount); err != nil {
		t.Fatalf("count Cerebro MCP timeline: %v", err)
	}
	if timelineCount != 1 {
		t.Fatalf("Cerebro MCP timeline events = %d, want 1", timelineCount)
	}
}

func callMCPToolFrame(t *testing.T, service *ToolService, id string, name string, args map[string]any) map[string]any {
	t.Helper()
	args = withTestMCPAuth(service, args)
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, toolCall(id, name, args))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("tool call %s returned %d frames, want 1", id, len(frames))
	}
	result := frames[0]["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("tool call %s unexpectedly failed: %#v", id, result)
	}
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("tool call %s returned non-JSON content %q: %v", id, text, err)
	}
	return parsed
}

func callMCPResourceReadFrame(t *testing.T, service *ToolService, id string, uri string) (map[string]any, map[string]any) {
	t.Helper()
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, resourceRead(id, uri, service.sharedSecret))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("resource read %s returned %d frames, want 1", id, len(frames))
	}
	result := frames[0]["result"].(map[string]any)
	contents := result["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("resource read %s returned contents %#v, want one item", id, contents)
	}
	content := contents[0].(map[string]any)
	text, ok := content["text"].(string)
	if !ok || strings.TrimSpace(text) == "" {
		t.Fatalf("resource read %s returned empty text content: %#v", id, content)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("resource read %s returned non-JSON content %q: %v", id, text, err)
	}
	return parsed, content
}

func expectMCPToolErrorFrame(t *testing.T, service *ToolService, id string, name string, args map[string]any) []byte {
	t.Helper()
	args = withTestMCPAuth(service, args)
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, toolCall(id, name, args))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("tool call %s returned %d frames, want 1", id, len(frames))
	}
	result := frames[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("tool call %s succeeded, want MCP isError result: %#v", id, result)
	}
	content := result["content"].([]any)
	if text := content[0].(map[string]any)["text"].(string); strings.TrimSpace(text) == "" {
		t.Fatalf("tool call %s returned empty error text: %#v", id, result)
	}
	return stdout
}

func expectMCPResourceReadErrorFrame(t *testing.T, service *ToolService, id string, uri string, authToken ...string) []byte {
	t.Helper()
	stdout := runServer(t, NewServer(service), strings.NewReader(joinFrames(t, resourceRead(id, uri, authToken...))))
	frames := decodeOutputFrames(t, stdout)
	if len(frames) != 1 {
		t.Fatalf("resource read %s returned %d frames, want 1", id, len(frames))
	}
	errorFrame, ok := frames[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("resource read %s succeeded, want JSON-RPC error: %#v", id, frames[0])
	}
	if errorFrame["message"] == "" {
		t.Fatalf("resource read %s returned empty error message: %#v", id, errorFrame)
	}
	return stdout
}

func withTestMCPAuth(service *ToolService, args map[string]any) map[string]any {
	if service == nil || strings.TrimSpace(service.sharedSecret) == "" {
		return args
	}
	if _, ok := args["authToken"]; ok {
		return args
	}
	scoped := make(map[string]any, len(args)+1)
	for key, value := range args {
		scoped[key] = value
	}
	scoped["authToken"] = service.sharedSecret
	return scoped
}

func requireStringField(t *testing.T, values map[string]any, field string) string {
	t.Helper()
	value, ok := values[field].(string)
	if !ok || strings.TrimSpace(value) == "" {
		t.Fatalf("field %s = %#v, want non-empty string in %#v", field, values[field], values)
	}
	return value
}

func requireTaskList(t *testing.T, result map[string]any, want int) []map[string]any {
	t.Helper()
	raw, ok := result["tasks"].([]any)
	if !ok {
		t.Fatalf("tasks = %#v, want array", result["tasks"])
	}
	if len(raw) != want {
		t.Fatalf("tasks length = %d, want %d: %#v", len(raw), want, raw)
	}
	tasks := make([]map[string]any, len(raw))
	for index, item := range raw {
		task, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("tasks[%d] = %#v, want object", index, item)
		}
		tasks[index] = task
	}
	return tasks
}

func queryMCPInt(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatalf("query int: %v\n%s", err, query)
	}
	return count
}

func seedMCPSIEMDestination(t *testing.T, db *sql.DB, orgID string, stream string, status string, filePath string) string {
	t.Helper()
	destinationID := prefixedID("dst")
	name := "MCP " + stream + " " + strings.ToLower(randomID())
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO siem_destinations (
			id, organization_id, kind, name, file_path, streams, status, created_at, updated_at
		)
		VALUES (
			$1, $2, 'JSON_FILE'::"SiemKind", $3, $4,
			ARRAY[$5::"SiemStreamType"], $6::"SiemStatus", NOW(), NOW()
		)
	`, destinationID, orgID, name, nullableString(filePath), stream, status); err != nil {
		t.Fatalf("seed MCP SIEM destination: %v", err)
	}
	return destinationID
}

func requireMCPEnqueued(t *testing.T, result map[string]any, want int64) {
	t.Helper()
	value, ok := result["enqueued"]
	if !ok {
		t.Fatalf("SIEM enqueue result missing enqueued field: %#v", result)
	}
	var got int64
	switch typed := value.(type) {
	case float64:
		got = int64(typed)
	case int64:
		got = typed
	case int:
		got = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			t.Fatalf("enqueued field is not an integer: %#v", value)
		}
		got = parsed
	default:
		t.Fatalf("enqueued field has unexpected type %T: %#v", value, value)
	}
	if got != want {
		t.Fatalf("enqueued = %d, want %d in %#v", got, want, result)
	}
}

type mcpSIEMDelivery struct {
	ID             string
	OrganizationID string
	DestinationID  string
	Stream         string
	DedupeKey      string
	Status         string
	Attempts       int
	DeliveredAt    sql.NullTime
	Payload        siemdispatcher.Payload
}

func mcpSIEMDeliveries(t *testing.T, db *sql.DB, orgID string) []mcpSIEMDelivery {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
		SELECT id, organization_id, destination_id, stream::text, dedupe_key, status::text, attempts, delivered_at, payload
		FROM siem_deliveries
		WHERE organization_id = $1
		ORDER BY created_at, id
	`, orgID)
	if err != nil {
		t.Fatalf("query MCP SIEM deliveries: %v", err)
	}
	defer rows.Close()
	deliveries := []mcpSIEMDelivery{}
	for rows.Next() {
		var delivery mcpSIEMDelivery
		var rawPayload []byte
		if err := rows.Scan(
			&delivery.ID,
			&delivery.OrganizationID,
			&delivery.DestinationID,
			&delivery.Stream,
			&delivery.DedupeKey,
			&delivery.Status,
			&delivery.Attempts,
			&delivery.DeliveredAt,
			&rawPayload,
		); err != nil {
			t.Fatalf("scan MCP SIEM delivery: %v", err)
		}
		if err := json.Unmarshal(rawPayload, &delivery.Payload); err != nil {
			t.Fatalf("decode MCP SIEM delivery payload %q: %v", string(rawPayload), err)
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate MCP SIEM deliveries: %v", err)
	}
	return deliveries
}

func requireSingleMCPDelivery(t *testing.T, db *sql.DB, orgID string, destinationID string) mcpSIEMDelivery {
	t.Helper()
	deliveries := mcpSIEMDeliveries(t, db, orgID)
	matches := []mcpSIEMDelivery{}
	for _, delivery := range deliveries {
		if delivery.DestinationID == destinationID {
			matches = append(matches, delivery)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("delivery count for destination %s = %d, want 1 in %#v", destinationID, len(matches), deliveries)
	}
	return matches[0]
}

func mcpSIEMDestinationHealth(t *testing.T, db *sql.DB, orgID string, destinationID string) (string, int, int, sql.NullTime, sql.NullString) {
	t.Helper()
	var status string
	var deliveriesOK, deliveriesFail int
	var lastDeliveryAt sql.NullTime
	var lastError sql.NullString
	if err := db.QueryRowContext(context.Background(), `
		SELECT status::text, deliveries_ok, deliveries_fail, last_delivery_at, last_error
		FROM siem_destinations
		WHERE organization_id = $1 AND id = $2
	`, orgID, destinationID).Scan(&status, &deliveriesOK, &deliveriesFail, &lastDeliveryAt, &lastError); err != nil {
		t.Fatalf("query MCP SIEM destination health: %v", err)
	}
	return status, deliveriesOK, deliveriesFail, lastDeliveryAt, lastError
}

func assertAgentFields(t *testing.T, db *sql.DB, agentID string, wantName string, wantKind string, wantCapabilities []string, wantStatus string) {
	t.Helper()
	var name, kind, capabilitiesJSON, status string
	var endpointURL, mcpServerURL sql.NullString
	var hasLastSeen bool
	if err := db.QueryRowContext(context.Background(), `
		SELECT name, kind::text, to_json(capabilities)::text, endpoint_url, mcp_server_url, status::text, last_seen_at IS NOT NULL
		FROM agents
		WHERE id = $1
	`, agentID).Scan(&name, &kind, &capabilitiesJSON, &endpointURL, &mcpServerURL, &status, &hasLastSeen); err != nil {
		t.Fatalf("query agent fields: %v", err)
	}
	var capabilities []string
	if err := json.Unmarshal([]byte(capabilitiesJSON), &capabilities); err != nil {
		t.Fatalf("decode capabilities %q: %v", capabilitiesJSON, err)
	}
	if name != wantName || kind != wantKind || status != wantStatus || !hasLastSeen {
		t.Fatalf("agent fields drifted: name=%s kind=%s status=%s hasLastSeen=%v", name, kind, status, hasLastSeen)
	}
	if strings.Join(capabilities, ",") != strings.Join(wantCapabilities, ",") {
		t.Fatalf("capabilities = %#v, want %#v", capabilities, wantCapabilities)
	}
	if endpointURL.String != "https://agents.example.test/scanner" || mcpServerURL.String != "https://agents.example.test/mcp" {
		t.Fatalf("agent URLs drifted: endpoint=%#v mcp=%#v", endpointURL, mcpServerURL)
	}
}

func assertTaskReferences(t *testing.T, db *sql.DB, taskID string, orgID string, createdByAgentID string, assignedAgentID string, parentTaskID string) {
	t.Helper()
	var gotOrgID, status, gotCreatedBy, gotAssigned, gotParent, inputJSON string
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, status::text, created_by_agent_id, assigned_agent_id, parent_task_id, input::text
		FROM agent_tasks
		WHERE id = $1
	`, taskID).Scan(&gotOrgID, &status, &gotCreatedBy, &gotAssigned, &gotParent, &inputJSON); err != nil {
		t.Fatalf("query task references: %v", err)
	}
	if gotOrgID != orgID || status != "QUEUED" || gotCreatedBy != createdByAgentID || gotAssigned != assignedAgentID || gotParent != parentTaskID {
		t.Fatalf("task references drifted: org=%s status=%s created=%s assigned=%s parent=%s", gotOrgID, status, gotCreatedBy, gotAssigned, gotParent)
	}
	if !strings.Contains(inputJSON, `"phase": "child"`) && !strings.Contains(inputJSON, `"phase":"child"`) {
		t.Fatalf("task input not persisted as JSON object: %s", inputJSON)
	}
}

func assertMessageReferences(t *testing.T, db *sql.DB, messageID string, orgID string, taskID string, fromAgentID string, toAgentID string) {
	t.Helper()
	var gotOrgID, gotTaskID, gotFromAgentID, gotToAgentID, role, messageType, correlationID, contentJSON string
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, task_id, from_agent_id, to_agent_id, role::text, message_type, correlation_id, content::text
		FROM agent_messages
		WHERE id = $1
	`, messageID).Scan(&gotOrgID, &gotTaskID, &gotFromAgentID, &gotToAgentID, &role, &messageType, &correlationID, &contentJSON); err != nil {
		t.Fatalf("query message references: %v", err)
	}
	if gotOrgID != orgID || gotTaskID != taskID || gotFromAgentID != fromAgentID || gotToAgentID != toAgentID || role != "AGENT" || messageType != "a2a.message.v1" || correlationID != "corr-1" {
		t.Fatalf("message fields drifted: org=%s task=%s from=%s to=%s role=%s type=%s corr=%s", gotOrgID, gotTaskID, gotFromAgentID, gotToAgentID, role, messageType, correlationID)
	}
	if !strings.Contains(contentJSON, `"body": "ready"`) && !strings.Contains(contentJSON, `"body":"ready"`) {
		t.Fatalf("message content not persisted as JSON object: %s", contentJSON)
	}
}

func assertTaskResultShape(t *testing.T, task map[string]any, taskID string, orgID string, taskType string, title string, status string, createdByKey string, assignedKey string, parentTaskID string) {
	t.Helper()
	wantKeys := []string{
		"assignedAgent", "assignedAgentId", "completedAt", "createdAt", "createdByAgent", "createdByAgentId",
		"error", "id", "input", "leaseExpiresAt", "organizationId", "output", "parentTaskId", "startedAt",
		"status", "taskType", "title", "updatedAt",
	}
	for _, key := range wantKeys {
		if _, ok := task[key]; !ok {
			t.Fatalf("task result missing key %s: %#v", key, task)
		}
	}
	if len(task) != len(wantKeys) {
		t.Fatalf("task result has unexpected keys: %#v", task)
	}
	if task["id"] != taskID || task["organizationId"] != orgID || task["taskType"] != taskType || task["title"] != title || task["status"] != status || task["parentTaskId"] != parentTaskID {
		t.Fatalf("task scalar fields drifted: %#v", task)
	}
	createdBy := task["createdByAgent"].(map[string]any)
	assigned := task["assignedAgent"].(map[string]any)
	if createdBy["key"] != createdByKey || assigned["key"] != assignedKey {
		t.Fatalf("task agent summaries drifted: created=%#v assigned=%#v", createdBy, assigned)
	}
}

func assertProposalHumanGated(t *testing.T, db *sql.DB, proposalID string, orgID string, taskID string, findingID string, agentID string) {
	t.Helper()
	var gotOrgID, gotTaskID, gotFindingID, proposedByAgentID, action, status, payloadJSON string
	var approvedBy sql.NullString
	var approvedAt, executedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(), `
		SELECT organization_id, task_id, finding_id, proposed_by_agent_id, action, status::text,
		       approved_by_user_id, approved_at, executed_at, payload::text
		FROM agent_proposals
		WHERE id = $1
	`, proposalID).Scan(&gotOrgID, &gotTaskID, &gotFindingID, &proposedByAgentID, &action, &status, &approvedBy, &approvedAt, &executedAt, &payloadJSON); err != nil {
		t.Fatalf("query proposal: %v", err)
	}
	if gotOrgID != orgID || gotTaskID != taskID || gotFindingID != findingID || proposedByAgentID != agentID || action != "slack.revoke_app_install" || status != "PROPOSED" {
		t.Fatalf("proposal fields drifted: org=%s task=%s finding=%s proposedBy=%s action=%s status=%s", gotOrgID, gotTaskID, gotFindingID, proposedByAgentID, action, status)
	}
	if approvedBy.Valid || approvedAt.Valid || executedAt.Valid {
		t.Fatalf("proposal was not human-gated: approvedBy=%#v approvedAt=%#v executedAt=%#v", approvedBy, approvedAt, executedAt)
	}
	if !strings.Contains(payloadJSON, `"appId": "A123"`) && !strings.Contains(payloadJSON, `"appId":"A123"`) {
		t.Fatalf("proposal payload not persisted correctly: %s", payloadJSON)
	}
}

func assertMCPISOTime(t *testing.T, value any) {
	t.Helper()
	text, ok := value.(string)
	if !ok {
		t.Fatalf("timestamp = %#v, want string", value)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`).MatchString(text) {
		t.Fatalf("timestamp %q does not match JavaScript ISO millisecond shape", text)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", text); err != nil {
		t.Fatalf("timestamp %q is not parseable: %v", text, err)
	}
}

func assertMCPSecretNotPersisted(t *testing.T, db *sql.DB, orgID string, secret string) {
	t.Helper()
	var matches int
	if err := db.QueryRowContext(context.Background(), `
		SELECT
			(SELECT COUNT(*) FROM agents
			 WHERE organization_id = $1
			   AND (
			     strpos(key, $2) > 0 OR strpos(name, $2) > 0 OR
			     strpos(COALESCE(array_to_string(capabilities, E'\n'), ''), $2) > 0 OR
			     strpos(COALESCE(endpoint_url, ''), $2) > 0 OR
			     strpos(COALESCE(mcp_server_url, ''), $2) > 0
			   )) +
			(SELECT COUNT(*) FROM agent_tasks
			 WHERE organization_id = $1
			   AND (
			     strpos(input::text, $2) > 0 OR strpos(COALESCE(output::text, ''), $2) > 0 OR
			     strpos(COALESCE(error, ''), $2) > 0
			   )) +
			(SELECT COUNT(*) FROM agent_messages
			 WHERE organization_id = $1 AND strpos(content::text, $2) > 0) +
			(SELECT COUNT(*) FROM agent_proposals
			 WHERE organization_id = $1
			   AND (
			     strpos(action, $2) > 0 OR strpos(rationale, $2) > 0 OR strpos(payload::text, $2) > 0
			   )) +
			(SELECT COUNT(*) FROM siem_deliveries
			 WHERE organization_id = $1 AND strpos(payload::text, $2) > 0)
	`, orgID, secret).Scan(&matches); err != nil {
		t.Fatalf("scan MCP side-effect tables for shared secret: %v", err)
	}
	if matches != 0 {
		t.Fatalf("shared secret appeared in %d MCP side-effect rows", matches)
	}
}
