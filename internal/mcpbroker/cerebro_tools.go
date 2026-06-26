package mcpbroker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	cerebroIncidentMimeType         = "application/vnd.aperio.cerebro.incident+json"
	cerebroFindingMimeType          = "application/vnd.aperio.cerebro.finding+json"
	cerebroSecurityOverviewMimeType = "application/vnd.aperio.cerebro.security-overview+json"
)

type cerebroResponseCapability struct {
	Action              string
	Provider            string
	ProviderAction      string
	TargetTypes         []string
	RequiredContextKeys []string
	Mode                string
	DryRun              bool
	ApprovalRequired    bool
	ExternalOwner       string
	Effect              string
	Rollback            string
}

var cerebroResponseCapabilityCatalog = []cerebroResponseCapability{
	{
		Action:              "REVOKE_OAUTH_GRANT",
		Provider:            "GOOGLE_WORKSPACE",
		ProviderAction:      "google_workspace.revoke_oauth_grant",
		TargetTypes:         []string{"oauth_grant", "oauth_app"},
		RequiredContextKeys: []string{"oauth_grant_id", "oauth_app_id", "oauth_user_email"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Revokes a risky Google Workspace OAuth grant after approval.",
		Rollback:            "The user must re-authorize the app if access is later approved.",
	},
	{
		Action:              "QUARANTINE_APP",
		Provider:            "SLACK",
		ProviderAction:      "slack.revoke_app_install",
		TargetTypes:         []string{"oauth_app", "slack_app"},
		RequiredContextKeys: []string{"oauth_app_id", "slack_app_id", "workspace_id"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Removes or blocks a risky Slack app installation after approval.",
		Rollback:            "Workspace admins can reinstall the app if the risk is accepted.",
	},
	{
		Action:              "QUARANTINE_APP",
		Provider:            "GITHUB",
		ProviderAction:      "github.revoke_oauth_app",
		TargetTypes:         []string{"oauth_app", "github_oauth_app"},
		RequiredContextKeys: []string{"oauth_app_id", "github_org", "github_user"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Revokes or blocks a risky GitHub OAuth app after approval.",
		Rollback:            "The app must be re-approved or re-installed if access is restored.",
	},
	{
		Action:              "REVOKE_SESSION",
		Provider:            "MICROSOFT_365",
		ProviderAction:      "microsoft_365.revoke_sessions",
		TargetTypes:         []string{"user", "identity"},
		RequiredContextKeys: []string{"user_id", "user_principal_name"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Invalidates Microsoft 365 sessions for a risky user after approval.",
		Rollback:            "The user signs in again after MFA or admin review.",
	},
	{
		Action:              "SUSPEND_USER",
		Provider:            "OKTA",
		ProviderAction:      "okta.suspend_user",
		TargetTypes:         []string{"user", "identity"},
		RequiredContextKeys: []string{"okta_user_id", "user_email"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Suspends a risky Okta user after approval.",
		Rollback:            "Identity admins can unsuspend the user after investigation.",
	},
	{
		Action:              "REMOVE_EXTERNAL_SHARE",
		Provider:            "ATLASSIAN",
		ProviderAction:      "atlassian.revoke_user_access",
		TargetTypes:         []string{"user", "group", "project"},
		RequiredContextKeys: []string{"atlassian_account_id", "resource_id"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Revokes risky external Atlassian access after approval.",
		Rollback:            "Project or site admins can restore access after review.",
	},
	{
		Action:              "REMOVE_ADMIN_ROLE",
		Provider:            "SALESFORCE",
		ProviderAction:      "salesforce.remove_admin_role",
		TargetTypes:         []string{"user", "permission_set", "profile"},
		RequiredContextKeys: []string{"salesforce_user_id", "permission_set_id"},
		Mode:                "aperio_human_gated",
		DryRun:              true,
		ApprovalRequired:    true,
		ExternalOwner:       "aperio",
		Effect:              "Removes excessive Salesforce admin entitlement after approval.",
		Rollback:            "Salesforce admins can restore the role or permission set.",
	},
	{
		Action:              "OPEN_TICKET",
		Provider:            "",
		ProviderAction:      "ticket.open",
		TargetTypes:         []string{"incident", "finding"},
		RequiredContextKeys: []string{"incident_id", "finding_id"},
		Mode:                "aperio_workflow",
		DryRun:              false,
		ApprovalRequired:    false,
		ExternalOwner:       "aperio",
		Effect:              "Opens a tracked workflow item with linked Cerebro context.",
		Rollback:            "The ticket can be closed without provider-side changes.",
	},
	{
		Action:              "NOTIFY_SECOPS",
		Provider:            "",
		ProviderAction:      "secops.notify",
		TargetTypes:         []string{"incident", "finding", "user", "oauth_app"},
		RequiredContextKeys: []string{"incident_id", "severity"},
		Mode:                "aperio_workflow",
		DryRun:              false,
		ApprovalRequired:    false,
		ExternalOwner:       "aperio",
		Effect:              "Sends a SecOps notification with linked Cerebro and Aperio context.",
		Rollback:            "No provider-side rollback is required.",
	},
}

type cerebroIncidentRow struct {
	ID                  string
	Title               string
	Summary             string
	Severity            string
	Status              string
	ConfidenceScore     int
	OwnerTeam           string
	FirstDetectedAt     time.Time
	LastActivityAt      time.Time
	SLADueAt            sql.NullTime
	ResolvedAt          sql.NullTime
	CerebroContextJSON  []byte
	FindingCount        int
	ResponseActionCount int
}

type cerebroFindingRow struct {
	ID                  string
	AssetID             string
	Title               string
	Description         string
	Severity            string
	Status              string
	RiskScore           int
	RemediationJSON     string
	TagsJSON            string
	EvidenceJSON        string
	DetectedAt          time.Time
	ResolvedAt          sql.NullTime
	IntegrationID       string
	Provider            string
	IntegrationName     string
	IncidentCount       int
	ResponseActionCount int
}

func (s *ToolService) listCerebroIncidents(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	status := stringValue(input["status"])
	severity := stringValue(input["severity"])
	limit := input["limit"].(int)
	rows, err := s.db.QueryContext(ctx, `
		WITH finding_counts AS (
			SELECT incident_id, COUNT(*)::int AS finding_count
			FROM saas_incident_findings
			WHERE organization_id = $1
			GROUP BY incident_id
		),
		action_counts AS (
			SELECT incident_id, COUNT(*)::int AS response_action_count
			FROM saas_response_actions
			WHERE organization_id = $1
			GROUP BY incident_id
		)
		SELECT
			si.id,
			si.title,
			si.summary,
			si.severity::text,
			si.status::text,
			si.confidence_score,
			COALESCE(si.owner_team, ''),
			si.first_detected_at,
			si.last_activity_at,
			si.sla_due_at,
			si.resolved_at,
			si.cerebro_context,
			COALESCE(fc.finding_count, 0),
			COALESCE(ac.response_action_count, 0)
		FROM saas_incidents si
		LEFT JOIN finding_counts fc ON fc.incident_id = si.id
		LEFT JOIN action_counts ac ON ac.incident_id = si.id
		WHERE si.organization_id = $1
		  AND ($2 = '' OR $2 = 'ALL' OR si.status = $2::"SaasIncidentStatus")
		  AND ($3 = '' OR si.severity = $3::"Severity")
		ORDER BY si.last_activity_at DESC, si.id DESC
		LIMIT $4
	`, organizationID, status, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	incidents := []map[string]any{}
	for rows.Next() {
		row, err := scanCerebroIncidentRow(rows)
		if err != nil {
			return nil, err
		}
		context := decodeJSON(row.CerebroContextJSON)
		incidents = append(incidents, map[string]any{
			"id":                  row.ID,
			"title":               row.Title,
			"summary":             row.Summary,
			"severity":            row.Severity,
			"status":              row.Status,
			"confidenceScore":     row.ConfidenceScore,
			"ownerTeam":           nullableText(row.OwnerTeam),
			"firstDetectedAt":     formatMCPTime(row.FirstDetectedAt),
			"lastActivityAt":      formatMCPTime(row.LastActivityAt),
			"slaDueAt":            nullableTime(row.SLADueAt),
			"resolvedAt":          nullableTime(row.ResolvedAt),
			"findingCount":        row.FindingCount,
			"responseActionCount": row.ResponseActionCount,
			"cerebro":             cerebroSummary(context),
			"resource":            cerebroIncidentResource(organizationID, row),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{
		"server":    ServerName,
		"resources": incidents,
		"tools":     cerebroMCPToolNames(),
	}, nil
}

func (s *ToolService) listCerebroFindings(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	status := stringValue(input["status"])
	severity := stringValue(input["severity"])
	provider := stringValue(input["provider"])
	limit := input["limit"].(int)
	rows, err := s.db.QueryContext(ctx, `
		WITH incident_counts AS (
			SELECT finding_id, COUNT(*)::int AS incident_count
			FROM saas_incident_findings
			WHERE organization_id = $1
			GROUP BY finding_id
		),
		action_counts AS (
			SELECT finding_id, COUNT(*)::int AS response_action_count
			FROM saas_response_actions
			WHERE organization_id = $1 AND finding_id IS NOT NULL
			GROUP BY finding_id
		)
		SELECT
			sf.id,
			COALESCE(sf.asset_id, ''),
			sf.title,
			sf.description,
			sf.severity::text,
			sf.status::text,
			sf.risk_score,
			COALESCE(to_json(sf.remediation_steps)::text, '[]'),
			COALESCE(to_json(sf.tags)::text, '[]'),
			sf.evidence::text,
			sf.detected_at,
			sf.resolved_at,
			ic.id,
			ic.provider::text,
			ic.display_name,
			COALESCE(icount.incident_count, 0),
			COALESCE(ac.response_action_count, 0)
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id AND ic.organization_id = sf.organization_id
		LEFT JOIN incident_counts icount ON icount.finding_id = sf.id
		LEFT JOIN action_counts ac ON ac.finding_id = sf.id
		WHERE sf.organization_id = $1
		  AND ($2 = '' OR $2 = 'ALL' OR sf.status = $2::"FindingStatus")
		  AND ($3 = '' OR sf.severity = $3::"Severity")
		  AND ($4 = '' OR ic.provider = $4::"SaaSProvider")
		ORDER BY sf.detected_at DESC, sf.id DESC
		LIMIT $5
	`, organizationID, status, severity, provider, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := []map[string]any{}
	for rows.Next() {
		row, err := scanCerebroFindingRow(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, row.toSummary(organizationID))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return map[string]any{
		"server":    ServerName,
		"resources": findings,
		"tools":     cerebroMCPToolNames(),
	}, nil
}

func (s *ToolService) getCerebroIncidentContext(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	incidentID := stringValue(input["incidentId"])
	incident, err := s.loadCerebroIncident(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	findings, err := s.listCerebroIncidentFindings(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	timeline, err := s.listCerebroIncidentTimeline(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	actions, err := s.listCerebroResponseActions(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	context := decodeJSON(incident.CerebroContextJSON)
	return map[string]any{
		"server":               ServerName,
		"resource":             cerebroIncidentResource(organizationID, incident),
		"responseCapabilities": cerebroResponseCapabilitiesForFindings(findings),
		"incident": map[string]any{
			"id":                  incident.ID,
			"title":               incident.Title,
			"summary":             incident.Summary,
			"severity":            incident.Severity,
			"status":              incident.Status,
			"confidenceScore":     incident.ConfidenceScore,
			"ownerTeam":           nullableText(incident.OwnerTeam),
			"firstDetectedAt":     formatMCPTime(incident.FirstDetectedAt),
			"lastActivityAt":      formatMCPTime(incident.LastActivityAt),
			"slaDueAt":            nullableTime(incident.SLADueAt),
			"resolvedAt":          nullableTime(incident.ResolvedAt),
			"findingCount":        incident.FindingCount,
			"responseActionCount": incident.ResponseActionCount,
			"cerebroContext":      context,
		},
		"findings":        findings,
		"timeline":        timeline,
		"responseActions": actions,
		"mcp": map[string]any{
			"resourceUri":       cerebroIncidentResourceURI(organizationID, incident.ID),
			"mimeType":          cerebroIncidentMimeType,
			"tools":             cerebroMCPToolNames(),
			"resourceTemplates": ApprovedResourceTemplates(),
		},
	}, nil
}

func (s *ToolService) getCerebroFindingContext(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	findingID := stringValue(input["findingId"])
	finding, err := s.loadCerebroFinding(ctx, organizationID, findingID)
	if err != nil {
		return nil, err
	}
	incidents, err := s.listCerebroFindingIncidents(ctx, organizationID, findingID)
	if err != nil {
		return nil, err
	}
	actions, err := s.listCerebroFindingResponseActions(ctx, organizationID, findingID)
	if err != nil {
		return nil, err
	}
	evidence := decodeJSON([]byte(finding.EvidenceJSON))
	return map[string]any{
		"server":               ServerName,
		"resource":             cerebroFindingResource(organizationID, finding),
		"finding":              finding.toDetail(organizationID),
		"incidents":            incidents,
		"responseActions":      actions,
		"responseCapabilities": cerebroResponseCapabilitiesForFinding(finding.Provider, evidence),
		"mcp": map[string]any{
			"resourceUri":       cerebroFindingResourceURI(organizationID, finding.ID),
			"mimeType":          cerebroFindingMimeType,
			"tools":             cerebroMCPToolNames(),
			"resourceTemplates": ApprovedResourceTemplates(),
		},
	}, nil
}

func (s *ToolService) proposeCerebroResponse(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	incidentID := stringValue(input["incidentId"])
	findingID := stringValue(input["findingId"])
	taskID, err := s.ensureTaskID(ctx, organizationID, stringValue(input["taskId"]))
	if err != nil {
		return nil, err
	}
	proposedByAgentID, err := s.getAgentID(ctx, organizationID, stringValue(input["proposedByAgentKey"]))
	if err != nil {
		return nil, err
	}
	if _, err := s.loadCerebroIncident(ctx, organizationID, incidentID); err != nil {
		return nil, err
	}
	if findingID != "" {
		if err := s.ensureIncidentFinding(ctx, organizationID, incidentID, findingID); err != nil {
			return nil, err
		}
	}

	actionID := prefixedID("act")
	now := s.currentTime()
	provider := stringValue(input["provider"])
	approvalRequired := input["approvalRequired"].(bool)
	dryRun := input["dryRun"].(bool)
	actionContract := cerebroResponseActionContract(stringValue(input["action"]), provider)
	proposalContext := map[string]any{
		"source":              "cerebro_mcp",
		"taskId":              nullableText(taskID),
		"proposedByAgentId":   nullableText(proposedByAgentID),
		"mcpResourceUri":      cerebroIncidentResourceURI(organizationID, incidentID),
		"requiresHumanReview": approvalRequired,
		"dryRun":              dryRun,
		"actionContract":      actionContract,
	}
	resultJSON, err := json.Marshal(proposalContext)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO saas_response_actions (
			id, organization_id, incident_id, finding_id, action, provider, target_type,
			target_identifier, status, approval_required, rationale, result, created_at, updated_at
		)
		VALUES ($1,$2,$3,NULLIF($4,''),$5::"SaasResponseActionKind",NULLIF($6,'')::"SaaSProvider",$7,$8,'PROPOSED',$9,$10,$11::jsonb,$12,$12)
	`, actionID, organizationID, incidentID, findingID, input["action"], provider, input["targetType"], input["targetIdentifier"], approvalRequired, input["rationale"], string(resultJSON), now); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE saas_incidents
		SET last_activity_at = $3, updated_at = $3
		WHERE organization_id = $1 AND id = $2
	`, organizationID, incidentID, now); err != nil {
		return nil, err
	}
	actor := stringValue(input["proposedByAgentKey"])
	if actor == "" {
		actor = "cerebro-mcp"
	}
	evidenceJSON, err := json.Marshal(proposalContext)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO saas_incident_timeline_events (
			id, organization_id, incident_id, finding_id, response_action_id, kind,
			title, description, actor, source, evidence, occurred_at, created_at
		)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,'RESPONSE_ACTION','Cerebro MCP response proposed',$6,$7,'CEREBRO_MCP',$8::jsonb,$9,$9)
	`, prefixedID("tle"), organizationID, incidentID, findingID, actionID, fmt.Sprintf("%s proposed for %s.", input["action"], input["targetIdentifier"]), actor, string(evidenceJSON), now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{
		"responseActionId": actionID,
		"incidentId":       incidentID,
		"status":           "PROPOSED",
		"approvalRequired": approvalRequired,
		"dryRun":           dryRun,
		"actionContract":   actionContract,
		"resourceUri":      cerebroIncidentResourceURI(organizationID, incidentID),
	}, nil
}

func (s *ToolService) loadCerebroIncident(ctx context.Context, organizationID string, incidentID string) (cerebroIncidentRow, error) {
	row := s.db.QueryRowContext(ctx, `
		WITH finding_counts AS (
			SELECT incident_id, COUNT(*)::int AS finding_count
			FROM saas_incident_findings
			WHERE organization_id = $1
			GROUP BY incident_id
		),
		action_counts AS (
			SELECT incident_id, COUNT(*)::int AS response_action_count
			FROM saas_response_actions
			WHERE organization_id = $1
			GROUP BY incident_id
		)
		SELECT
			si.id,
			si.title,
			si.summary,
			si.severity::text,
			si.status::text,
			si.confidence_score,
			COALESCE(si.owner_team, ''),
			si.first_detected_at,
			si.last_activity_at,
			si.sla_due_at,
			si.resolved_at,
			si.cerebro_context,
			COALESCE(fc.finding_count, 0),
			COALESCE(ac.response_action_count, 0)
		FROM saas_incidents si
		LEFT JOIN finding_counts fc ON fc.incident_id = si.id
		LEFT JOIN action_counts ac ON ac.incident_id = si.id
		WHERE si.organization_id = $1 AND si.id = $2
	`, organizationID, incidentID)
	incident, err := scanCerebroIncidentRow(row)
	if err == sql.ErrNoRows {
		return cerebroIncidentRow{}, fmt.Errorf("Cerebro incident not found: %s", incidentID)
	}
	return incident, err
}

func (s *ToolService) loadCerebroFinding(ctx context.Context, organizationID string, findingID string) (cerebroFindingRow, error) {
	row := s.db.QueryRowContext(ctx, `
		WITH incident_counts AS (
			SELECT finding_id, COUNT(*)::int AS incident_count
			FROM saas_incident_findings
			WHERE organization_id = $1
			GROUP BY finding_id
		),
		action_counts AS (
			SELECT finding_id, COUNT(*)::int AS response_action_count
			FROM saas_response_actions
			WHERE organization_id = $1 AND finding_id IS NOT NULL
			GROUP BY finding_id
		)
		SELECT
			sf.id,
			COALESCE(sf.asset_id, ''),
			sf.title,
			sf.description,
			sf.severity::text,
			sf.status::text,
			sf.risk_score,
			COALESCE(to_json(sf.remediation_steps)::text, '[]'),
			COALESCE(to_json(sf.tags)::text, '[]'),
			sf.evidence::text,
			sf.detected_at,
			sf.resolved_at,
			ic.id,
			ic.provider::text,
			ic.display_name,
			COALESCE(icount.incident_count, 0),
			COALESCE(ac.response_action_count, 0)
		FROM security_findings sf
		JOIN integration_connections ic ON ic.id = sf.integration_id AND ic.organization_id = sf.organization_id
		LEFT JOIN incident_counts icount ON icount.finding_id = sf.id
		LEFT JOIN action_counts ac ON ac.finding_id = sf.id
		WHERE sf.organization_id = $1 AND sf.id = $2
	`, organizationID, findingID)
	finding, err := scanCerebroFindingRow(row)
	if err == sql.ErrNoRows {
		return cerebroFindingRow{}, fmt.Errorf("Cerebro finding not found: %s", findingID)
	}
	return finding, err
}

func scanCerebroIncidentRow(scanner interface{ Scan(...any) error }) (cerebroIncidentRow, error) {
	var row cerebroIncidentRow
	err := scanner.Scan(
		&row.ID,
		&row.Title,
		&row.Summary,
		&row.Severity,
		&row.Status,
		&row.ConfidenceScore,
		&row.OwnerTeam,
		&row.FirstDetectedAt,
		&row.LastActivityAt,
		&row.SLADueAt,
		&row.ResolvedAt,
		&row.CerebroContextJSON,
		&row.FindingCount,
		&row.ResponseActionCount,
	)
	return row, err
}

func scanCerebroFindingRow(scanner interface{ Scan(...any) error }) (cerebroFindingRow, error) {
	var row cerebroFindingRow
	err := scanner.Scan(
		&row.ID,
		&row.AssetID,
		&row.Title,
		&row.Description,
		&row.Severity,
		&row.Status,
		&row.RiskScore,
		&row.RemediationJSON,
		&row.TagsJSON,
		&row.EvidenceJSON,
		&row.DetectedAt,
		&row.ResolvedAt,
		&row.IntegrationID,
		&row.Provider,
		&row.IntegrationName,
		&row.IncidentCount,
		&row.ResponseActionCount,
	)
	return row, err
}

func (s *ToolService) listCerebroIncidentFindings(ctx context.Context, organizationID string, incidentID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sf.id, sf.title, sf.description, sf.severity::text, sf.status::text, sf.risk_score,
		       sf.evidence, sf.detected_at, ic.provider::text, ic.display_name
		FROM saas_incident_findings sif
		JOIN security_findings sf ON sf.id = sif.finding_id AND sf.organization_id = sif.organization_id
		JOIN integration_connections ic ON ic.id = sf.integration_id AND ic.organization_id = sf.organization_id
		WHERE sif.organization_id = $1 AND sif.incident_id = $2
		ORDER BY sf.detected_at DESC, sf.id DESC
	`, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, title, description, severity, status, provider, integrationName string
		var riskScore int
		var evidence []byte
		var detectedAt time.Time
		if err := rows.Scan(&id, &title, &description, &severity, &status, &riskScore, &evidence, &detectedAt, &provider, &integrationName); err != nil {
			return nil, err
		}
		decodedEvidence := decodeJSON(evidence)
		record := map[string]any{
			"id":              id,
			"title":           title,
			"description":     description,
			"severity":        severity,
			"status":          status,
			"riskScore":       riskScore,
			"evidence":        decodedEvidence,
			"detectedAt":      formatMCPTime(detectedAt),
			"provider":        provider,
			"integrationName": integrationName,
			"responseCapabilities": cerebroResponseCapabilitiesForFinding(
				provider,
				decodedEvidence,
			),
		}
		if exposure := cerebroOAuthExposure(provider, decodedEvidence); len(exposure) > 0 {
			record["oauthExposure"] = exposure
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *ToolService) listCerebroFindingIncidents(ctx context.Context, organizationID string, findingID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH finding_counts AS (
			SELECT incident_id, COUNT(*)::int AS finding_count
			FROM saas_incident_findings
			WHERE organization_id = $1
			GROUP BY incident_id
		),
		action_counts AS (
			SELECT incident_id, COUNT(*)::int AS response_action_count
			FROM saas_response_actions
			WHERE organization_id = $1
			GROUP BY incident_id
		)
		SELECT
			si.id,
			si.title,
			si.summary,
			si.severity::text,
			si.status::text,
			si.confidence_score,
			COALESCE(si.owner_team, ''),
			si.first_detected_at,
			si.last_activity_at,
			si.sla_due_at,
			si.resolved_at,
			si.cerebro_context,
			COALESCE(fc.finding_count, 0),
			COALESCE(ac.response_action_count, 0)
		FROM saas_incident_findings sif
		JOIN saas_incidents si ON si.id = sif.incident_id AND si.organization_id = sif.organization_id
		LEFT JOIN finding_counts fc ON fc.incident_id = si.id
		LEFT JOIN action_counts ac ON ac.incident_id = si.id
		WHERE sif.organization_id = $1 AND sif.finding_id = $2
		ORDER BY si.last_activity_at DESC, si.id DESC
	`, organizationID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		row, err := scanCerebroIncidentRow(rows)
		if err != nil {
			return nil, err
		}
		context := decodeJSON(row.CerebroContextJSON)
		out = append(out, map[string]any{
			"id":                  row.ID,
			"title":               row.Title,
			"summary":             row.Summary,
			"severity":            row.Severity,
			"status":              row.Status,
			"confidenceScore":     row.ConfidenceScore,
			"ownerTeam":           nullableText(row.OwnerTeam),
			"firstDetectedAt":     formatMCPTime(row.FirstDetectedAt),
			"lastActivityAt":      formatMCPTime(row.LastActivityAt),
			"slaDueAt":            nullableTime(row.SLADueAt),
			"resolvedAt":          nullableTime(row.ResolvedAt),
			"findingCount":        row.FindingCount,
			"responseActionCount": row.ResponseActionCount,
			"cerebro":             cerebroSummary(context),
			"resource":            cerebroIncidentResource(organizationID, row),
		})
	}
	return out, rows.Err()
}

func (s *ToolService) listCerebroIncidentTimeline(ctx context.Context, organizationID string, incidentID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(finding_id, ''), COALESCE(response_action_id, ''), kind::text,
		       title, description, COALESCE(actor, ''), source, evidence, occurred_at
		FROM saas_incident_timeline_events
		WHERE organization_id = $1 AND incident_id = $2
		ORDER BY occurred_at ASC, id ASC
	`, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, findingID, responseActionID, kind, title, description, actor, source string
		var evidence []byte
		var occurredAt time.Time
		if err := rows.Scan(&id, &findingID, &responseActionID, &kind, &title, &description, &actor, &source, &evidence, &occurredAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":               id,
			"findingId":        nullableText(findingID),
			"responseActionId": nullableText(responseActionID),
			"kind":             kind,
			"title":            title,
			"description":      description,
			"actor":            nullableText(actor),
			"source":           source,
			"evidence":         decodeJSON(evidence),
			"occurredAt":       formatMCPTime(occurredAt),
		})
	}
	return out, rows.Err()
}

func (s *ToolService) listCerebroFindingResponseActions(ctx context.Context, organizationID string, findingID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, incident_id, action::text, COALESCE(provider::text, ''),
		       target_type, target_identifier, status::text, approval_required, rationale,
		       approved_at, executed_at, COALESCE(error_message, ''), result, created_at
		FROM saas_response_actions
		WHERE organization_id = $1 AND finding_id = $2
		ORDER BY created_at DESC, id DESC
	`, organizationID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, incidentID, action, provider, targetType, targetIdentifier, status, rationale, errorMessage string
		var approvalRequired bool
		var approvedAt, executedAt sql.NullTime
		var result []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &incidentID, &action, &provider, &targetType, &targetIdentifier, &status, &approvalRequired, &rationale, &approvedAt, &executedAt, &errorMessage, &result, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":               id,
			"incidentId":       incidentID,
			"action":           action,
			"provider":         nullableText(provider),
			"targetType":       targetType,
			"targetIdentifier": targetIdentifier,
			"status":           status,
			"approvalRequired": approvalRequired,
			"rationale":        rationale,
			"approvedAt":       nullableTime(approvedAt),
			"executedAt":       nullableTime(executedAt),
			"errorMessage":     nullableText(errorMessage),
			"result":           decodeJSON(result),
			"actionContract":   cerebroResponseActionContract(action, provider),
			"createdAt":        formatMCPTime(createdAt),
		})
	}
	return out, rows.Err()
}

func (s *ToolService) listCerebroResponseActions(ctx context.Context, organizationID string, incidentID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(finding_id, ''), action::text, COALESCE(provider::text, ''),
		       target_type, target_identifier, status::text, approval_required, rationale,
		       approved_at, executed_at, COALESCE(error_message, ''), result, created_at
		FROM saas_response_actions
		WHERE organization_id = $1 AND incident_id = $2
		ORDER BY created_at DESC, id DESC
	`, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, findingID, action, provider, targetType, targetIdentifier, status, rationale, errorMessage string
		var approvalRequired bool
		var approvedAt, executedAt sql.NullTime
		var result []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &findingID, &action, &provider, &targetType, &targetIdentifier, &status, &approvalRequired, &rationale, &approvedAt, &executedAt, &errorMessage, &result, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":               id,
			"findingId":        nullableText(findingID),
			"action":           action,
			"provider":         nullableText(provider),
			"targetType":       targetType,
			"targetIdentifier": targetIdentifier,
			"status":           status,
			"approvalRequired": approvalRequired,
			"rationale":        rationale,
			"approvedAt":       nullableTime(approvedAt),
			"executedAt":       nullableTime(executedAt),
			"errorMessage":     nullableText(errorMessage),
			"result":           decodeJSON(result),
			"actionContract":   cerebroResponseActionContract(action, provider),
			"createdAt":        formatMCPTime(createdAt),
		})
	}
	return out, rows.Err()
}

func (s *ToolService) ensureIncidentFinding(ctx context.Context, organizationID string, incidentID string, findingID string) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM saas_incident_findings
			WHERE organization_id = $1 AND incident_id = $2 AND finding_id = $3
		)
	`, organizationID, incidentID, findingID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("Finding is not linked to Cerebro incident: %s", findingID)
	}
	return nil
}

func (s *ToolService) ReadResource(ctx context.Context, params ResourceReadParams) (ResourceContent, error) {
	organizationID, collection, resourceID, err := parseCerebroResourceURI(params.URI)
	if err != nil {
		return ResourceContent{}, err
	}
	if err := s.assertScope(map[string]any{
		"organizationId": organizationID,
		"authToken":      params.AuthToken,
	}); err != nil {
		return ResourceContent{}, err
	}
	if s.db == nil {
		return ResourceContent{}, fmt.Errorf("database is not configured for MCP resource reads")
	}

	var payload any
	var mimeType string
	switch collection {
	case "incidents":
		payload, err = s.getCerebroIncidentContext(ctx, map[string]any{
			"organizationId": organizationID,
			"incidentId":     resourceID,
		})
		mimeType = cerebroIncidentMimeType
	case "findings":
		payload, err = s.getCerebroFindingContext(ctx, map[string]any{
			"organizationId": organizationID,
			"findingId":      resourceID,
		})
		mimeType = cerebroFindingMimeType
	case "security":
		if resourceID != "overview" {
			return ResourceContent{}, fmt.Errorf("Unsupported Cerebro MCP security resource: %s", resourceID)
		}
		payload, err = s.getCerebroSecurityOverviewContext(ctx, map[string]any{
			"organizationId": organizationID,
		})
		mimeType = cerebroSecurityOverviewMimeType
	default:
		return ResourceContent{}, fmt.Errorf("Unsupported Cerebro MCP resource collection: %s", collection)
	}
	if err != nil {
		return ResourceContent{}, err
	}
	text, err := json.Marshal(payload)
	if err != nil {
		return ResourceContent{}, fmt.Errorf("Cerebro MCP resource could not be encoded")
	}
	return ResourceContent{
		URI:      normalizedCerebroResourceURI(organizationID, collection, resourceID),
		MimeType: mimeType,
		Text:     string(text),
	}, nil
}

func parseCerebroResourceURI(rawURI string) (string, string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURI))
	if err != nil {
		return "", "", "", fmt.Errorf("Invalid Cerebro MCP resource URI")
	}
	if parsed.Scheme != "cerebro" || parsed.Host != "aperio" {
		return "", "", "", fmt.Errorf("Unsupported Cerebro MCP resource URI")
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("Cerebro MCP resource URI must include organization, collection, and id")
	}
	organizationID, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", fmt.Errorf("Invalid Cerebro MCP organization id")
	}
	collection, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", fmt.Errorf("Invalid Cerebro MCP resource collection")
	}
	resourceID, err := url.PathUnescape(parts[2])
	if err != nil {
		return "", "", "", fmt.Errorf("Invalid Cerebro MCP resource id")
	}
	organizationID = strings.TrimSpace(organizationID)
	collection = strings.TrimSpace(collection)
	resourceID = strings.TrimSpace(resourceID)
	if organizationID == "" || collection == "" || resourceID == "" {
		return "", "", "", fmt.Errorf("Cerebro MCP resource URI must include organization, collection, and id")
	}
	return organizationID, collection, resourceID, nil
}

func normalizedCerebroResourceURI(organizationID string, collection string, resourceID string) string {
	switch collection {
	case "incidents":
		return cerebroIncidentResourceURI(organizationID, resourceID)
	case "findings":
		return cerebroFindingResourceURI(organizationID, resourceID)
	case "security":
		if resourceID == "overview" {
			return cerebroSecurityOverviewResourceURI(organizationID)
		}
		return "cerebro://aperio/" + url.PathEscape(organizationID) + "/security/" + url.PathEscape(resourceID)
	default:
		return "cerebro://aperio/" + url.PathEscape(organizationID) + "/" + url.PathEscape(collection) + "/" + url.PathEscape(resourceID)
	}
}

func (s *ToolService) getCerebroSecurityOverviewContext(ctx context.Context, input map[string]any) (any, error) {
	organizationID := stringValue(input["organizationId"])
	summary, err := s.cerebroSecurityOverviewSummary(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	findingsResult, err := s.listCerebroFindings(ctx, map[string]any{
		"organizationId": organizationID,
		"status":         "OPEN",
		"limit":          10,
	})
	if err != nil {
		return nil, err
	}
	incidentsResult, err := s.listCerebroIncidents(ctx, map[string]any{
		"organizationId": organizationID,
		"status":         "ALL",
		"limit":          10,
	})
	if err != nil {
		return nil, err
	}

	resourceURI := cerebroSecurityOverviewResourceURI(organizationID)
	mcp := map[string]any{
		"resourceUri":       resourceURI,
		"mimeType":          cerebroSecurityOverviewMimeType,
		"tools":             cerebroMCPToolNames(),
		"resourceTemplates": ApprovedResourceTemplates(),
	}
	return map[string]any{
		"server": ServerName,
		"resource": map[string]any{
			"uri":         resourceURI,
			"name":        "Aperio security overview",
			"description": "Tenant-scoped Cerebro security posture overview for Aperio.",
			"mimeType":    cerebroSecurityOverviewMimeType,
		},
		"summary":              summary,
		"findings":             findingsResult.(map[string]any)["resources"],
		"incidents":            incidentsResult.(map[string]any)["resources"],
		"responseCapabilities": cerebroResponseCapabilities(),
		"cerebroContext": map[string]any{
			"source":               "local-projection",
			"mode":                 "mcp-resource",
			"findingContract":      "cerebro.v1.Finding",
			"mcp":                  mcp,
			"responseCapabilities": cerebroResponseCapabilities(),
			"responseHints": []string{
				"Use linked incident and finding resources to inspect Cerebro graph context before response.",
			},
		},
		"mcp": mcp,
	}, nil
}

func (s *ToolService) cerebroSecurityOverviewSummary(ctx context.Context, organizationID string) (map[string]any, error) {
	severityCounts, err := s.cerebroSecurityOverviewCountMap(ctx, `
		SELECT severity::text, COUNT(*)::int
		FROM security_findings
		WHERE organization_id = $1 AND status = 'OPEN'::"FindingStatus"
		GROUP BY severity::text
	`, organizationID)
	if err != nil {
		return nil, err
	}
	incidentStatusCounts, err := s.cerebroSecurityOverviewCountMap(ctx, `
		SELECT status::text, COUNT(*)::int
		FROM saas_incidents
		WHERE organization_id = $1
		GROUP BY status::text
	`, organizationID)
	if err != nil {
		return nil, err
	}
	responseStatusCounts, err := s.cerebroSecurityOverviewCountMap(ctx, `
		SELECT status::text, COUNT(*)::int
		FROM saas_response_actions
		WHERE organization_id = $1
		GROUP BY status::text
	`, organizationID)
	if err != nil {
		return nil, err
	}
	openFindingCount := 0
	for _, count := range severityCounts {
		openFindingCount += count
	}
	activeIncidentCount := 0
	for status, count := range incidentStatusCounts {
		if status != "RESOLVED" {
			activeIncidentCount += count
		}
	}
	return map[string]any{
		"openFindingCount":            openFindingCount,
		"criticalFindingCount":        severityCounts["CRITICAL"],
		"highFindingCount":            severityCounts["HIGH"],
		"activeIncidentCount":         activeIncidentCount,
		"proposedResponseActionCount": responseStatusCounts["PROPOSED"],
		"findingSeverityCounts":       severityCounts,
		"incidentStatusCounts":        incidentStatusCounts,
		"responseActionStatusCounts":  responseStatusCounts,
	}, nil
}

func (s *ToolService) cerebroSecurityOverviewCountMap(ctx context.Context, query string, organizationID string) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, query, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}
		counts[key] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func (s *ToolService) currentTime() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func cerebroIncidentResource(organizationID string, incident cerebroIncidentRow) map[string]any {
	return map[string]any{
		"uri":         cerebroIncidentResourceURI(organizationID, incident.ID),
		"name":        incident.Title,
		"description": incident.Summary,
		"mimeType":    cerebroIncidentMimeType,
	}
}

func cerebroFindingResource(organizationID string, finding cerebroFindingRow) map[string]any {
	return map[string]any{
		"uri":         cerebroFindingResourceURI(organizationID, finding.ID),
		"name":        finding.Title,
		"description": finding.Description,
		"mimeType":    cerebroFindingMimeType,
	}
}

func cerebroIncidentResourceURI(organizationID string, incidentID string) string {
	return "cerebro://aperio/" + url.PathEscape(organizationID) + "/incidents/" + url.PathEscape(incidentID)
}

func cerebroFindingResourceURI(organizationID string, findingID string) string {
	return "cerebro://aperio/" + url.PathEscape(organizationID) + "/findings/" + url.PathEscape(findingID)
}

func cerebroSecurityOverviewResourceURI(organizationID string) string {
	return "cerebro://aperio/" + url.PathEscape(organizationID) + "/security/overview"
}

func cerebroMCPToolNames() []string {
	return []string{
		"aperio.list_cerebro_incidents",
		"aperio.get_cerebro_incident_context",
		"aperio.list_cerebro_findings",
		"aperio.get_cerebro_finding_context",
		"aperio.propose_cerebro_response",
	}
}

func cerebroResponseCapabilities() []map[string]any {
	out := make([]map[string]any, 0, len(cerebroResponseCapabilityCatalog))
	for _, capability := range cerebroResponseCapabilityCatalog {
		out = append(out, capability.toRecord())
	}
	return out
}

func cerebroResponseCapabilitiesForProvider(provider string) []map[string]any {
	normalizedProvider := strings.ToUpper(strings.TrimSpace(provider))
	out := []map[string]any{}
	for _, capability := range cerebroResponseCapabilityCatalog {
		if capability.Provider == "" || capability.Provider == normalizedProvider {
			out = append(out, capability.toRecord())
		}
	}
	return out
}

func cerebroResponseCapabilitiesForFinding(provider string, evidence any) []map[string]any {
	capabilities := cerebroResponseCapabilitiesForProvider(provider)
	if len(cerebroOAuthExposure(provider, evidence)) == 0 {
		return capabilities
	}
	for _, capability := range capabilities {
		action := stringValue(capability["action"])
		if action == "REVOKE_OAUTH_GRANT" || action == "QUARANTINE_APP" {
			capability["rankHint"] = "primary_oauth_containment"
		}
	}
	return capabilities
}

func cerebroResponseCapabilitiesForFindings(findings []map[string]any) []map[string]any {
	out := []map[string]any{}
	seen := map[string]int{}
	for _, finding := range findings {
		for _, capability := range cerebroResponseCapabilitiesForFinding(stringValue(finding["provider"]), finding["evidence"]) {
			key := responseCapabilityKey(capability)
			if index, ok := seen[key]; ok {
				if stringValue(capability["rankHint"]) != "" && stringValue(out[index]["rankHint"]) == "" {
					out[index]["rankHint"] = capability["rankHint"]
				}
				continue
			}
			seen[key] = len(out)
			out = append(out, capability)
		}
	}
	if len(out) == 0 {
		return cerebroResponseCapabilities()
	}
	return out
}

func cerebroResponseActionContract(action string, provider string) map[string]any {
	if capability, ok := findCerebroResponseCapability(action, provider); ok {
		record := capability.toRecord()
		record["tool"] = "aperio.propose_cerebro_response"
		return record
	}
	return map[string]any{
		"action":              action,
		"provider":            nullableText(provider),
		"providerAction":      nullableText(providerActionFallback(action, provider)),
		"targetTypes":         []string{},
		"requiredContextKeys": []string{"incident_id"},
		"mode":                "aperio_human_gated",
		"dryRun":              true,
		"approvalRequired":    true,
		"externalOwner":       "aperio",
		"tool":                "aperio.propose_cerebro_response",
	}
}

func findCerebroResponseCapability(action string, provider string) (cerebroResponseCapability, bool) {
	normalizedAction := strings.ToUpper(strings.TrimSpace(action))
	normalizedProvider := strings.ToUpper(strings.TrimSpace(provider))
	for _, capability := range cerebroResponseCapabilityCatalog {
		if capability.Action == normalizedAction && capability.Provider == normalizedProvider {
			return capability, true
		}
	}
	for _, capability := range cerebroResponseCapabilityCatalog {
		if capability.Action == normalizedAction && capability.Provider == "" {
			return capability, true
		}
	}
	return cerebroResponseCapability{}, false
}

func (capability cerebroResponseCapability) toRecord() map[string]any {
	return map[string]any{
		"action":              capability.Action,
		"provider":            nullableText(capability.Provider),
		"providerAction":      capability.ProviderAction,
		"targetTypes":         copyStrings(capability.TargetTypes),
		"requiredContextKeys": copyStrings(capability.RequiredContextKeys),
		"mode":                capability.Mode,
		"dryRun":              capability.DryRun,
		"approvalRequired":    capability.ApprovalRequired,
		"externalOwner":       capability.ExternalOwner,
		"effect":              capability.Effect,
		"rollback":            capability.Rollback,
	}
}

func responseCapabilityKey(capability map[string]any) string {
	return strings.Join([]string{
		stringValue(capability["action"]),
		stringValue(capability["provider"]),
		stringValue(capability["providerAction"]),
	}, "|")
}

func providerActionFallback(action string, provider string) string {
	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	if normalizedProvider == "" {
		return ""
	}
	return normalizedProvider + "." + strings.ToLower(strings.TrimSpace(action))
}

func copyStrings(values []string) []string {
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func cerebroOAuthExposure(provider string, evidence any) map[string]any {
	record, _ := evidence.(map[string]any)
	scopes := sanitizeEvidenceStrings(stringArrayFromEvidence(record, "scopes", "oauthScopes", "oauth_scopes", "grantScopes", "grant_scopes"))
	resourceFamilies := sanitizeEvidenceStrings(stringArrayFromEvidence(record, "resourceFamilies", "resource_families", "resources", "resourceTypes"))
	for _, scope := range scopes {
		if family := oauthScopeResourceFamily(scope); family != "" {
			resourceFamilies = append(resourceFamilies, family)
		}
	}
	resourceFamilies = uniqueStrings(resourceFamilies)
	appID := sanitizeEvidenceText(firstEvidenceString(record, "oauthAppId", "oauth_app_id", "appId", "app_id", "clientId", "client_id"))
	grantID := sanitizeEvidenceText(firstEvidenceString(record, "oauthGrantId", "oauth_grant_id", "grantId", "grant_id"))
	user := sanitizeEvidenceText(firstEvidenceString(record, "oauthUserEmail", "oauth_user_email", "userEmail", "user_email", "principal", "actorEmail"))
	appName := sanitizeEvidenceText(firstEvidenceString(record, "oauthAppName", "oauth_app_name", "appName", "app_name", "clientName", "client_name"))
	riskyScopes := sanitizeEvidenceStrings(stringArrayFromEvidence(record, "riskyScopes", "risky_scopes", "privilegedScopes", "privileged_scopes"))
	domainWideAccess := boolEvidenceValue(record, "domainWideAccess", "domain_wide_access", "isDomainWide")
	if appID == "" && grantID == "" && appName == "" && user == "" && len(scopes) == 0 && len(resourceFamilies) == 0 && len(riskyScopes) == 0 && !domainWideAccess {
		return map[string]any{}
	}
	return map[string]any{
		"provider":           nullableText(provider),
		"appId":              nullableText(appID),
		"appName":            nullableText(appName),
		"grantId":            nullableText(grantID),
		"user":               nullableText(user),
		"scopeCount":         len(scopes),
		"scopes":             scopes,
		"riskyScopes":        riskyScopes,
		"resourceFamilies":   resourceFamilies,
		"domainWideAccess":   domainWideAccess,
		"blastRadiusSummary": oauthBlastRadiusSummary(user, scopes, resourceFamilies, domainWideAccess),
	}
}

func oauthBlastRadiusSummary(user string, scopes []string, resourceFamilies []string, domainWideAccess bool) string {
	parts := []string{}
	if domainWideAccess {
		parts = append(parts, "domain-wide access")
	}
	if user != "" {
		parts = append(parts, "user "+user)
	}
	if len(resourceFamilies) > 0 {
		parts = append(parts, strings.Join(resourceFamilies, ", "))
	}
	if len(scopes) > 0 {
		parts = append(parts, fmt.Sprintf("%d OAuth scopes", len(scopes)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " / ")
}

func sanitizeEvidenceStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if sanitized := sanitizeEvidenceText(value); sanitized != "" {
			out = append(out, sanitized)
		}
	}
	return uniqueStrings(out)
}

func sanitizeEvidenceText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, trimmed)
	return strings.Join(strings.Fields(cleaned), " ")
}

func oauthScopeResourceFamily(scope string) string {
	normalized := strings.ToLower(strings.TrimSpace(scope))
	switch {
	case strings.Contains(normalized, "profile") || strings.Contains(normalized, "userinfo") || strings.Contains(normalized, "email"):
		return "profile"
	case strings.Contains(normalized, "gmail") || strings.Contains(normalized, "mail"):
		return "mail"
	case strings.Contains(normalized, "drive") || strings.Contains(normalized, "docs") || strings.Contains(normalized, "sheets") || strings.Contains(normalized, "files"):
		return "files"
	case strings.Contains(normalized, "calendar"):
		return "calendar"
	case strings.Contains(normalized, "admin") || strings.Contains(normalized, "directory") || strings.Contains(normalized, "groups"):
		return "directory"
	case strings.Contains(normalized, "chat") || strings.Contains(normalized, "channels"):
		return "collaboration"
	case strings.Contains(normalized, "repo") || strings.Contains(normalized, "code"):
		return "code"
	default:
		return ""
	}
}

func firstEvidenceString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func boolEvidenceValue(record map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch typed := record[key].(type) {
		case bool:
			return typed
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			if normalized == "true" || normalized == "yes" || normalized == "1" {
				return true
			}
		}
	}
	return false
}

func stringArrayFromEvidence(record map[string]any, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		switch typed := record[key].(type) {
		case []string:
			values = append(values, typed...)
		case []any:
			for _, item := range typed {
				if value := stringValue(item); value != "" {
					values = append(values, value)
				}
			}
		case string:
			for _, item := range strings.FieldsFunc(typed, func(r rune) bool {
				return r == ',' || r == '\n' || r == '\t'
			}) {
				if value := strings.TrimSpace(item); value != "" {
					values = append(values, value)
				}
			}
		}
	}
	return uniqueStrings(values)
}

func uniqueStrings(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func (row cerebroFindingRow) toSummary(organizationID string) map[string]any {
	evidence := decodeJSON([]byte(row.EvidenceJSON))
	summary := map[string]any{
		"id":                  row.ID,
		"assetId":             nullableText(row.AssetID),
		"title":               row.Title,
		"description":         row.Description,
		"severity":            row.Severity,
		"status":              row.Status,
		"riskScore":           row.RiskScore,
		"detectedAt":          formatMCPTime(row.DetectedAt),
		"resolvedAt":          nullableTime(row.ResolvedAt),
		"provider":            row.Provider,
		"integrationId":       row.IntegrationID,
		"integrationName":     row.IntegrationName,
		"incidentCount":       row.IncidentCount,
		"responseActionCount": row.ResponseActionCount,
		"cerebro":             cerebroFindingSummary(evidence),
		"resource":            cerebroFindingResource(organizationID, row),
	}
	if exposure := cerebroOAuthExposure(row.Provider, evidence); len(exposure) > 0 {
		summary["oauthExposure"] = exposure
	}
	return summary
}

func (row cerebroFindingRow) toDetail(organizationID string) map[string]any {
	evidence := decodeJSON([]byte(row.EvidenceJSON))
	detail := row.toSummary(organizationID)
	detail["remediationSteps"] = decodeJSON([]byte(row.RemediationJSON))
	detail["tags"] = decodeJSON([]byte(row.TagsJSON))
	detail["evidence"] = evidence
	detail["cerebroContext"] = cerebroFindingContext(organizationID, row, evidence)
	detail["responseCapabilities"] = cerebroResponseCapabilitiesForFinding(row.Provider, evidence)
	return detail
}

func cerebroFindingSummary(evidence any) map[string]any {
	sourceEventID := sourceEventIDFromEvidence(evidence)
	return map[string]any{
		"source":          "local-projection",
		"mode":            "not-configured",
		"findingContract": "cerebro.v1.Finding",
		"sourceEventId":   nullableText(sourceEventID),
	}
}

func cerebroFindingContext(organizationID string, row cerebroFindingRow, evidence any) map[string]any {
	context := cerebroFindingSummary(evidence)
	context["mcp"] = map[string]any{
		"resourceUri":       cerebroFindingResourceURI(organizationID, row.ID),
		"mimeType":          cerebroFindingMimeType,
		"tools":             cerebroMCPToolNames(),
		"resourceTemplates": ApprovedResourceTemplates(),
	}
	if exposure := cerebroOAuthExposure(row.Provider, evidence); len(exposure) > 0 {
		context["oauthExposure"] = exposure
	}
	context["responseCapabilities"] = cerebroResponseCapabilitiesForFinding(row.Provider, evidence)
	context["responseHints"] = []string{
		"Use linked incident context and Cerebro response proposals before resolving or accepting this finding.",
	}
	return context
}

func sourceEventIDFromEvidence(evidence any) string {
	record, _ := evidence.(map[string]any)
	for _, key := range []string{"sourceEventId", "source_event_id", "eventId"} {
		if value := stringValue(record[key]); value != "" {
			return value
		}
	}
	return ""
}

func cerebroSummary(context any) map[string]any {
	record, _ := context.(map[string]any)
	summary := map[string]any{
		"source":           stringValue(record["source"]),
		"mode":             stringValue(record["mode"]),
		"sourceRuntimeId":  stringValue(record["sourceRuntimeId"]),
		"findingContract":  stringValue(record["findingContract"]),
		"claimCount":       numberValue(record["claimCount"]),
		"graphSignalCount": len(arrayValue(record["graphSignals"])),
		"graphPathCount":   len(arrayValue(record["graphPaths"])),
	}
	return summary
}

func arrayValue(value any) []any {
	if items, ok := value.([]any); ok {
		return items
	}
	return nil
}

func numberValue(value any) any {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return typed
	case int64:
		return typed
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed
		}
		if parsed, err := typed.Float64(); err == nil {
			return parsed
		}
	}
	return nil
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
