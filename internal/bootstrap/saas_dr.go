package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
)

type saasIncidentRow struct {
	ID                           string
	Title                        string
	Summary                      string
	Severity                     string
	Status                       string
	ConfidenceScore              int32
	OwnerTeam                    string
	AssigneeID                   string
	AssigneeEmail                string
	AssigneeName                 string
	FirstDetectedAt              time.Time
	LastActivityAt               time.Time
	SLADueAt                     sql.NullTime
	ResolvedAt                   sql.NullTime
	CerebroContextJSON           string
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
	FindingCount                 int32
	OpenFindingCount             int32
	ResponseActionCount          int32
	CompletedResponseActionCount int32
}

type saasTimelineRow struct {
	ID               string
	IncidentID       string
	FindingID        string
	ResponseActionID string
	Kind             string
	Title            string
	Description      string
	Actor            string
	Source           string
	EvidenceJSON     string
	OccurredAt       time.Time
	CreatedAt        time.Time
}

type saasResponseActionRow struct {
	ID               string
	IncidentID       string
	FindingID        string
	Action           string
	Provider         string
	TargetType       string
	TargetIdentifier string
	Status           string
	ApprovalRequired bool
	Rationale        string
	ApprovedByID     string
	ApprovedByEmail  string
	ApprovedByName   string
	ApprovedAt       sql.NullTime
	ExecutedAt       sql.NullTime
	ErrorMessage     string
	ResultJSON       string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (a *App) ListSaasIncidents(
	ctx context.Context,
	req *connect.Request[aperiov1.ListSaasIncidentsRequest],
) (*connect.Response[aperiov1.ListSaasIncidentsResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	if err := validateSaasIncidentListRequest(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	rows, total, err := a.listSaasIncidents(ctx, organizationID, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("saas incidents unavailable"))
	}
	metrics, err := a.saasIncidentMetrics(ctx, organizationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("saas incident metrics unavailable"))
	}
	response := &aperiov1.ListSaasIncidentsResponse{
		Data: make([]*aperiov1.SaasIncident, 0, len(rows)),
		PageInfo: &aperiov1.PageInfo{
			Total: int32(total),
		},
		Metrics: metrics,
	}
	limit := normalizedLimit(req.Msg.Limit)
	if len(rows) == limit {
		response.PageInfo.NextCursor = rows[len(rows)-1].ID
	}
	for _, row := range rows {
		response.Data = append(response.Data, row.toProto())
	}
	return connect.NewResponse(response), nil
}

func (a *App) GetSaasIncident(
	ctx context.Context,
	req *connect.Request[aperiov1.GetSaasIncidentRequest],
) (*connect.Response[aperiov1.GetSaasIncidentResponse], error) {
	organizationID, err := a.authenticatedOrganization(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	incidentID := strings.TrimSpace(req.Msg.Id)
	if incidentID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("incident id is required"))
	}
	detail, err := a.getSaasIncidentDetail(ctx, organizationID, incidentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("incident not found"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("incident unavailable"))
	}
	return connect.NewResponse(&aperiov1.GetSaasIncidentResponse{Data: detail}), nil
}

func (a *App) CreateSaasIncident(
	ctx context.Context,
	req *connect.Request[aperiov1.CreateSaasIncidentRequest],
) (*connect.Response[aperiov1.CreateSaasIncidentResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	incidentID, err := a.createSaasIncident(ctx, auth, req.Msg)
	if err != nil {
		return nil, err
	}
	detail, err := a.getSaasIncidentDetail(ctx, auth.OrganizationID, incidentID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("incident unavailable"))
	}
	return connect.NewResponse(&aperiov1.CreateSaasIncidentResponse{Data: detail}), nil
}

func (a *App) UpdateSaasIncidentStatus(
	ctx context.Context,
	req *connect.Request[aperiov1.UpdateSaasIncidentStatusRequest],
) (*connect.Response[aperiov1.UpdateSaasIncidentStatusResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	row, err := a.updateSaasIncidentStatus(ctx, auth, req.Msg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("incident not found"))
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.UpdateSaasIncidentStatusResponse{Data: row.toProto()}), nil
}

func (a *App) ProposeSaasResponseAction(
	ctx context.Context,
	req *connect.Request[aperiov1.ProposeSaasResponseActionRequest],
) (*connect.Response[aperiov1.ProposeSaasResponseActionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST"); err != nil {
		return nil, err
	}
	action, err := a.proposeSaasResponseAction(ctx, auth, req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ProposeSaasResponseActionResponse{Data: action.toProto()}), nil
}

func (a *App) ExecuteSaasResponseAction(
	ctx context.Context,
	req *connect.Request[aperiov1.ExecuteSaasResponseActionRequest],
) (*connect.Response[aperiov1.ExecuteSaasResponseActionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	action, err := a.executeSaasResponseAction(ctx, auth, req.Msg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("response action not found"))
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ExecuteSaasResponseActionResponse{Data: action.toProto()}), nil
}

func validateSaasIncidentListRequest(req *aperiov1.ListSaasIncidentsRequest) error {
	if req.Limit > 100 {
		return errors.New("limit must be less than or equal to 100")
	}
	if req.Status != "" && !allowedValue(req.Status, "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "ALL") {
		return errors.New("invalid incident status filter")
	}
	if req.Severity != "" && !allowedValue(req.Severity, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") {
		return errors.New("invalid severity filter")
	}
	return nil
}

func validateSaasIncidentInput(title, severity string) error {
	if strings.TrimSpace(title) == "" {
		return errors.New("title is required")
	}
	if severity == "" || !allowedValue(severity, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") {
		return errors.New("valid severity is required")
	}
	return nil
}

func validateSaasResponseActionInput(req *aperiov1.ProposeSaasResponseActionRequest) error {
	if strings.TrimSpace(req.IncidentId) == "" {
		return errors.New("incident id is required")
	}
	if !allowedValue(req.Action, "REVOKE_OAUTH_GRANT", "SUSPEND_USER", "RESET_MFA", "REVOKE_SESSION", "REMOVE_EXTERNAL_SHARE", "DISABLE_FORWARDING", "REMOVE_ADMIN_ROLE", "QUARANTINE_APP", "OPEN_TICKET", "NOTIFY_SECOPS") {
		return errors.New("valid response action is required")
	}
	if req.Provider != "" && !allowedValue(req.Provider, "GITHUB", "SLACK", "GOOGLE_WORKSPACE", "ONE_PASSWORD", "OKTA", "MICROSOFT_365", "ATLASSIAN", "SALESFORCE") {
		return errors.New("invalid provider")
	}
	if strings.TrimSpace(req.TargetType) == "" || strings.TrimSpace(req.TargetIdentifier) == "" {
		return errors.New("target type and identifier are required")
	}
	if strings.TrimSpace(req.Rationale) == "" {
		return errors.New("rationale is required")
	}
	return nil
}

func (a *App) listSaasIncidents(
	ctx context.Context,
	organizationID string,
	req *aperiov1.ListSaasIncidentsRequest,
) ([]saasIncidentRow, int, error) {
	where, args := saasIncidentFilterWhere(organizationID, req)
	var total int
	countQuery := `SELECT COUNT(*)::int FROM saas_incidents si WHERE ` + strings.Join(where, " AND ")
	if err := a.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listWhere := append([]string{}, where...)
	listArgs := append([]any{}, args...)
	if cursor := strings.TrimSpace(req.Cursor); cursor != "" {
		var cursorLastActivityAt time.Time
		err := a.db.QueryRowContext(ctx, `
			SELECT last_activity_at
			FROM saas_incidents
			WHERE organization_id = $1 AND id = $2
		`, organizationID, cursor).Scan(&cursorLastActivityAt)
		if errors.Is(err, sql.ErrNoRows) {
			return []saasIncidentRow{}, total, nil
		}
		if err != nil {
			return nil, 0, err
		}
		listArgs = append(listArgs, cursorLastActivityAt, cursor)
		listWhere = append(listWhere, "(si.last_activity_at, si.id) < ($"+intPlaceholder(len(listArgs)-1)+", $"+intPlaceholder(len(listArgs))+")")
	}
	listArgs = append(listArgs, normalizedLimit(req.Limit))
	query := saasIncidentSelectSQL(`
		WHERE ` + strings.Join(listWhere, " AND ") + `
		ORDER BY si.last_activity_at DESC, si.id DESC
		LIMIT $` + intPlaceholder(len(listArgs)))
	rows, err := a.db.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	incidents, err := scanSaasIncidentRows(rows)
	return incidents, total, err
}

func (a *App) saasIncidentMetrics(ctx context.Context, organizationID string) (*aperiov1.SaasIncidentMetrics, error) {
	var metrics aperiov1.SaasIncidentMetrics
	err := a.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'OPEN')::int,
			COUNT(*) FILTER (WHERE status = 'INVESTIGATING')::int,
			COUNT(*) FILTER (WHERE status = 'CONTAINED')::int,
			COUNT(*) FILTER (WHERE status = 'RESOLVED')::int,
			COUNT(*) FILTER (WHERE status IN ('OPEN','INVESTIGATING') AND severity = 'CRITICAL')::int,
			(
				SELECT COUNT(*)::int
				FROM saas_response_actions sra
				WHERE sra.organization_id = $1
				  AND sra.status IN ('PROPOSED','APPROVED','EXECUTING')
			)
		FROM saas_incidents
		WHERE organization_id = $1
	`, organizationID).Scan(
		&metrics.Open,
		&metrics.Investigating,
		&metrics.Contained,
		&metrics.Resolved,
		&metrics.CriticalOpen,
		&metrics.ResponseActionsPending,
	)
	return &metrics, err
}

func saasIncidentFilterWhere(organizationID string, req *aperiov1.ListSaasIncidentsRequest) ([]string, []any) {
	where := []string{"si.organization_id = $1"}
	args := []any{organizationID}
	if status := strings.TrimSpace(req.Status); status != "" && status != "ALL" {
		args = append(args, status)
		where = append(where, "si.status::text = $"+intPlaceholder(len(args)))
	}
	if severity := strings.TrimSpace(req.Severity); severity != "" {
		args = append(args, severity)
		where = append(where, "si.severity::text = $"+intPlaceholder(len(args)))
	}
	if assigneeUserID := strings.TrimSpace(req.AssigneeUserId); assigneeUserID != "" {
		args = append(args, assigneeUserID)
		where = append(where, "si.assignee_user_id = $"+intPlaceholder(len(args)))
	}
	return where, args
}

func saasIncidentSelectSQL(suffix string) string {
	return `
		WITH finding_counts AS (
			SELECT
				sif.incident_id,
				COUNT(*)::int AS finding_count,
				COUNT(*) FILTER (WHERE sf.status = 'OPEN')::int AS open_finding_count
			FROM saas_incident_findings sif
			JOIN security_findings sf ON sf.id = sif.finding_id
			GROUP BY sif.incident_id
		),
		action_counts AS (
			SELECT
				incident_id,
				COUNT(*)::int AS response_action_count,
				COUNT(*) FILTER (WHERE status = 'SUCCEEDED')::int AS completed_response_action_count
			FROM saas_response_actions
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
			COALESCE(assignee.id, ''),
			COALESCE(assignee.email, ''),
			COALESCE(assignee.display_name, ''),
			si.first_detected_at,
			si.last_activity_at,
			si.sla_due_at,
			si.resolved_at,
			si.cerebro_context::text,
			si.created_at,
			si.updated_at,
			COALESCE(fc.finding_count, 0),
			COALESCE(fc.open_finding_count, 0),
			COALESCE(ac.response_action_count, 0),
			COALESCE(ac.completed_response_action_count, 0)
		FROM saas_incidents si
		LEFT JOIN users assignee ON assignee.id = si.assignee_user_id
			AND assignee.organization_id = si.organization_id
		LEFT JOIN finding_counts fc ON fc.incident_id = si.id
		LEFT JOIN action_counts ac ON ac.incident_id = si.id
	` + suffix
}

type saasIncidentScanner interface {
	Scan(dest ...any) error
}

func scanSaasIncidentRows(rows *sql.Rows) ([]saasIncidentRow, error) {
	var incidents []saasIncidentRow
	for rows.Next() {
		row, err := scanSaasIncidentRow(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, row)
	}
	return incidents, rows.Err()
}

func scanSaasIncidentRow(scanner saasIncidentScanner) (saasIncidentRow, error) {
	var row saasIncidentRow
	err := scanner.Scan(
		&row.ID,
		&row.Title,
		&row.Summary,
		&row.Severity,
		&row.Status,
		&row.ConfidenceScore,
		&row.OwnerTeam,
		&row.AssigneeID,
		&row.AssigneeEmail,
		&row.AssigneeName,
		&row.FirstDetectedAt,
		&row.LastActivityAt,
		&row.SLADueAt,
		&row.ResolvedAt,
		&row.CerebroContextJSON,
		&row.CreatedAt,
		&row.UpdatedAt,
		&row.FindingCount,
		&row.OpenFindingCount,
		&row.ResponseActionCount,
		&row.CompletedResponseActionCount,
	)
	return row, err
}

func (row saasIncidentRow) toProto() *aperiov1.SaasIncident {
	incident := &aperiov1.SaasIncident{
		Id:                           row.ID,
		Title:                        row.Title,
		Summary:                      row.Summary,
		Severity:                     row.Severity,
		Status:                       row.Status,
		ConfidenceScore:              row.ConfidenceScore,
		OwnerTeam:                    row.OwnerTeam,
		FirstDetectedAt:              row.FirstDetectedAt.UTC().Format(time.RFC3339Nano),
		LastActivityAt:               row.LastActivityAt.UTC().Format(time.RFC3339Nano),
		SlaDueAt:                     nullTimeString(row.SLADueAt),
		ResolvedAt:                   nullTimeString(row.ResolvedAt),
		CerebroContextJson:           row.CerebroContextJSON,
		CreatedAt:                    row.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:                    row.UpdatedAt.UTC().Format(time.RFC3339Nano),
		FindingCount:                 row.FindingCount,
		OpenFindingCount:             row.OpenFindingCount,
		ResponseActionCount:          row.ResponseActionCount,
		CompletedResponseActionCount: row.CompletedResponseActionCount,
	}
	if row.AssigneeID != "" {
		incident.Assignee = &aperiov1.SecurityPrincipal{
			Id:          row.AssigneeID,
			Email:       row.AssigneeEmail,
			DisplayName: row.AssigneeName,
		}
	}
	return incident
}

func (a *App) getSaasIncidentDetail(ctx context.Context, organizationID, incidentID string) (*aperiov1.SaasIncidentDetail, error) {
	incident, err := a.getSaasIncidentRow(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	findings, err := a.listSaasIncidentFindings(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	timeline, err := a.listSaasIncidentTimeline(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	actions, err := a.listSaasResponseActions(ctx, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	detail := &aperiov1.SaasIncidentDetail{
		Incident:        incident.toProto(),
		Findings:        make([]*aperiov1.Finding, 0, len(findings)),
		Timeline:        make([]*aperiov1.SaasIncidentTimelineEvent, 0, len(timeline)),
		ResponseActions: make([]*aperiov1.SaasResponseAction, 0, len(actions)),
	}
	for _, finding := range findings {
		detail.Findings = append(detail.Findings, finding.toProto())
	}
	for _, event := range timeline {
		detail.Timeline = append(detail.Timeline, event.toProto())
	}
	for _, action := range actions {
		detail.ResponseActions = append(detail.ResponseActions, action.toProto())
	}
	return detail, nil
}

func (a *App) getSaasIncidentRow(ctx context.Context, organizationID, incidentID string) (saasIncidentRow, error) {
	query := saasIncidentSelectSQL(`
		WHERE si.organization_id = $1 AND si.id = $2
	`)
	return scanSaasIncidentRow(a.db.QueryRowContext(ctx, query, organizationID, incidentID))
}

func (a *App) listSaasIncidentFindings(ctx context.Context, organizationID, incidentID string) ([]findingRow, error) {
	rows, err := a.db.QueryContext(ctx, `
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
			ic.display_name
		FROM saas_incident_findings sif
		JOIN security_findings sf ON sf.id = sif.finding_id
		JOIN integration_connections ic ON ic.id = sf.integration_id
		WHERE sif.organization_id = $1 AND sif.incident_id = $2
		ORDER BY sf.detected_at DESC, sf.id DESC
	`, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindingRows(rows)
}

func (a *App) listSaasIncidentTimeline(ctx context.Context, organizationID, incidentID string) ([]saasTimelineRow, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			id,
			incident_id,
			COALESCE(finding_id, ''),
			COALESCE(response_action_id, ''),
			kind::text,
			title,
			description,
			COALESCE(actor, ''),
			source,
			evidence::text,
			occurred_at,
			created_at
		FROM saas_incident_timeline_events
		WHERE organization_id = $1 AND incident_id = $2
		ORDER BY occurred_at ASC, id ASC
	`, organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []saasTimelineRow
	for rows.Next() {
		var row saasTimelineRow
		if err := rows.Scan(
			&row.ID,
			&row.IncidentID,
			&row.FindingID,
			&row.ResponseActionID,
			&row.Kind,
			&row.Title,
			&row.Description,
			&row.Actor,
			&row.Source,
			&row.EvidenceJSON,
			&row.OccurredAt,
			&row.CreatedAt,
		); err != nil {
			return nil, err
		}
		events = append(events, row)
	}
	return events, rows.Err()
}

func (row saasTimelineRow) toProto() *aperiov1.SaasIncidentTimelineEvent {
	return &aperiov1.SaasIncidentTimelineEvent{
		Id:               row.ID,
		IncidentId:       row.IncidentID,
		FindingId:        row.FindingID,
		ResponseActionId: row.ResponseActionID,
		Kind:             row.Kind,
		Title:            row.Title,
		Description:      row.Description,
		Actor:            row.Actor,
		Source:           row.Source,
		EvidenceJson:     row.EvidenceJSON,
		OccurredAt:       row.OccurredAt.UTC().Format(time.RFC3339Nano),
		CreatedAt:        row.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func (a *App) listSaasResponseActions(ctx context.Context, organizationID, incidentID string) ([]saasResponseActionRow, error) {
	rows, err := a.db.QueryContext(ctx, saasResponseActionSelectSQL(`
		WHERE sra.organization_id = $1 AND sra.incident_id = $2
		ORDER BY sra.created_at DESC, sra.id DESC
	`), organizationID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSaasResponseActionRows(rows)
}

func saasResponseActionSelectSQL(suffix string) string {
	return `
		SELECT
			sra.id,
			sra.incident_id,
			COALESCE(sra.finding_id, ''),
			sra.action::text,
			COALESCE(sra.provider::text, ''),
			sra.target_type,
			sra.target_identifier,
			sra.status::text,
			sra.approval_required,
			sra.rationale,
			COALESCE(approved_by.id, ''),
			COALESCE(approved_by.email, ''),
			COALESCE(approved_by.display_name, ''),
			sra.approved_at,
			sra.executed_at,
			COALESCE(sra.error_message, ''),
			sra.result::text,
			sra.created_at,
			sra.updated_at
		FROM saas_response_actions sra
		LEFT JOIN users approved_by ON approved_by.id = sra.approved_by_user_id
			AND approved_by.organization_id = sra.organization_id
	` + suffix
}

func scanSaasResponseActionRows(rows *sql.Rows) ([]saasResponseActionRow, error) {
	var actions []saasResponseActionRow
	for rows.Next() {
		row, err := scanSaasResponseActionRow(rows)
		if err != nil {
			return nil, err
		}
		actions = append(actions, row)
	}
	return actions, rows.Err()
}

type saasResponseActionScanner interface {
	Scan(dest ...any) error
}

func scanSaasResponseActionRow(scanner saasResponseActionScanner) (saasResponseActionRow, error) {
	var row saasResponseActionRow
	err := scanner.Scan(
		&row.ID,
		&row.IncidentID,
		&row.FindingID,
		&row.Action,
		&row.Provider,
		&row.TargetType,
		&row.TargetIdentifier,
		&row.Status,
		&row.ApprovalRequired,
		&row.Rationale,
		&row.ApprovedByID,
		&row.ApprovedByEmail,
		&row.ApprovedByName,
		&row.ApprovedAt,
		&row.ExecutedAt,
		&row.ErrorMessage,
		&row.ResultJSON,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	return row, err
}

func (row saasResponseActionRow) toProto() *aperiov1.SaasResponseAction {
	action := &aperiov1.SaasResponseAction{
		Id:               row.ID,
		IncidentId:       row.IncidentID,
		FindingId:        row.FindingID,
		Action:           row.Action,
		Provider:         row.Provider,
		TargetType:       row.TargetType,
		TargetIdentifier: row.TargetIdentifier,
		Status:           row.Status,
		ApprovalRequired: row.ApprovalRequired,
		Rationale:        row.Rationale,
		ApprovedAt:       nullTimeString(row.ApprovedAt),
		ExecutedAt:       nullTimeString(row.ExecutedAt),
		ErrorMessage:     row.ErrorMessage,
		ResultJson:       row.ResultJSON,
		CreatedAt:        row.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:        row.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if row.ApprovedByID != "" {
		action.ApprovedBy = &aperiov1.SecurityPrincipal{
			Id:          row.ApprovedByID,
			Email:       row.ApprovedByEmail,
			DisplayName: row.ApprovedByName,
		}
	}
	return action
}

func (a *App) createSaasIncident(ctx context.Context, auth compatAuth, req *aperiov1.CreateSaasIncidentRequest) (string, error) {
	title := strings.TrimSpace(req.Title)
	severity := strings.TrimSpace(req.Severity)
	if err := validateSaasIncidentInput(title, severity); err != nil {
		return "", connect.NewError(connect.CodeInvalidArgument, err)
	}
	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = "Posture incident opened from Aperio."
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return "", internalServerError("saas_incident.begin_tx", err)
	}
	defer tx.Rollback()

	var defaultSLAHours int
	if err := tx.QueryRowContext(ctx, `SELECT default_sla_hours FROM organizations WHERE id = $1`, auth.OrganizationID).Scan(&defaultSLAHours); err != nil {
		return "", internalServerError("saas_incident.default_sla", err)
	}
	assigneeUserID := strings.TrimSpace(req.AssigneeUserId)
	if assigneeUserID != "" {
		var assigneeExists bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM users
				WHERE organization_id = $1 AND id = $2 AND is_active = TRUE
			)
		`, auth.OrganizationID, assigneeUserID).Scan(&assigneeExists); err != nil {
			return "", internalServerError("saas_incident.assignee_lookup", err)
		}
		if !assigneeExists {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("assignee not found"))
		}
	}
	incidentID := compatID("inc")
	contextJSON := saasCerebroContextJSON()
	now := time.Now().UTC()
	slaDueAt := now.Add(time.Duration(defaultSLAHours) * time.Hour)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO saas_incidents (
			id, organization_id, title, summary, severity, status, confidence_score,
			owner_team, assignee_user_id, first_detected_at, last_activity_at,
			sla_due_at, cerebro_context, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5::"Severity",'OPEN',70,$6,NULLIF($7,''),$8,$8,$9,$10::jsonb,$8,$8)
	`, incidentID, auth.OrganizationID, title, summary, severity, strings.TrimSpace(req.OwnerTeam), assigneeUserID, now, slaDueAt, contextJSON); err != nil {
		return "", internalServerError("saas_incident.insert", err)
	}
	if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, "", "", "DETECTION", "Incident opened", summary, auth.Email, "APERIO", map[string]any{"severity": severity}, now); err != nil {
		return "", err
	}
	cerebroEvidence := map[string]any{
		"contract":        "cerebro.v1.Finding",
		"mode":            "context-pending",
		"sourceRuntimeId": "writer-aperio-sspm",
	}
	if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, "", "", "CEREBRO_CONTEXT", "Cerebro context attached", "Aperio will enrich this incident with Cerebro posture, graph, ownership, and finding context.", "cerebro", "CEREBRO", cerebroEvidence, now.Add(time.Millisecond)); err != nil {
		return "", err
	}
	for _, rawID := range req.FindingIds {
		findingID := strings.TrimSpace(rawID)
		if findingID == "" {
			continue
		}
		var findingTitle string
		if err := tx.QueryRowContext(ctx, `
			SELECT title
			FROM security_findings
			WHERE organization_id = $1 AND id = $2
		`, auth.OrganizationID, findingID).Scan(&findingTitle); errors.Is(err, sql.ErrNoRows) {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("finding not found: "+findingID))
		} else if err != nil {
			return "", internalServerError("saas_incident.finding_lookup", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO saas_incident_findings (id, organization_id, incident_id, finding_id, created_at)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (incident_id, finding_id) DO NOTHING
		`, compatID("iln"), auth.OrganizationID, incidentID, findingID, now); err != nil {
			return "", internalServerError("saas_incident.link_finding", err)
		}
		if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, findingID, "", "DETECTION", "Finding linked", findingTitle, auth.Email, "APERIO", map[string]any{"findingId": findingID}, now.Add(2*time.Millisecond)); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", internalServerError("saas_incident.commit", err)
	}
	return incidentID, nil
}

func (a *App) updateSaasIncidentStatus(ctx context.Context, auth compatAuth, req *aperiov1.UpdateSaasIncidentStatusRequest) (saasIncidentRow, error) {
	incidentID := strings.TrimSpace(req.Id)
	status := strings.TrimSpace(req.Status)
	if incidentID == "" {
		return saasIncidentRow{}, connect.NewError(connect.CodeInvalidArgument, errors.New("incident id is required"))
	}
	if !allowedValue(status, "OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED") {
		return saasIncidentRow{}, connect.NewError(connect.CodeInvalidArgument, errors.New("valid incident status is required"))
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return saasIncidentRow{}, internalServerError("saas_incident_status.begin_tx", err)
	}
	defer tx.Rollback()
	var title string
	if err := tx.QueryRowContext(ctx, `
		UPDATE saas_incidents
		SET status = $3::"SaasIncidentStatus",
		    resolved_at = CASE WHEN $3 = 'RESOLVED' THEN NOW() ELSE NULL END,
		    last_activity_at = NOW(),
		    updated_at = NOW()
		WHERE organization_id = $1 AND id = $2
		RETURNING title
	`, auth.OrganizationID, incidentID, status).Scan(&title); err != nil {
		return saasIncidentRow{}, err
	}
	description := "Incident status changed to " + status + "."
	if note := strings.TrimSpace(req.Note); note != "" {
		description = note
	}
	if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, "", "", "STATUS_CHANGE", "Status changed", description, auth.Email, "APERIO", map[string]any{"status": status, "incidentTitle": title}, time.Now().UTC()); err != nil {
		return saasIncidentRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return saasIncidentRow{}, internalServerError("saas_incident_status.commit", err)
	}
	return a.getSaasIncidentRow(ctx, auth.OrganizationID, incidentID)
}

func (a *App) proposeSaasResponseAction(ctx context.Context, auth compatAuth, req *aperiov1.ProposeSaasResponseActionRequest) (saasResponseActionRow, error) {
	if err := validateSaasResponseActionInput(req); err != nil {
		return saasResponseActionRow{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	incidentID := strings.TrimSpace(req.IncidentId)
	findingID := strings.TrimSpace(req.FindingId)
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response.begin_tx", err)
	}
	defer tx.Rollback()
	var incidentTitle string
	if err := tx.QueryRowContext(ctx, `
		SELECT title FROM saas_incidents WHERE organization_id = $1 AND id = $2
	`, auth.OrganizationID, incidentID).Scan(&incidentTitle); errors.Is(err, sql.ErrNoRows) {
		return saasResponseActionRow{}, connect.NewError(connect.CodeNotFound, errors.New("incident not found"))
	} else if err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response.incident_lookup", err)
	}
	if findingID != "" {
		var exists bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM saas_incident_findings
				WHERE organization_id = $1
				  AND incident_id = $2
				  AND finding_id = $3
			)
		`, auth.OrganizationID, incidentID, findingID).Scan(&exists); err != nil {
			return saasResponseActionRow{}, internalServerError("saas_response.finding_lookup", err)
		}
		if !exists {
			return saasResponseActionRow{}, connect.NewError(connect.CodeInvalidArgument, errors.New("finding is not linked to incident"))
		}
	}
	actionID := compatID("act")
	providerSQL := sql.NullString{String: strings.TrimSpace(req.Provider), Valid: strings.TrimSpace(req.Provider) != ""}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO saas_response_actions (
			id, organization_id, incident_id, finding_id, action, provider, target_type,
			target_identifier, status, approval_required, rationale, created_at, updated_at
		)
		VALUES ($1,$2,$3,NULLIF($4,''),$5::"SaasResponseActionKind",$6::"SaaSProvider",$7,$8,'PROPOSED',$9,$10,$11,$11)
	`, actionID, auth.OrganizationID, incidentID, findingID, req.Action, providerSQL, strings.TrimSpace(req.TargetType), strings.TrimSpace(req.TargetIdentifier), req.ApprovalRequired, strings.TrimSpace(req.Rationale), now); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response.insert", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE saas_incidents SET last_activity_at = $3, updated_at = $3 WHERE organization_id = $1 AND id = $2`, auth.OrganizationID, incidentID, now); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response.touch_incident", err)
	}
	if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, findingID, actionID, "RESPONSE_ACTION", "Response proposed", req.Action+" proposed for "+req.TargetIdentifier+".", auth.Email, "APERIO", map[string]any{"action": req.Action, "incidentTitle": incidentTitle}, now); err != nil {
		return saasResponseActionRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response.commit", err)
	}
	return a.getSaasResponseAction(ctx, auth.OrganizationID, actionID)
}

func (a *App) executeSaasResponseAction(ctx context.Context, auth compatAuth, req *aperiov1.ExecuteSaasResponseActionRequest) (saasResponseActionRow, error) {
	actionID := strings.TrimSpace(req.Id)
	if actionID == "" {
		return saasResponseActionRow{}, connect.NewError(connect.CodeInvalidArgument, errors.New("response action id is required"))
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response_execute.begin_tx", err)
	}
	defer tx.Rollback()
	var incidentID, findingID, action, targetIdentifier string
	if err := tx.QueryRowContext(ctx, `
		SELECT incident_id, COALESCE(finding_id, ''), action::text, target_identifier
		FROM saas_response_actions
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE
	`, auth.OrganizationID, actionID).Scan(&incidentID, &findingID, &action, &targetIdentifier); err != nil {
		return saasResponseActionRow{}, err
	}
	result := map[string]any{
		"manualOutcome":    true,
		"providerExecuted": false,
		"effect":           "manual response outcome recorded for native posture workflow",
		"note":             strings.TrimSpace(req.Note),
	}
	resultJSON, _ := json.Marshal(result)
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE saas_response_actions
		SET status = 'SUCCEEDED',
		    approved_by_user_id = COALESCE(approved_by_user_id, $3),
		    approved_at = COALESCE(approved_at, $4),
		    executed_at = $4,
		    result = $5::jsonb,
		    error_message = NULL,
		    updated_at = $4
		WHERE organization_id = $1 AND id = $2
	`, auth.OrganizationID, actionID, auth.UserID, now, string(resultJSON)); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response_execute.update", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE saas_incidents SET last_activity_at = $3, updated_at = $3 WHERE organization_id = $1 AND id = $2`, auth.OrganizationID, incidentID, now); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response_execute.touch_incident", err)
	}
	if err := insertSaasTimelineEvent(ctx, tx, auth.OrganizationID, incidentID, findingID, actionID, "RESPONSE_ACTION", "Response outcome recorded", action+" outcome recorded for "+targetIdentifier+".", auth.Email, "APERIO", result, now); err != nil {
		return saasResponseActionRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return saasResponseActionRow{}, internalServerError("saas_response_execute.commit", err)
	}
	return a.getSaasResponseAction(ctx, auth.OrganizationID, actionID)
}

func (a *App) getSaasResponseAction(ctx context.Context, organizationID, actionID string) (saasResponseActionRow, error) {
	return scanSaasResponseActionRow(a.db.QueryRowContext(ctx, saasResponseActionSelectSQL(`
		WHERE sra.organization_id = $1 AND sra.id = $2
	`), organizationID, actionID))
}

type saasTimelineExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertSaasTimelineEvent(ctx context.Context, execer saasTimelineExecer, organizationID, incidentID, findingID, responseActionID, kind, title, description, actor, source string, evidence map[string]any, occurredAt time.Time) error {
	payload, err := json.Marshal(evidence)
	if err != nil {
		return internalServerError("saas_timeline.marshal", err)
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO saas_incident_timeline_events (
			id, organization_id, incident_id, finding_id, response_action_id, kind,
			title, description, actor, source, evidence, occurred_at, created_at
		)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6::"SaasIncidentTimelineKind",$7,$8,NULLIF($9,''),$10,$11::jsonb,$12,$12)
	`, compatID("tle"), organizationID, incidentID, findingID, responseActionID, kind, title, description, actor, source, string(payload), occurredAt); err != nil {
		return internalServerError("saas_timeline.insert", err)
	}
	return nil
}

func saasCerebroContextJSON() string {
	payload := map[string]any{
		"source":          "cerebro",
		"mode":            "context-pending",
		"sourceRuntimeId": "writer-aperio-sspm",
		"findingContract": "cerebro.v1.Finding",
		"claimCount":      0,
		"graphSignals":    []map[string]any{},
		"entities":        []map[string]any{},
		"graphPaths":      []map[string]any{},
		"claimSummaries":  []map[string]any{},
		"responseHints": []string{
			"Attach Cerebro claims before executing high-impact response actions.",
		},
		"uses": []string{
			"asset criticality",
			"identity privilege",
			"owner mapping",
			"graph paths",
			"finding evidence",
			"workflow decisions",
		},
	}
	buf, _ := json.Marshal(payload)
	return string(buf)
}
