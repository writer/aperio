package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	connect "connectrpc.com/connect"

	"github.com/writer/aperio/internal/ingestionworker"
)

// compatListConnectorRules returns the union of built-in and custom rules
// for one integration, each annotated with enabled status. The shape the
// UI consumes is intentionally flat so the connectors page does not have
// to merge two lists client-side.
func (a *App) compatListConnectorRules(ctx context.Context, integrationID string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN", "SECURITY_ANALYST", "VIEWER"); err != nil {
		return nil, err
	}
	var provider string
	var disabledJSON string
	var metadataJSON string
	if err := a.db.QueryRowContext(ctx, `
		SELECT provider::text, COALESCE(array_to_json(disabled_checks)::text, '[]'), disabled_check_metadata::text
		FROM integration_connections
		WHERE id = $1 AND organization_id = $2
	`, integrationID, auth.OrganizationID).Scan(&provider, &disabledJSON, &metadataJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	disabled := []string{}
	_ = json.Unmarshal([]byte(disabledJSON), &disabled)
	disabled, _, _ = applyDisabledCheckExpiry(disabled, decodeDisabledCheckMetadata(metadataJSON), time.Now().UTC())
	disabledSet := map[string]struct{}{}
	for _, d := range disabled {
		disabledSet[d] = struct{}{}
	}
	// The built-in list must mirror the FULL set of FindingChecks the
	// connector definition knows about, not just the subset that has a
	// rich RuleCatalog entry. The connector-rules dialog recomputes the
	// entire disabled_checks set from this list on every toggle and posts
	// it as a wholesale replacement via compatUpdateIntegrationChecks, so
	// any check we omit here (e.g. github.deploy_key_added, slack.app_installed,
	// one_password.travel_mode_enabled — all DefaultEnabled=false and
	// seeded into disabled_checks at connect time) would be silently
	// dropped from the set on the first toggle and the check would
	// re-enable itself, generating findings the operator never opted into.
	// Where a check also has a RuleCatalog entry we prefer its richer
	// metadata (eventTypes, longer description, exact severity); otherwise
	// we fall back to the findingCheck columns.
	catalogByID := map[string]ingestionworker.RuleCatalogEntry{}
	for _, entry := range ingestionworker.RuleCatalogForProvider(provider) {
		catalogByID[entry.ID] = entry
	}
	builtIns := make([]map[string]any, 0)
	for _, check := range compatFindingChecksForProvider(provider) {
		_, off := disabledSet[check.Key]
		if entry, ok := catalogByID[check.Key]; ok {
			pack, _ := ingestionworker.DetectionPackByID(entry.PackID)
			builtIns = append(builtIns, map[string]any{
				"id":              entry.ID,
				"kind":            "built_in",
				"provider":        entry.Provider,
				"title":           entry.Title,
				"description":     entry.Description,
				"severity":        entry.Severity,
				"eventTypes":      entry.EventTypes,
				"packId":          entry.PackID,
				"packName":        pack.Name,
				"mitreTechniques": entry.MitreTechniques,
				"intent":          entry.Intent,
				"tags":            entry.Tags,
				"enabled":         !off,
			})
			continue
		}
		builtIns = append(builtIns, map[string]any{
			"id":              check.Key,
			"kind":            "built_in",
			"provider":        provider,
			"title":           check.Title,
			"description":     check.Description,
			"severity":        check.SeverityHint,
			"eventTypes":      []string{},
			"packId":          "",
			"packName":        "",
			"mitreTechniques": []string{},
			"intent":          "",
			"tags":            []string{},
			"enabled":         !off,
		})
	}
	customs, err := a.loadCustomRulesForIntegration(ctx, auth.OrganizationID, integrationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return map[string]any{"data": map[string]any{
		"integrationId": integrationID,
		"provider":      provider,
		"builtIn":       builtIns,
		"custom":        customs,
	}}, nil
}

type customRuleRow struct {
	ID           string
	Name         string
	Severity     string
	EventType    string
	SubjectField string
	Predicate    json.RawMessage
	Enabled      bool
	UpdatedAt    time.Time
}

func (a *App) loadCustomRulesForIntegration(ctx context.Context, organizationID, integrationID string) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT id, name, severity::text, event_type, subject_field, predicate, enabled, updated_at
		FROM custom_finding_rules
		WHERE organization_id = $1 AND integration_id = $2
		ORDER BY created_at ASC
	`, organizationID, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var r customRuleRow
		var predicateRaw []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Severity, &r.EventType, &r.SubjectField, &predicateRaw, &r.Enabled, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Predicate = predicateRaw
		var predicateVal any
		if len(r.Predicate) > 0 {
			_ = json.Unmarshal(r.Predicate, &predicateVal)
		}
		out = append(out, map[string]any{
			"id":           r.ID,
			"kind":         "custom",
			"name":         r.Name,
			"severity":     r.Severity,
			"eventType":    r.EventType,
			"subjectField": r.SubjectField,
			"predicate":    predicateVal,
			"enabled":      r.Enabled,
			"updatedAt":    r.UpdatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return out, rows.Err()
}

func (a *App) compatCreateCustomRule(ctx context.Context, integrationID string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	if err := a.assertIntegrationOwned(ctx, integrationID, auth.OrganizationID); err != nil {
		return nil, err
	}
	name, severity, eventType, subjectField, predicateRaw, enabled, err := parseCustomRuleBody(body)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	id := "cfr_" + randomCompatID()
	if _, err := a.db.ExecContext(ctx, `
		INSERT INTO custom_finding_rules (id, organization_id, integration_id, name, severity, event_type, subject_field, predicate, enabled, updated_at)
		VALUES ($1, $2, $3, $4, $5::"Severity", $6, $7, $8::jsonb, $9, NOW())
	`, id, auth.OrganizationID, integrationID, name, severity, eventType, subjectField, string(predicateRaw), enabled); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	a.writeCompatAudit(ctx, auth, "integration.custom_rule.create", "integration_connection", integrationID, map[string]any{
		"ruleId":       id,
		"name":         name,
		"severity":     severity,
		"eventType":    eventType,
		"subjectField": subjectField,
	})
	return map[string]any{"data": map[string]any{"id": id}}, nil
}

func (a *App) compatUpdateCustomRule(ctx context.Context, integrationID, ruleID string, body map[string]any, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	if err := a.assertIntegrationOwned(ctx, integrationID, auth.OrganizationID); err != nil {
		return nil, err
	}
	name, severity, eventType, subjectField, predicateRaw, enabled, err := parseCustomRuleBody(body)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Capture the previous enabled state so we can mirror the built-in
	// toggle's "disable auto-resolves OPEN findings" semantics. The
	// connector rules dialog explicitly promises this to operators, and
	// without it a disabled custom rule would leave its produced findings
	// stuck on dashboards forever.
	var previousEnabled bool
	if err := a.db.QueryRowContext(ctx, `
		SELECT enabled FROM custom_finding_rules
		WHERE id = $1 AND organization_id = $2 AND integration_id = $3
	`, ruleID, auth.OrganizationID, integrationID).Scan(&previousEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("custom rule not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	res, err := a.db.ExecContext(ctx, `
		UPDATE custom_finding_rules
		SET name = $1, severity = $2::"Severity", event_type = $3, subject_field = $4, predicate = $5::jsonb, enabled = $6, updated_at = NOW()
		WHERE id = $7 AND organization_id = $8 AND integration_id = $9
	`, name, severity, eventType, subjectField, string(predicateRaw), enabled, ruleID, auth.OrganizationID, integrationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("custom rule not found"))
	}
	if previousEnabled && !enabled {
		// Findings carry evidence.ruleId = "custom.<id>" (see EvaluateCustomRules
		// in internal/ingestionworker/custom_rules.go).
		resolved, err := a.autoResolveFindingsForDisabledRules(ctx, auth.OrganizationID, integrationID, []string{"custom." + ruleID}, auth.UserID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if resolved > 0 {
			a.writeCompatAudit(ctx, auth, "integration.custom_rule.auto_resolve", "integration_connection", integrationID, map[string]any{
				"ruleId":        ruleID,
				"resolvedCount": resolved,
			})
		}
	}
	a.writeCompatAudit(ctx, auth, "integration.custom_rule.update", "integration_connection", integrationID, map[string]any{
		"ruleId":  ruleID,
		"enabled": enabled,
	})
	return map[string]any{"data": map[string]any{"id": ruleID}}, nil
}

func (a *App) compatDeleteCustomRule(ctx context.Context, integrationID, ruleID string, auth compatAuth) (any, error) {
	if err := requireCompatRole(auth, "OWNER", "ADMIN"); err != nil {
		return nil, err
	}
	if err := a.assertIntegrationOwned(ctx, integrationID, auth.OrganizationID); err != nil {
		return nil, err
	}
	// Delete also implicitly stops the rule from firing, so it must match
	// the disable path and auto-resolve any OPEN findings the rule
	// produced. Run the resolve BEFORE the delete so the audit log still
	// has the rule id to reference.
	resolved, err := a.autoResolveFindingsForDisabledRules(ctx, auth.OrganizationID, integrationID, []string{"custom." + ruleID}, auth.UserID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	res, err := a.db.ExecContext(ctx, `
		DELETE FROM custom_finding_rules
		WHERE id = $1 AND organization_id = $2 AND integration_id = $3
	`, ruleID, auth.OrganizationID, integrationID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("custom rule not found"))
	}
	a.writeCompatAudit(ctx, auth, "integration.custom_rule.delete", "integration_connection", integrationID, map[string]any{
		"ruleId":        ruleID,
		"resolvedCount": resolved,
	})
	return map[string]any{"data": map[string]any{"id": ruleID}}, nil
}

func (a *App) assertIntegrationOwned(ctx context.Context, integrationID, organizationID string) error {
	var exists bool
	if err := a.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM integration_connections WHERE id = $1 AND organization_id = $2)
	`, integrationID, organizationID).Scan(&exists); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !exists {
		return connect.NewError(connect.CodeNotFound, errors.New("integration not found"))
	}
	return nil
}

// parseCustomRuleBody validates and normalizes the incoming JSON. Severity
// must be one of LOW/MEDIUM/HIGH/CRITICAL to match the Severity enum.
// eventType is uppercased so a UI typo of "external_sharing_enabled" still
// matches the producer-side mapping in MapEventType.
func parseCustomRuleBody(body map[string]any) (name, severity, eventType, subjectField string, predicate []byte, enabled bool, err error) {
	name = strings.TrimSpace(stringValueFromBody(body["name"]))
	if name == "" {
		err = errors.New("name is required")
		return
	}
	if len(name) > 160 {
		err = errors.New("name must be 160 characters or fewer")
		return
	}
	severity = strings.ToUpper(strings.TrimSpace(stringValueFromBody(body["severity"])))
	switch severity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	case "":
		severity = "MEDIUM"
	default:
		err = errors.New("severity must be LOW, MEDIUM, HIGH, or CRITICAL")
		return
	}
	eventType = strings.ToUpper(strings.TrimSpace(stringValueFromBody(body["eventType"])))
	if eventType == "" {
		err = errors.New("eventType is required")
		return
	}
	if len(eventType) > 120 {
		err = errors.New("eventType must be 120 characters or fewer")
		return
	}
	// subjectField is optional; when set, the evaluator uses it as both the
	// finding's display target and dedupe target so multiple subjects per
	// actor don't collapse via ON CONFLICT (organization_id, dedupe_key).
	subjectField = strings.TrimSpace(stringValueFromBody(body["subjectField"]))
	if len(subjectField) > 200 {
		err = errors.New("subjectField must be 200 characters or fewer")
		return
	}
	enabled = true
	if v, ok := body["enabled"].(bool); ok {
		enabled = v
	}
	predicateAny, hasPredicate := body["predicate"]
	if !hasPredicate || predicateAny == nil {
		predicate = []byte("{}")
	} else {
		predicate, err = json.Marshal(predicateAny)
		if err != nil {
			err = errors.New("predicate must be a JSON object")
			return
		}
	}
	// json.Marshal succeeds for any JSON value (scalar, array, object), so
	// without a follow-up shape check the API silently persists a 200 for
	// a rule that the evaluator can never execute (unmarshal into
	// predicateNode fails -> EvaluateCustomRules treats the error as a
	// clean skip). Reject malformed predicates here so the operator gets
	// CodeInvalidArgument up front instead of a phantom-rule UI.
	if validateErr := ingestionworker.ValidatePredicate(predicate); validateErr != nil {
		err = validateErr
		return
	}
	return
}

func stringValueFromBody(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func randomCompatID() string {
	return compatID("cfr")
}
