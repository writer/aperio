package bootstrap

import (
	"context"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
	"github.com/writer/aperio/internal/cerebroclient"
)

// seedSaasIncidentSetup provisions an analyst, an admin, and an open SaaS
// incident in the auth tenant. The internal helpers (rather than the Connect
// handlers) are used so the tests stay focused on the domain logic without
// minting a session cookie for each role.
func seedSaasIncidentSetup(t *testing.T, app *App, auth compatAuth) (incidentID string, analyst compatAuth, admin compatAuth) {
	t.Helper()
	analyst = seedOrgUserWithPassword(t, app, auth.OrganizationID, "SECURITY_ANALYST",
		"analyst-"+randomBase36(8)+"@example.com", "analyst-pw-12345")
	admin = seedOrgUserWithPassword(t, app, auth.OrganizationID, "ADMIN",
		"admin-"+randomBase36(8)+"@example.com", "admin-pw-12345")
	id, err := app.createSaasIncident(context.Background(), analyst, &aperiov1.CreateSaasIncidentRequest{
		Title:    "Test SaaS incident",
		Summary:  "Seeded for D&R contract tests.",
		Severity: "HIGH",
	})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	incidentID = id
	return
}

func proposeAction(t *testing.T, app *App, auth compatAuth, incidentID string, approvalRequired bool) string {
	t.Helper()
	row, err := app.proposeSaasResponseAction(context.Background(), auth, &aperiov1.ProposeSaasResponseActionRequest{
		IncidentId:       incidentID,
		Action:           "REVOKE_OAUTH_GRANT",
		Provider:         "GOOGLE_WORKSPACE",
		TargetType:       "oauth_app",
		TargetIdentifier: "vendor-app",
		Rationale:        "test rationale",
		ApprovalRequired: &approvalRequired,
	})
	if err != nil {
		t.Fatalf("propose response action: %v", err)
	}
	return row.ID
}

func TestSaasResponseActionRequiresApprovalBeforeExecute(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	incidentID, analyst, _ := seedSaasIncidentSetup(t, app, auth)
	actionID := proposeAction(t, app, analyst, incidentID, true)

	if _, err := app.executeSaasResponseAction(context.Background(), auth, &aperiov1.ExecuteSaasResponseActionRequest{Id: actionID}); err == nil {
		t.Fatalf("expected execute on PROPOSED+approval_required to fail, got success")
	} else if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", got, err)
	}
}

func TestSaasResponseActionApproverDifferentFromProposer(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	incidentID, analyst, admin := seedSaasIncidentSetup(t, app, auth)
	actionID := proposeAction(t, app, analyst, incidentID, true)

	// Self-approval by the proposer must be rejected even though the proposer
	// would otherwise have permission to approve.
	if _, err := app.approveSaasResponseAction(context.Background(), analyst, &aperiov1.ApproveSaasResponseActionRequest{Id: actionID}); err == nil {
		t.Fatalf("expected proposer self-approval to be rejected")
	} else if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", got, err)
	}

	// Approval by a different user succeeds and unblocks execution.
	if _, err := app.approveSaasResponseAction(context.Background(), admin, &aperiov1.ApproveSaasResponseActionRequest{Id: actionID}); err != nil {
		t.Fatalf("approve response action: %v", err)
	}
	executor := seedOrgUserWithPassword(t, app, auth.OrganizationID, "OWNER",
		"owner-"+randomBase36(8)+"@example.com", "owner-pw-12345")
	executed, err := app.executeSaasResponseAction(context.Background(), executor, &aperiov1.ExecuteSaasResponseActionRequest{Id: actionID})
	if err != nil {
		t.Fatalf("execute approved action: %v", err)
	}
	if executed.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED status, got %s", executed.Status)
	}
	if executed.ExecutedByID == "" {
		t.Fatalf("expected executed_by_user_id to be recorded")
	}
}

func TestSaasResponseActionRejectsReexecution(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	incidentID, analyst, _ := seedSaasIncidentSetup(t, app, auth)
	// approval not required so we can execute directly
	actionID := proposeAction(t, app, analyst, incidentID, false)
	if _, err := app.executeSaasResponseAction(context.Background(), auth, &aperiov1.ExecuteSaasResponseActionRequest{Id: actionID}); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if _, err := app.executeSaasResponseAction(context.Background(), auth, &aperiov1.ExecuteSaasResponseActionRequest{Id: actionID}); err == nil {
		t.Fatalf("expected re-execution to be rejected")
	} else if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("expected FailedPrecondition on re-execution, got %v (%v)", got, err)
	}
}

func TestSaasIncidentStatusTransitionsAreValidated(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	incidentID, _, _ := seedSaasIncidentSetup(t, app, auth)

	// OPEN -> RESOLVED is allowed.
	if _, err := app.updateSaasIncidentStatus(context.Background(), auth, &aperiov1.UpdateSaasIncidentStatusRequest{Id: incidentID, Status: "RESOLVED"}); err != nil {
		t.Fatalf("OPEN->RESOLVED: %v", err)
	}
	// RESOLVED -> CONTAINED is not allowed.
	if _, err := app.updateSaasIncidentStatus(context.Background(), auth, &aperiov1.UpdateSaasIncidentStatusRequest{Id: incidentID, Status: "CONTAINED"}); err == nil {
		t.Fatalf("expected RESOLVED->CONTAINED to be rejected")
	} else if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v (%v)", got, err)
	}
	// RESOLVED -> OPEN (re-open) is allowed and must keep resolved_at intact for auditability.
	if _, err := app.updateSaasIncidentStatus(context.Background(), auth, &aperiov1.UpdateSaasIncidentStatusRequest{Id: incidentID, Status: "OPEN"}); err != nil {
		t.Fatalf("RESOLVED->OPEN: %v", err)
	}
	row, err := app.getSaasIncidentRow(context.Background(), auth.OrganizationID, incidentID)
	if err != nil {
		t.Fatalf("fetch incident after reopen: %v", err)
	}
	if !row.ResolvedAt.Valid {
		t.Fatalf("expected resolved_at to be preserved after re-open")
	}
}

func TestSaasIncidentTenantIsolation(t *testing.T) {
	app, attacker := newTestDBApp(t)
	attacker = seedOrgAdmin(t, app, attacker.OrganizationID)
	victim := seedIsolationOrg(t, app)
	incidentID, _, _ := seedSaasIncidentSetup(t, app, victim)

	// Attacker cannot fetch a victim's incident.
	if _, err := app.GetSaasIncident(context.Background(), connect.NewRequest(&aperiov1.GetSaasIncidentRequest{Id: incidentID})); err == nil {
		t.Fatalf("expected attacker without session to be rejected")
	}

	// Attacker cannot update the victim's incident status via the helper.
	if _, err := app.updateSaasIncidentStatus(context.Background(), attacker, &aperiov1.UpdateSaasIncidentStatusRequest{Id: incidentID, Status: "RESOLVED"}); err == nil {
		t.Fatalf("expected cross-tenant status update to be rejected")
	}

	// Attacker cannot propose a response on victim's incident.
	if _, err := app.proposeSaasResponseAction(context.Background(), attacker, &aperiov1.ProposeSaasResponseActionRequest{
		IncidentId:       incidentID,
		Action:           "REVOKE_OAUTH_GRANT",
		Provider:         "GOOGLE_WORKSPACE",
		TargetType:       "oauth_app",
		TargetIdentifier: "vendor-app",
		Rationale:        "cross-tenant probe",
	}); err == nil {
		t.Fatalf("expected cross-tenant propose to be rejected")
	} else if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("expected NotFound on cross-tenant propose, got %v (%v)", got, err)
	}
}

func TestGetSaasIncidentPersistsEnrichedCerebroContext(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	ctx := context.Background()
	_, findingID := seedRemediationFixture(t, app, auth, "GITHUB")
	sourceEventID := "evt-" + randomBase36(8)
	evidence, err := json.Marshal(map[string]any{
		"sourceEventId": sourceEventID,
		"subject":       "writer/aperio",
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		UPDATE security_findings
		SET evidence = $3::jsonb
		WHERE organization_id = $1 AND id = $2
	`, auth.OrganizationID, findingID, string(evidence)); err != nil {
		t.Fatalf("seed finding evidence: %v", err)
	}
	incidentID, err := app.createSaasIncident(ctx, auth, &aperiov1.CreateSaasIncidentRequest{
		Title:      "Cerebro linked incident",
		Summary:    "Hydration should update shared context.",
		Severity:   "HIGH",
		FindingIds: []string{findingID},
	})
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}

	rootURN := "urn:cerebro:" + auth.OrganizationID + ":runtime:runtime-a:finding:" + findingID
	cerebroClient := &fakeSaasCerebroContextClient{
		claims: map[string][]cerebroclient.Claim{
			sourceEventID: {
				{
					SubjectURN:    rootURN,
					SubjectRef:    cerebroclient.EntityRef{URN: rootURN, EntityType: "finding", Label: "Public repository created"},
					Predicate:     "severity",
					ObjectValue:   "HIGH",
					ClaimType:     "attribute",
					Status:        "asserted",
					SourceEventID: sourceEventID,
				},
			},
		},
	}
	app.WithCerebroContextClient("runtime-a", cerebroClient)

	detail, err := app.getSaasIncidentDetail(ctx, auth.OrganizationID, incidentID)
	if err != nil {
		t.Fatalf("get incident detail: %v", err)
	}
	detailContext := decodeSaasCerebroContext(t, detail.Incident.CerebroContextJson)
	assertCerebroContextHydrated(t, "detail", detailContext)

	row, err := app.getSaasIncidentRow(ctx, auth.OrganizationID, incidentID)
	if err != nil {
		t.Fatalf("reload incident: %v", err)
	}
	persistedContext := decodeSaasCerebroContext(t, row.CerebroContextJSON)
	assertCerebroContextHydrated(t, "persisted row", persistedContext)

	rows, _, err := app.listSaasIncidents(ctx, auth.OrganizationID, &aperiov1.ListSaasIncidentsRequest{Limit: 10})
	if err != nil {
		t.Fatalf("list incidents: %v", err)
	}
	found := false
	for _, row := range rows {
		if row.ID != incidentID {
			continue
		}
		listContext := decodeSaasCerebroContext(t, row.CerebroContextJSON)
		assertCerebroContextHydrated(t, "list row", listContext)
		found = true
		break
	}
	if !found {
		t.Fatalf("incident %s missing from list rows", incidentID)
	}

	nextSourceEventID := "evt-" + randomBase36(8)
	evidence, err = json.Marshal(map[string]any{
		"sourceEventId": nextSourceEventID,
		"subject":       "writer/aperio",
	})
	if err != nil {
		t.Fatalf("marshal replacement evidence: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `
		UPDATE security_findings
		SET evidence = $3::jsonb
		WHERE organization_id = $1 AND id = $2
	`, auth.OrganizationID, findingID, string(evidence)); err != nil {
		t.Fatalf("replace finding evidence: %v", err)
	}
	cerebroClient.claims = map[string][]cerebroclient.Claim{}

	detail, err = app.getSaasIncidentDetail(ctx, auth.OrganizationID, incidentID)
	if err != nil {
		t.Fatalf("get incident detail after no-claim lookup: %v", err)
	}
	detailContext = decodeSaasCerebroContext(t, detail.Incident.CerebroContextJson)
	assertCerebroContextPending(t, "detail after no-claim lookup", detailContext)

	row, err = app.getSaasIncidentRow(ctx, auth.OrganizationID, incidentID)
	if err != nil {
		t.Fatalf("reload incident after no-claim lookup: %v", err)
	}
	persistedContext = decodeSaasCerebroContext(t, row.CerebroContextJSON)
	assertCerebroContextPending(t, "persisted row after no-claim lookup", persistedContext)
}

func assertCerebroContextHydrated(t *testing.T, label string, contextPayload map[string]any) {
	t.Helper()
	if contextPayload["mode"] != "claim-linked" {
		t.Fatalf("%s mode = %#v, want claim-linked", label, contextPayload["mode"])
	}
	if contextPayload["claimCount"] != float64(1) {
		t.Fatalf("%s claimCount = %#v, want 1", label, contextPayload["claimCount"])
	}
	if contextPayload["sourceRuntimeId"] != "runtime-a" {
		t.Fatalf("%s sourceRuntimeId = %#v, want runtime-a", label, contextPayload["sourceRuntimeId"])
	}
}

func assertCerebroContextPending(t *testing.T, label string, contextPayload map[string]any) {
	t.Helper()
	if contextPayload["mode"] != "context-pending" {
		t.Fatalf("%s mode = %#v, want context-pending", label, contextPayload["mode"])
	}
	if contextPayload["claimCount"] != float64(0) {
		t.Fatalf("%s claimCount = %#v, want 0", label, contextPayload["claimCount"])
	}
	for _, key := range []string{"claimSummaries", "graphSignals", "entities", "graphPaths"} {
		if got := len(contextRecords(contextPayload[key])); got != 0 {
			t.Fatalf("%s %s = %d, want 0", label, key, got)
		}
	}
	if got := len(contextRecords(contextPayload["responseHints"])); got != 1 {
		t.Fatalf("%s responseHints = %d, want 1", label, got)
	}
}

func TestSaasIncidentCreateCapsLinkedFindings(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	tooMany := make([]string, maxSaasIncidentLinkedFindings+1)
	for i := range tooMany {
		tooMany[i] = "fnd_"
	}
	if _, err := app.createSaasIncident(context.Background(), auth, &aperiov1.CreateSaasIncidentRequest{
		Title:      "Too many",
		Severity:   "MEDIUM",
		FindingIds: tooMany,
	}); err == nil {
		t.Fatalf("expected create with too many findings to be rejected")
	} else if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", got, err)
	}
}

func TestSaasResponseActionDefaultsApprovalRequiredWhenOmitted(t *testing.T) {
	app, auth := newTestDBApp(t)
	auth = seedOrgAdmin(t, app, auth.OrganizationID)
	incidentID, analyst, _ := seedSaasIncidentSetup(t, app, auth)
	// Omit ApprovalRequired entirely. A naive proto3 read would persist
	// `false` and let the proposer also execute, defeating segregation of
	// duties; we expect the server to back-fill to `true`.
	row, err := app.proposeSaasResponseAction(context.Background(), analyst, &aperiov1.ProposeSaasResponseActionRequest{
		IncidentId:       incidentID,
		Action:           "SUSPEND_USER",
		Provider:         "GOOGLE_WORKSPACE",
		TargetType:       "user",
		TargetIdentifier: "user@example.com",
		Rationale:        "test default",
	})
	if err != nil {
		t.Fatalf("propose response action: %v", err)
	}
	if !row.ApprovalRequired {
		t.Fatalf("expected approval_required to default to true, got false")
	}
}
