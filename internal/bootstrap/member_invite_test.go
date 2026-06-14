package bootstrap

import (
	"context"
	"testing"
)

func TestCompatCreateMemberReinviteUsesPersistedUserID(t *testing.T) {
	app, baseAuth := newTestDBApp(t)
	auth := seedOrgAdmin(t, app, baseAuth.OrganizationID)
	ctx := context.Background()

	email := "reinvite-" + randomBase36(10) + "@example.com"
	roleID, err := app.ensureCompatRole(ctx, auth.OrganizationID, "VIEWER")
	if err != nil {
		t.Fatalf("ensure viewer role: %v", err)
	}
	existingUserID := compatID("usr")
	if _, err := app.db.ExecContext(ctx, `
		INSERT INTO users (id, organization_id, role_id, email, display_name, is_active, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,TRUE,NOW(),NOW())
	`, existingUserID, auth.OrganizationID, roleID, email, "Existing Member"); err != nil {
		t.Fatalf("seed existing member: %v", err)
	}

	result, err := app.compatCreateMember(ctx, map[string]any{
		"email":    email,
		"roleName": "ADMIN",
	}, auth)
	if err != nil {
		t.Fatalf("compat create member re-invite: %v", err)
	}
	invitedID, _ := dataMap(t, result)["id"].(string)
	if invitedID != existingUserID {
		t.Fatalf("re-invite response id = %s, want %s", invitedID, existingUserID)
	}

	var auditTargetID string
	if err := app.db.QueryRowContext(ctx, `
		SELECT target_id
		FROM tenant_audit_logs
		WHERE organization_id = $1 AND action = 'member.invite'
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, auth.OrganizationID).Scan(&auditTargetID); err != nil {
		t.Fatalf("query member invite audit row: %v", err)
	}
	if auditTargetID != existingUserID {
		t.Fatalf("member.invite audit target_id = %s, want %s", auditTargetID, existingUserID)
	}

	var inviteTokenUserID string
	if err := app.db.QueryRowContext(ctx, `
		SELECT user_id
		FROM auth_tokens
		WHERE organization_id = $1 AND purpose = 'INVITE'
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, auth.OrganizationID).Scan(&inviteTokenUserID); err != nil {
		t.Fatalf("query invite token: %v", err)
	}
	if inviteTokenUserID != existingUserID {
		t.Fatalf("invite token user_id = %s, want %s", inviteTokenUserID, existingUserID)
	}
}
