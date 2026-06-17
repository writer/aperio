package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	aperiov1 "github.com/writer/aperio/gen/aperio/v1"
)

func (a *App) Signup(ctx context.Context, req *connect.Request[aperiov1.SignupRequest]) (*connect.Response[aperiov1.SignupResponse], error) {
	body := map[string]any{
		"organizationName":  req.Msg.OrganizationName,
		"organizationSlug":  req.Msg.OrganizationSlug,
		"notificationEmail": req.Msg.NotificationEmail,
		"ownerEmail":        req.Msg.OwnerEmail,
		"ownerDisplayName":  req.Msg.OwnerDisplayName,
		"password":          req.Msg.Password,
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/signup", body); err != nil {
		return nil, err
	}
	headers := http.Header{}
	result, err := a.compatSignup(ctx, body, headers)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.SignupResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))})
	copyCompatHeaders(response.Header(), headers)
	return response, nil
}

func (a *App) Login(ctx context.Context, req *connect.Request[aperiov1.LoginRequest]) (*connect.Response[aperiov1.LoginResponse], error) {
	body := map[string]any{
		"organizationSlug": req.Msg.OrganizationSlug,
		"email":            req.Msg.Email,
		"password":         req.Msg.Password,
		"totpCode":         req.Msg.TotpCode,
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/login", body); err != nil {
		return nil, err
	}
	headers := http.Header{}
	result, err := a.compatLogin(ctx, body, headers)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.LoginResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))})
	copyCompatHeaders(response.Header(), headers)
	return response, nil
}

func (a *App) GetCurrentSession(ctx context.Context, req *connect.Request[aperiov1.GetCurrentSessionRequest]) (*connect.Response[aperiov1.GetCurrentSessionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatSession(ctx, auth, "")
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetCurrentSessionResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) LogoutCurrentSession(ctx context.Context, req *connect.Request[aperiov1.LogoutCurrentSessionRequest]) (*connect.Response[aperiov1.LogoutCurrentSessionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1`, auth.SessionID)
	response := connect.NewResponse(&aperiov1.LogoutCurrentSessionResponse{Data: &aperiov1.DeleteResult{Ok: true}})
	response.Header().Add("Set-Cookie", expiredCompatSessionCookie())
	return response, nil
}

func (a *App) ListWorkspaces(ctx context.Context, req *connect.Request[aperiov1.ListWorkspacesRequest]) (*connect.Response[aperiov1.ListWorkspacesResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatWorkspaces(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListWorkspacesResponse{Data: workspaceMembershipsFromAny(asMap(result)["data"])}), nil
}

func (a *App) SwitchWorkspace(ctx context.Context, req *connect.Request[aperiov1.SwitchWorkspaceRequest]) (*connect.Response[aperiov1.SwitchWorkspaceResponse], error) {
	body := map[string]any{"organizationSlug": req.Msg.OrganizationSlug, "password": req.Msg.Password, "totpCode": req.Msg.TotpCode}
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/workspaces/switch", compatRateLimitBodyWithAuth(body, auth)); err != nil {
		return nil, err
	}
	headers := http.Header{}
	result, err := a.compatSwitchWorkspace(ctx, body, auth, headers)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.SwitchWorkspaceResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))})
	copyCompatHeaders(response.Header(), headers)
	return response, nil
}

func (a *App) RequestPasswordReset(ctx context.Context, req *connect.Request[aperiov1.RequestPasswordResetRequest]) (*connect.Response[aperiov1.RequestPasswordResetResponse], error) {
	body := map[string]any{"organizationSlug": req.Msg.OrganizationSlug, "email": req.Msg.Email}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/forgot-password", body); err != nil {
		return nil, err
	}
	result, err := a.compatForgotPassword(ctx, body)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.RequestPasswordResetResponse{Data: passwordResetResultFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) ResetPassword(ctx context.Context, req *connect.Request[aperiov1.ResetPasswordRequest]) (*connect.Response[aperiov1.ResetPasswordResponse], error) {
	body := map[string]any{"token": req.Msg.Token, "password": req.Msg.Password}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/reset-password", body); err != nil {
		return nil, err
	}
	headers := http.Header{}
	result, err := a.compatResetPassword(ctx, body, headers)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.ResetPasswordResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))})
	copyCompatHeaders(response.Header(), headers)
	return response, nil
}

func (a *App) AcceptInvite(ctx context.Context, req *connect.Request[aperiov1.AcceptInviteRequest]) (*connect.Response[aperiov1.AcceptInviteResponse], error) {
	body := map[string]any{"token": req.Msg.Token, "displayName": req.Msg.DisplayName, "password": req.Msg.Password}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodPost, "/api/v1/auth/invitations/accept", body); err != nil {
		return nil, err
	}
	headers := http.Header{}
	result, err := a.compatAcceptInvite(ctx, body, headers)
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&aperiov1.AcceptInviteResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))})
	copyCompatHeaders(response.Header(), headers)
	return response, nil
}

func (a *App) BeginMfaEnrollment(ctx context.Context, req *connect.Request[aperiov1.BeginMfaEnrollmentRequest]) (*connect.Response[aperiov1.BeginMfaEnrollmentResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatMFASetup(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.BeginMfaEnrollmentResponse{Data: mfaEnrollmentFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) EnableMfa(ctx context.Context, req *connect.Request[aperiov1.EnableMfaRequest]) (*connect.Response[aperiov1.EnableMfaResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatMFAEnable(ctx, map[string]any{"code": req.Msg.Code}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.EnableMfaResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) DisableMfa(ctx context.Context, req *connect.Request[aperiov1.DisableMfaRequest]) (*connect.Response[aperiov1.DisableMfaResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatMFADisable(ctx, map[string]any{"password": req.Msg.Password, "code": req.Msg.Code}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.DisableMfaResponse{Data: authSessionFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) GetTenantSettings(ctx context.Context, req *connect.Request[aperiov1.GetTenantSettingsRequest]) (*connect.Response[aperiov1.GetTenantSettingsResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatTenantSettings(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetTenantSettingsResponse{Data: tenantSettingsFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) UpdateTenantSettings(ctx context.Context, req *connect.Request[aperiov1.UpdateTenantSettingsRequest]) (*connect.Response[aperiov1.UpdateTenantSettingsResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body := map[string]any{}
	if req.Msg.Name != nil {
		body["name"] = req.Msg.GetName()
	}
	if req.Msg.NotificationEmail != nil {
		body["notificationEmail"] = req.Msg.GetNotificationEmail()
	}
	if req.Msg.DataRetentionDays != nil {
		body["dataRetentionDays"] = int(req.Msg.GetDataRetentionDays())
	}
	if req.Msg.CriticalRiskThreshold != nil {
		body["criticalRiskThreshold"] = int(req.Msg.GetCriticalRiskThreshold())
	}
	if req.Msg.DefaultSlaHours != nil {
		body["defaultSlaHours"] = int(req.Msg.GetDefaultSlaHours())
	}
	if req.Msg.AutoResolveLowSeverity != nil {
		body["autoResolveLowSeverity"] = req.Msg.GetAutoResolveLowSeverity()
	}
	if req.Msg.EnforceSsoOnly != nil {
		body["enforceSsoOnly"] = req.Msg.GetEnforceSsoOnly()
	}
	if req.Msg.WebhookAlertUrl != nil {
		body["webhookAlertUrl"] = req.Msg.GetWebhookAlertUrl()
	}
	result, err := a.compatUpdateTenantSettings(ctx, body, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.UpdateTenantSettingsResponse{Data: tenantSettingsFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) ListTenantMembers(ctx context.Context, req *connect.Request[aperiov1.ListTenantMembersRequest]) (*connect.Response[aperiov1.ListTenantMembersResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatMembers(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListTenantMembersResponse{Data: tenantMembersFromAny(asMap(result)["data"])}), nil
}

func (a *App) CreateTenantMember(ctx context.Context, req *connect.Request[aperiov1.CreateTenantMemberRequest]) (*connect.Response[aperiov1.CreateTenantMemberResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatCreateMember(ctx, map[string]any{"email": req.Msg.Email, "displayName": req.Msg.DisplayName, "roleName": req.Msg.RoleName}, auth)
	if err != nil {
		return nil, err
	}
	payload := asMap(result)
	return connect.NewResponse(&aperiov1.CreateTenantMemberResponse{
		Data:       tenantMemberFromMap(asMap(payload["data"])),
		Invitation: invitationResultFromMap(asMap(payload["invitation"])),
	}), nil
}

func (a *App) CreateMemberResetLink(ctx context.Context, req *connect.Request[aperiov1.CreateMemberResetLinkRequest]) (*connect.Response[aperiov1.CreateMemberResetLinkResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatCreateMemberReset(ctx, req.Msg.Id, auth)
	if err != nil {
		return nil, err
	}
	payload := asMap(result)
	return connect.NewResponse(&aperiov1.CreateMemberResetLinkResponse{
		Data:   tenantMemberFromMap(asMap(payload["data"])),
		Reset_: invitationResultFromMap(asMap(payload["reset"])),
	}), nil
}

func (a *App) UpdateMemberRole(ctx context.Context, req *connect.Request[aperiov1.UpdateMemberRoleRequest]) (*connect.Response[aperiov1.UpdateMemberRoleResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatUpdateMemberRole(ctx, req.Msg.Id, map[string]any{"roleName": req.Msg.RoleName}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.UpdateMemberRoleResponse{Data: tenantMemberFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) ListAuditLogs(ctx context.Context, req *connect.Request[aperiov1.ListAuditLogsRequest]) (*connect.Response[aperiov1.ListAuditLogsResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatAuditLogs(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListAuditLogsResponse{Data: auditLogsFromAny(asMap(result)["data"])}), nil
}

func (a *App) GetSecurityOverview(ctx context.Context, req *connect.Request[aperiov1.GetSecurityOverviewRequest]) (*connect.Response[aperiov1.GetSecurityOverviewResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	if err := a.compatRateLimit(ctx, req.Header(), req.Peer().Addr, http.MethodGet, securityOverviewRateLimitPath, typedRateLimitSubjectBody(auth)); err != nil {
		return nil, err
	}
	result, err := a.compatSecurityOverview(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetSecurityOverviewResponse{Data: securityOverviewFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) CreateSecurityAsset(ctx context.Context, req *connect.Request[aperiov1.CreateSecurityAssetRequest]) (*connect.Response[aperiov1.CreateSecurityAssetResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatCreateSecurityAsset(ctx, map[string]any{
		"integrationId":         req.Msg.IntegrationId,
		"ownerUserId":           req.Msg.OwnerUserId,
		"businessOwnerUserId":   req.Msg.BusinessOwnerUserId,
		"type":                  req.Msg.Type,
		"provider":              req.Msg.Provider,
		"name":                  req.Msg.Name,
		"summary":               req.Msg.Summary,
		"externalId":            req.Msg.ExternalId,
		"labels":                req.Msg.Labels,
		"criticality":           req.Msg.Criticality,
		"exposureLevel":         req.Msg.ExposureLevel,
		"ownershipStatus":       req.Msg.OwnershipStatus,
		"containsSensitiveData": req.Msg.ContainsSensitiveData,
		"isPrivileged":          req.Msg.IsPrivileged,
		"riskScore":             int(req.Msg.RiskScore),
		"lastObservedAt":        req.Msg.LastObservedAt,
	}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.CreateSecurityAssetResponse{Data: securityAssetFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) UpdateSecurityAsset(ctx context.Context, req *connect.Request[aperiov1.UpdateSecurityAssetRequest]) (*connect.Response[aperiov1.UpdateSecurityAssetResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body := map[string]any{}
	if req.Msg.IntegrationId != nil {
		body["integrationId"] = req.Msg.GetIntegrationId()
	}
	if req.Msg.OwnerUserId != nil {
		body["ownerUserId"] = req.Msg.GetOwnerUserId()
	}
	if req.Msg.BusinessOwnerUserId != nil {
		body["businessOwnerUserId"] = req.Msg.GetBusinessOwnerUserId()
	}
	if req.Msg.Type != nil {
		body["type"] = req.Msg.GetType()
	}
	if req.Msg.Provider != nil {
		body["provider"] = req.Msg.GetProvider()
	}
	if req.Msg.Name != nil {
		body["name"] = req.Msg.GetName()
	}
	if req.Msg.Summary != nil {
		body["summary"] = req.Msg.GetSummary()
	}
	if req.Msg.ExternalId != nil {
		body["externalId"] = req.Msg.GetExternalId()
	}
	if req.Msg.LabelsPresent {
		body["labels"] = req.Msg.Labels
	}
	if req.Msg.Criticality != nil {
		body["criticality"] = req.Msg.GetCriticality()
	}
	if req.Msg.ExposureLevel != nil {
		body["exposureLevel"] = req.Msg.GetExposureLevel()
	}
	if req.Msg.OwnershipStatus != nil {
		body["ownershipStatus"] = req.Msg.GetOwnershipStatus()
	}
	if req.Msg.ContainsSensitiveData != nil {
		body["containsSensitiveData"] = req.Msg.GetContainsSensitiveData()
	}
	if req.Msg.IsPrivileged != nil {
		body["isPrivileged"] = req.Msg.GetIsPrivileged()
	}
	if req.Msg.RiskScore != nil {
		body["riskScore"] = int(req.Msg.GetRiskScore())
	}
	if req.Msg.LastObservedAt != nil {
		body["lastObservedAt"] = req.Msg.GetLastObservedAt()
	}
	result, err := a.compatUpdateSecurityAsset(ctx, req.Msg.Id, body, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.UpdateSecurityAssetResponse{Data: securityAssetFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) CreateRiskException(ctx context.Context, req *connect.Request[aperiov1.CreateRiskExceptionRequest]) (*connect.Response[aperiov1.CreateRiskExceptionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatCreateRiskException(ctx, map[string]any{
		"assetId":              req.Msg.AssetId,
		"findingId":            req.Msg.FindingId,
		"title":                req.Msg.Title,
		"rationale":            req.Msg.Rationale,
		"compensatingControls": req.Msg.CompensatingControls,
		"expiresAt":            req.Msg.ExpiresAt,
	}, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.CreateRiskExceptionResponse{Data: riskExceptionFromMap(asMap(asMap(result)["data"]))}), nil
}

func (a *App) UpdateRiskException(ctx context.Context, req *connect.Request[aperiov1.UpdateRiskExceptionRequest]) (*connect.Response[aperiov1.UpdateRiskExceptionResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body := map[string]any{}
	if req.Msg.Title != nil {
		body["title"] = req.Msg.GetTitle()
	}
	if req.Msg.Rationale != nil {
		body["rationale"] = req.Msg.GetRationale()
	}
	if req.Msg.CompensatingControlsPresent {
		body["compensatingControls"] = req.Msg.CompensatingControls
	}
	if req.Msg.Status != nil {
		body["status"] = req.Msg.GetStatus()
	}
	if req.Msg.ExpiresAt != nil {
		body["expiresAt"] = req.Msg.GetExpiresAt()
	}
	result, err := a.compatUpdateRiskException(ctx, req.Msg.Id, body, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.UpdateRiskExceptionResponse{Data: riskExceptionFromMap(asMap(asMap(result)["data"]))}), nil
}

func copyCompatHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func authSessionFromMap(data map[string]any) *aperiov1.AuthSession {
	return &aperiov1.AuthSession{
		User:         authUserFromAny(data["user"]),
		Organization: authOrganizationFromAny(data["organization"]),
		AuthContext:  authContextFromAny(data["authContext"]),
	}
}

func authUserFromAny(value any) *aperiov1.AuthUser {
	switch typed := value.(type) {
	case compatSessionUser:
		return &aperiov1.AuthUser{
			Id:          typed.ID,
			Email:       typed.Email,
			DisplayName: optionalStringFromAny(typed.DisplayName),
			MfaEnabled:  typed.MFAEnabled,
			Role:        typed.Role,
		}
	case *compatSessionUser:
		if typed != nil {
			return authUserFromAny(*typed)
		}
	}
	data := asMap(value)
	return &aperiov1.AuthUser{
		Id:          stringFromAny(data["id"]),
		Email:       stringFromAny(data["email"]),
		DisplayName: optionalStringFromAny(data["displayName"]),
		MfaEnabled:  boolFromAny(data["mfaEnabled"]),
		Role:        stringFromAny(data["role"]),
	}
}

func authOrganizationFromAny(value any) *aperiov1.AuthOrganization {
	switch typed := value.(type) {
	case compatSessionOrg:
		return &aperiov1.AuthOrganization{Id: typed.ID, Name: typed.Name, Slug: typed.Slug}
	case *compatSessionOrg:
		if typed != nil {
			return authOrganizationFromAny(*typed)
		}
	}
	data := asMap(value)
	return &aperiov1.AuthOrganization{
		Id:   stringFromAny(data["id"]),
		Name: stringFromAny(data["name"]),
		Slug: stringFromAny(data["slug"]),
	}
}

func authContextFromAny(value any) *aperiov1.AuthContext {
	switch typed := value.(type) {
	case compatSessionAuthContext:
		return &aperiov1.AuthContext{
			Principal:                      typed.Principal,
			TenantId:                       typed.TenantID,
			TenantSlug:                     typed.TenantSlug,
			CredentialKind:                 typed.CredentialKind,
			AuthMode:                       typed.AuthMode,
			TokenTransport:                 typed.TokenTransport,
			CerebroResource:                typed.CerebroResource,
			AllowedTenants:                 typed.AllowedTenants,
			CerebroScopes:                  typed.CerebroScopes,
			Groups:                         typed.Groups,
			CerebroMcpResource:             typed.CerebroMCPResource,
			CerebroMcpResourceMetadataPath: typed.CerebroMCPResourceMetadataPath,
			CerebroOauthAuthorizationServerMetadataPath: typed.CerebroOAuthAuthorizationServerMetadataPath,
			CerebroMcpGrantTypes:                        typed.CerebroMCPGrantTypes,
			CerebroMcpBearerMethods:                     typed.CerebroMCPBearerMethods,
		}
	case *compatSessionAuthContext:
		if typed != nil {
			return authContextFromAny(*typed)
		}
	}
	data := asMap(value)
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.AuthContext{
		Principal:                      stringFromAny(data["principal"]),
		TenantId:                       stringFromAny(data["tenantId"]),
		TenantSlug:                     stringFromAny(data["tenantSlug"]),
		CredentialKind:                 stringFromAny(data["credentialKind"]),
		AuthMode:                       stringFromAny(data["authMode"]),
		TokenTransport:                 stringFromAny(data["tokenTransport"]),
		CerebroResource:                stringFromAny(data["cerebroResource"]),
		AllowedTenants:                 stringSliceFromAny(data["allowedTenants"]),
		CerebroScopes:                  stringSliceFromAny(data["cerebroScopes"]),
		Groups:                         stringSliceFromAny(data["groups"]),
		CerebroMcpResource:             stringFromAny(data["cerebroMcpResource"]),
		CerebroMcpResourceMetadataPath: stringFromAny(data["cerebroMcpResourceMetadataPath"]),
		CerebroOauthAuthorizationServerMetadataPath: stringFromAny(data["cerebroOauthAuthorizationServerMetadataPath"]),
		CerebroMcpGrantTypes:                        stringSliceFromAny(data["cerebroMcpGrantTypes"]),
		CerebroMcpBearerMethods:                     stringSliceFromAny(data["cerebroMcpBearerMethods"]),
	}
}

func workspaceMembershipsFromAny(value any) []*aperiov1.WorkspaceMembership {
	items := anyList(value)
	out := make([]*aperiov1.WorkspaceMembership, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.WorkspaceMembership{
			Id:      stringFromAny(data["id"]),
			Name:    stringFromAny(data["name"]),
			Slug:    stringFromAny(data["slug"]),
			Role:    stringFromAny(data["role"]),
			Current: boolFromAny(data["current"]),
		})
	}
	return out
}

func passwordResetResultFromMap(data map[string]any) *aperiov1.PasswordResetResult {
	return &aperiov1.PasswordResetResult{
		Accepted:         boolFromAny(data["accepted"]),
		Delivery:         stringFromAny(data["delivery"]),
		ResetUrl:         stringFromAny(data["resetUrl"]),
		ExpiresAt:        stringFromAny(data["expiresAt"]),
		OrganizationName: stringFromAny(data["organizationName"]),
	}
}

func mfaEnrollmentFromMap(data map[string]any) *aperiov1.MfaEnrollment {
	return &aperiov1.MfaEnrollment{
		Secret:     stringFromAny(data["secret"]),
		OtpauthUrl: stringFromAny(data["otpauthUrl"]),
	}
}

func tenantSettingsFromMap(data map[string]any) *aperiov1.TenantSettings {
	return &aperiov1.TenantSettings{
		Id:                     stringFromAny(data["id"]),
		Name:                   stringFromAny(data["name"]),
		Slug:                   stringFromAny(data["slug"]),
		NotificationEmail:      optionalStringFromAny(data["notificationEmail"]),
		DataRetentionDays:      int32(intValue(data["dataRetentionDays"])),
		CriticalRiskThreshold:  int32(intValue(data["criticalRiskThreshold"])),
		DefaultSlaHours:        int32(intValue(data["defaultSlaHours"])),
		AutoResolveLowSeverity: boolFromAny(data["autoResolveLowSeverity"]),
		EnforceSsoOnly:         boolFromAny(data["enforceSsoOnly"]),
		WebhookAlertUrl:        optionalStringFromAny(data["webhookAlertUrl"]),
		CreatedAt:              stringFromAny(data["createdAt"]),
		UpdatedAt:              stringFromAny(data["updatedAt"]),
	}
}

func tenantMembersFromAny(value any) []*aperiov1.TenantMember {
	items := anyList(value)
	out := make([]*aperiov1.TenantMember, 0, len(items))
	for _, item := range items {
		out = append(out, tenantMemberFromMap(asMap(item)))
	}
	return out
}

func tenantMemberFromMap(data map[string]any) *aperiov1.TenantMember {
	return &aperiov1.TenantMember{
		Id:                     stringFromAny(data["id"]),
		Email:                  stringFromAny(data["email"]),
		DisplayName:            optionalStringFromAny(data["displayName"]),
		IsActive:               boolFromAny(data["isActive"]),
		MfaEnabled:             boolFromAny(data["mfaEnabled"]),
		LastLoginAt:            optionalStringFromAny(data["lastLoginAt"]),
		IsBreakGlass:           boolFromAny(data["isBreakGlass"]),
		Role:                   stringFromAny(data["role"]),
		AuthState:              stringFromAny(data["authState"]),
		PendingActionExpiresAt: optionalStringFromAny(data["pendingActionExpiresAt"]),
		CreatedAt:              stringFromAny(data["createdAt"]),
	}
}

func invitationResultFromMap(data map[string]any) *aperiov1.InvitationResult {
	return &aperiov1.InvitationResult{
		Delivery:  stringFromAny(data["delivery"]),
		Url:       stringFromAny(data["url"]),
		ExpiresAt: stringFromAny(data["expiresAt"]),
	}
}

func auditLogsFromAny(value any) []*aperiov1.AuditLogEntry {
	items := anyList(value)
	out := make([]*aperiov1.AuditLogEntry, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		metadataJSON := "{}"
		if metadata, ok := data["metadata"]; ok && metadata != nil {
			if bytes, err := json.Marshal(metadata); err == nil {
				metadataJSON = string(bytes)
			}
		}
		out = append(out, &aperiov1.AuditLogEntry{
			Id:           stringFromAny(data["id"]),
			Action:       stringFromAny(data["action"]),
			TargetType:   stringFromAny(data["targetType"]),
			TargetId:     stringFromAny(data["targetId"]),
			Actor:        stringFromAny(data["actor"]),
			CreatedAt:    stringFromAny(data["createdAt"]),
			MetadataJson: metadataJSON,
		})
	}
	return out
}

func securityOverviewFromMap(data map[string]any) *aperiov1.SecurityOverview {
	graph := asMap(data["graph"])
	return &aperiov1.SecurityOverview{
		Summary:               securityOverviewSummaryFromMap(asMap(data["summary"])),
		Identities:            securityIdentitiesFromAny(data["identities"]),
		Graph:                 securityGraphFromMap(graph),
		OauthApps:             securityAssetsFromAny(data["oauthApps"]),
		DataAssets:            securityAssetsFromAny(data["dataAssets"]),
		AttackPaths:           attackPathsFromAny(data["attackPaths"]),
		OwnershipGaps:         securityAssetsFromAny(data["ownershipGaps"]),
		Exceptions:            riskExceptionsFromAny(data["exceptions"]),
		DomainWideDelegations: domainWideDelegationsFromAny(data["domainWideDelegations"]),
		CerebroContext:        securityCerebroContextFromMap(asMap(data["cerebroContext"])),
	}
}

func securityOverviewSummaryFromMap(data map[string]any) *aperiov1.SecurityOverviewSummary {
	return &aperiov1.SecurityOverviewSummary{
		PrivilegedIdentities:      int32(intValue(data["privilegedIdentities"])),
		AdminIdentitiesWithoutMfa: int32(intValue(data["adminIdentitiesWithoutMfa"])),
		RiskyOauthApps:            int32(intValue(data["riskyOauthApps"])),
		ExposedDataAssets:         int32(intValue(data["exposedDataAssets"])),
		UnownedAssets:             int32(intValue(data["unownedAssets"])),
		ActiveExceptions:          int32(intValue(data["activeExceptions"])),
		TopBlastRadiusScore:       int32(intValue(data["topBlastRadiusScore"])),
	}
}

func securityCerebroContextFromMap(data map[string]any) *aperiov1.SecurityCerebroContext {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.SecurityCerebroContext{
		Source:           stringFromAny(data["source"]),
		Mode:             stringFromAny(data["mode"]),
		SourceRuntimeId:  stringFromAny(data["sourceRuntimeId"]),
		FindingContract:  stringFromAny(data["findingContract"]),
		ClaimCount:       int32(intValue(data["claimCount"])),
		GraphSignalCount: int32(intValue(data["graphSignalCount"])),
		EntityCount:      int32(intValue(data["entityCount"])),
		GraphPathCount:   int32(intValue(data["graphPathCount"])),
		Mcp:              securityCerebroMCPContextFromMap(asMap(data["mcp"])),
		ResponseHints:    stringSliceFromAny(data["responseHints"]),
	}
}

func securityCerebroMCPContextFromMap(data map[string]any) *aperiov1.SecurityCerebroMCPContext {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.SecurityCerebroMCPContext{
		Server:            stringFromAny(data["server"]),
		ResourceUri:       stringFromAny(data["resourceUri"]),
		Resource:          stringFromAny(data["resource"]),
		Tools:             stringSliceFromAny(data["tools"]),
		ResourceTemplates: cerebroMCPResourceTemplatesFromAny(data["resourceTemplates"]),
	}
}

func cerebroMCPResourceTemplatesFromAny(value any) []*aperiov1.CerebroMCPResourceTemplate {
	items := anyList(value)
	out := make([]*aperiov1.CerebroMCPResourceTemplate, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		uriTemplate := stringFromAny(data["uriTemplate"])
		if uriTemplate == "" {
			continue
		}
		out = append(out, &aperiov1.CerebroMCPResourceTemplate{
			UriTemplate: uriTemplate,
			Name:        stringFromAny(data["name"]),
			Description: stringFromAny(data["description"]),
			MimeType:    stringFromAny(data["mimeType"]),
		})
	}
	return out
}

func securityIdentitiesFromAny(value any) []*aperiov1.SecurityIdentity {
	items := anyList(value)
	out := make([]*aperiov1.SecurityIdentity, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.SecurityIdentity{
			Id:               stringFromAny(data["id"]),
			EntityId:         stringFromAny(data["entityId"]),
			Kind:             stringFromAny(data["kind"]),
			Name:             stringFromAny(data["name"]),
			Email:            optionalStringFromAny(data["email"]),
			Provider:         optionalStringFromAny(data["provider"]),
			Integration:      findingIntegrationFromMap(asMap(data["integration"])),
			Role:             stringFromAny(data["role"]),
			Privileged:       boolFromAny(data["privileged"]),
			MfaEnabled:       boolFromAny(data["mfaEnabled"]),
			MfaEnabledState:  optionalBoolFromAny(data["mfaEnabled"]),
			Status:           stringFromAny(data["status"]),
			IsExternal:       boolFromAny(data["isExternal"]),
			LastObservedAt:   optionalStringFromAny(data["lastObservedAt"]),
			LinkedAssetCount: int32(intValue(data["linkedAssetCount"])),
			RiskScore:        int32(intValue(data["riskScore"])),
		})
	}
	return out
}

func securityGraphFromMap(data map[string]any) *aperiov1.SecurityGraph {
	return &aperiov1.SecurityGraph{
		Nodes: securityGraphNodesFromAny(data["nodes"]),
		Edges: securityGraphEdgesFromAny(data["edges"]),
	}
}

func securityGraphNodesFromAny(value any) []*aperiov1.SecurityGraphNode {
	items := anyList(value)
	out := make([]*aperiov1.SecurityGraphNode, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.SecurityGraphNode{
			Id:            stringFromAny(data["id"]),
			Label:         stringFromAny(data["label"]),
			Kind:          stringFromAny(data["kind"]),
			RiskScore:     int32(intValue(data["riskScore"])),
			Privileged:    boolFromAny(data["privileged"]),
			ExposureLevel: stringFromAny(data["exposureLevel"]),
			Criticality:   stringFromAny(data["criticality"]),
		})
	}
	return out
}

func securityGraphEdgesFromAny(value any) []*aperiov1.SecurityGraphEdge {
	items := anyList(value)
	out := make([]*aperiov1.SecurityGraphEdge, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.SecurityGraphEdge{
			Id:               stringFromAny(data["id"]),
			SourceId:         stringFromAny(data["sourceId"]),
			TargetId:         stringFromAny(data["targetId"]),
			RelationshipType: stringFromAny(data["relationshipType"]),
		})
	}
	return out
}

func attackPathsFromAny(value any) []*aperiov1.AttackPath {
	items := anyList(value)
	out := make([]*aperiov1.AttackPath, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.AttackPath{
			Id:            stringFromAny(data["id"]),
			Title:         stringFromAny(data["title"]),
			Score:         int32(intValue(data["score"])),
			FindingTitle:  stringFromAny(data["findingTitle"]),
			EntryPoint:    stringFromAny(data["entryPoint"]),
			Target:        stringFromAny(data["target"]),
			Owner:         stringFromAny(data["owner"]),
			ExposureLevel: stringFromAny(data["exposureLevel"]),
			Criticality:   stringFromAny(data["criticality"]),
			Reason:        stringFromAny(data["reason"]),
			Path:          stringSlice(data["path"]),
		})
	}
	return out
}

func domainWideDelegationsFromAny(value any) []*aperiov1.DomainWideDelegation {
	items := anyList(value)
	out := make([]*aperiov1.DomainWideDelegation, 0, len(items))
	for _, item := range items {
		data := asMap(item)
		out = append(out, &aperiov1.DomainWideDelegation{
			IntegrationId:             stringFromAny(data["integrationId"]),
			Provider:                  stringFromAny(data["provider"]),
			DisplayName:               stringFromAny(data["displayName"]),
			WorkspaceDomain:           stringFromAny(data["workspaceDomain"]),
			ServiceAccountClientEmail: optionalStringFromAny(data["serviceAccountClientEmail"]),
			Scopes:                    stringSlice(data["scopes"]),
			Status:                    stringFromAny(data["status"]),
			IntegrationStatus:         stringFromAny(data["integrationStatus"]),
			Mode:                      stringFromAny(data["mode"]),
			OpenMailboxFindings:       int32(intValue(data["openMailboxFindings"])),
			LastSyncAt:                optionalStringFromAny(data["lastSyncAt"]),
			ConfiguredAt:              stringFromAny(data["configuredAt"]),
		})
	}
	return out
}

func securityAssetsFromAny(value any) []*aperiov1.SecurityAsset {
	items := anyList(value)
	out := make([]*aperiov1.SecurityAsset, 0, len(items))
	for _, item := range items {
		out = append(out, securityAssetFromMap(asMap(item)))
	}
	return out
}

func securityAssetFromMap(data map[string]any) *aperiov1.SecurityAsset {
	return &aperiov1.SecurityAsset{
		Id:                    stringFromAny(data["id"]),
		Type:                  stringFromAny(data["type"]),
		Provider:              optionalStringFromAny(data["provider"]),
		Name:                  stringFromAny(data["name"]),
		Summary:               optionalStringFromAny(data["summary"]),
		ExternalId:            optionalStringFromAny(anyKey(data, "externalId", "external_id")),
		Labels:                stringSlice(data["labels"]),
		Criticality:           stringFromAny(data["criticality"]),
		ExposureLevel:         stringFromAny(anyKey(data, "exposureLevel", "exposure_level")),
		OwnershipStatus:       stringFromAny(anyKey(data, "ownershipStatus", "ownership_status")),
		ContainsSensitiveData: boolFromAny(anyKey(data, "containsSensitiveData", "contains_sensitive_data")),
		IsPrivileged:          boolFromAny(anyKey(data, "isPrivileged", "is_privileged")),
		RiskScore:             int32(intValue(anyKey(data, "riskScore", "risk_score"))),
		LastObservedAt:        optionalStringFromAny(anyKey(data, "lastObservedAt", "last_observed_at")),
		CreatedAt:             stringFromAny(anyKey(data, "createdAt", "created_at")),
		UpdatedAt:             stringFromAny(anyKey(data, "updatedAt", "updated_at")),
		Integration:           findingIntegrationFromMap(asMap(data["integration"])),
		Owner:                 securityPrincipalFromMap(asMap(data["owner"])),
		BusinessOwner:         securityPrincipalFromMap(asMap(anyKey(data, "businessOwner", "business_owner"))),
		OpenFindingCount:      int32(intValue(anyKey(data, "openFindingCount", "open_finding_count"))),
		ActiveExceptionCount:  int32(intValue(anyKey(data, "activeExceptionCount", "active_exception_count"))),
	}
}

func findingIntegrationFromMap(data map[string]any) *aperiov1.FindingIntegration {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.FindingIntegration{
		Id:          stringFromAny(data["id"]),
		Provider:    stringFromAny(data["provider"]),
		DisplayName: stringFromAny(anyKey(data, "displayName", "display_name")),
	}
}

func securityPrincipalFromMap(data map[string]any) *aperiov1.SecurityPrincipal {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.SecurityPrincipal{
		Id:          stringFromAny(data["id"]),
		Email:       stringFromAny(data["email"]),
		DisplayName: optionalStringFromAny(anyKey(data, "displayName", "display_name")),
	}
}

func riskExceptionsFromAny(value any) []*aperiov1.RiskException {
	items := anyList(value)
	out := make([]*aperiov1.RiskException, 0, len(items))
	for _, item := range items {
		out = append(out, riskExceptionFromMap(asMap(item)))
	}
	return out
}

func riskExceptionFromMap(data map[string]any) *aperiov1.RiskException {
	return &aperiov1.RiskException{
		Id:                   stringFromAny(data["id"]),
		Title:                stringFromAny(data["title"]),
		Rationale:            stringFromAny(data["rationale"]),
		CompensatingControls: stringSlice(anyKey(data, "compensatingControls", "compensating_controls")),
		Status:               stringFromAny(data["status"]),
		ExpiresAt:            optionalStringFromAny(anyKey(data, "expiresAt", "expires_at")),
		ApprovedAt:           optionalStringFromAny(anyKey(data, "approvedAt", "approved_at")),
		CreatedAt:            stringFromAny(anyKey(data, "createdAt", "created_at")),
		UpdatedAt:            stringFromAny(anyKey(data, "updatedAt", "updated_at")),
		Asset:                riskExceptionAssetFromMap(asMap(data["asset"])),
		Finding:              riskExceptionFindingFromMap(asMap(data["finding"])),
		CreatedBy:            securityPrincipalFromMap(asMap(anyKey(data, "createdBy", "created_by"))),
		ApprovedBy:           securityPrincipalFromMap(asMap(anyKey(data, "approvedBy", "approved_by"))),
	}
}

func riskExceptionAssetFromMap(data map[string]any) *aperiov1.RiskExceptionAsset {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.RiskExceptionAsset{
		Id:   stringFromAny(data["id"]),
		Name: stringFromAny(data["name"]),
		Type: stringFromAny(data["type"]),
	}
}

func riskExceptionFindingFromMap(data map[string]any) *aperiov1.RiskExceptionFinding {
	if len(data) == 0 {
		return nil
	}
	return &aperiov1.RiskExceptionFinding{
		Id:       stringFromAny(data["id"]),
		Title:    stringFromAny(data["title"]),
		Severity: stringFromAny(data["severity"]),
		Status:   stringFromAny(data["status"]),
	}
}

func anyList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []map[string]any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []map[string]string:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	}
	return []any{}
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, len(typed))
		copy(out, typed)
		return out
	}
	items := anyList(value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value := stringFromAny(item); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func anyKey(data map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			return value
		}
	}
	return nil
}

func executiveReportFromAny(value any) *aperiov1.ExecutiveReport {
	data := asMap(value)
	if len(data) == 0 {
		return nil
	}
	kpiJSON := "{}"
	if kpi, ok := data["kpiSnapshot"]; ok && kpi != nil {
		if bytes, err := json.Marshal(kpi); err == nil {
			kpiJSON = string(bytes)
		}
	}
	return &aperiov1.ExecutiveReport{
		Id:                stringFromAny(data["id"]),
		Template:          stringFromAny(data["template"]),
		Period:            stringFromAny(data["period"]),
		PeriodStart:       stringFromAny(data["periodStart"]),
		PeriodEnd:         stringFromAny(data["periodEnd"]),
		Title:             stringFromAny(data["title"]),
		Summary:           stringFromAny(data["summary"]),
		Status:            stringFromAny(data["status"]),
		KpiSnapshotJson:   kpiJSON,
		HasHtml:           boolFromAny(data["hasHtml"]),
		HasPdf:            boolFromAny(data["hasPdf"]),
		HtmlUrl:           stringFromAny(data["htmlUrl"]),
		PdfUrl:            stringFromAny(data["pdfUrl"]),
		CreatedAt:         stringFromAny(data["createdAt"]),
		UpdatedAt:         stringFromAny(data["updatedAt"]),
		GeneratedAt:       stringFromAny(data["generatedAt"]),
		ErrorMessage:      stringFromAny(data["errorMessage"]),
		RequestedByUserId: stringFromAny(data["requestedByUser"]),
	}
}

func executiveReportsFromAny(value any) []*aperiov1.ExecutiveReport {
	items := anyList(value)
	out := make([]*aperiov1.ExecutiveReport, 0, len(items))
	for _, item := range items {
		report := executiveReportFromAny(item)
		if report != nil {
			out = append(out, report)
		}
	}
	return out
}

func (a *App) ListExecutiveReports(ctx context.Context, req *connect.Request[aperiov1.ListExecutiveReportsRequest]) (*connect.Response[aperiov1.ListExecutiveReportsResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatListExecutiveReports(ctx, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.ListExecutiveReportsResponse{
		Data: executiveReportsFromAny(asMap(result)["data"]),
	}), nil
}

func (a *App) GetExecutiveReport(ctx context.Context, req *connect.Request[aperiov1.GetExecutiveReportRequest]) (*connect.Response[aperiov1.GetExecutiveReportResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatGetExecutiveReport(ctx, req.Msg.Id, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.GetExecutiveReportResponse{
		Data: executiveReportFromAny(asMap(result)["data"]),
	}), nil
}

func (a *App) CreateExecutiveReport(ctx context.Context, req *connect.Request[aperiov1.CreateExecutiveReportRequest]) (*connect.Response[aperiov1.CreateExecutiveReportResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	body := map[string]any{
		"period":      req.Msg.Period,
		"title":       req.Msg.Title,
		"periodStart": req.Msg.PeriodStart,
		"periodEnd":   req.Msg.PeriodEnd,
		"template":    req.Msg.Template,
	}
	result, err := a.compatCreateExecutiveReport(ctx, body, auth)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&aperiov1.CreateExecutiveReportResponse{
		Data: executiveReportFromAny(asMap(result)["data"]),
	}), nil
}

func (a *App) DeleteExecutiveReport(ctx context.Context, req *connect.Request[aperiov1.DeleteExecutiveReportRequest]) (*connect.Response[aperiov1.DeleteExecutiveReportResponse], error) {
	auth, err := a.compatAuthFromSession(ctx, req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthorized"))
	}
	result, err := a.compatDeleteExecutiveReport(ctx, req.Msg.Id, auth)
	if err != nil {
		return nil, err
	}
	data := asMap(asMap(result)["data"])
	return connect.NewResponse(&aperiov1.DeleteExecutiveReportResponse{
		Deleted: boolFromAny(data["deleted"]),
	}), nil
}
