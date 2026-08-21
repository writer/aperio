package ingestionworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/aperio/internal/cerebrofanout"
	"github.com/writer/aperio/internal/observability"
	"github.com/writer/aperio/internal/runtimeutil"
	"github.com/writer/aperio/internal/siemdispatcher"
	"github.com/writer/aperio/internal/telemetry"
)

const leaseDuration = 5 * time.Minute

var (
	errIngestionLeaseLost                 = errors.New("ingestion job lease lost")
	errIntegrationNotConnected            = errors.New("integration not found or not connected")
	errIntegrationCredentialMissing       = errors.New("integration credential is missing")
	errIntegrationCredentialUnavailable   = errors.New("integration credential is unavailable")
	errIntegrationCredentialIntegrity     = errors.New("integration credential failed integrity validation")
	errIntegrationConfigurationIncomplete = errors.New("integration configuration is incomplete")
	errUnsupportedIngestionWork           = errors.New("unsupported ingestion work")
	errIngestionPayloadNotObject          = errors.New("ingestion payload must be a JSON object")
)

var supportedIngestionEventTypes = map[string][]string{
	"GITHUB": {
		"PUBLIC_REPOSITORY_CREATED",
		"repository.publicized",
		"REPOSITORY_PRIVATE",
		"REPOSITORY_PRIVATEIZED",
		"REPOSITORY_VISIBILITY_CHANGED",
		"repository.private",
		"repository.privateized",
		"repository.visibility_changed",
		"BRANCH_PROTECTION_DISABLED",
		"BRANCH_PROTECTION_RULE_DELETED",
		"BRANCH_PROTECTION_RULE_UPDATED",
		"branch_protection.disabled",
		"branch_protection_rule.deleted",
		"branch_protection_rule.updated",
		"OAUTH_APP_INSTALLED",
		"GITHUB_APP_INSTALLED",
		"ORG_OAUTH_APP_ACCESS_APPROVED",
		"oauth_app.installed",
		"github_app.installed",
		"org.oauth_app_access_approved",
		"DEPLOY_KEY_ADDED",
		"DEPLOY_KEY_CREATED",
		"deploy_key.added",
		"deploy_key.created",
	},
	"SLACK": {
		"MFA_DISABLED",
		"TWO_FACTOR_AUTH_DISABLED",
		"mfa.disabled",
		"two-factor auth disabled",
		"MFA_ENABLED",
		"TWO_FACTOR_AUTH_ENABLED",
		"mfa.enabled",
		"two-factor auth enabled",
		"EXTERNAL_SHARED_CHANNEL_CREATED",
		"SHARED_CHANNEL_INVITE_ACCEPTED",
		"external_shared_channel.created",
		"shared_channel_invite.accepted",
		"WORKSPACE_INVITE_LINK_ENABLED",
		"INVITE_LINK_CREATED",
		"workspace_invite_link.enabled",
		"invite_link.created",
		"APP_INSTALLED",
		"APP_APPROVED",
		"APP_SCOPES_APPROVED",
		"app.installed",
		"app.approved",
		"app_scopes.approved",
	},
	"OKTA": {
		"USER_ACCOUNT_PRIVILEGE_GRANT",
		"USER_ACCOUNT_PRIVILEGE_GRANTED",
		"ADMIN_ROLE_ASSIGNED",
		"ROLE_ASSIGNMENT_CREATED",
		"user.account.privilege.grant",
		"user.account.privilege.granted",
		"admin.role.assigned",
		"role.assignment.created",
		"USER_MFA_FACTOR_RESET",
		"USER_MFA_FACTOR_RESET_ALL",
		"MFA_FACTOR_RESET",
		"user.mfa.factor.reset",
		"user.mfa.factor.reset_all",
		"mfa.factor.reset",
		"POLICY_LIFECYCLE_UPDATE",
		"PASSWORD_POLICY_UPDATED",
		"policy.lifecycle.update",
		"password.policy.updated",
		"SECURITY_THREAT_DETECTED",
		"USER_AUTHENTICATION_FAILED",
		"USER_SESSION_START",
		"security.threat.detected",
		"user.authentication.failed",
		"user.session.start",
	},
	"GOOGLE_WORKSPACE": {
		"EXTERNAL_SHARING_ENABLED",
		"external.sharing.enabled",
		"EXTERNAL_SHARING_DISABLED",
		"DRIVE_FILE_VISIBILITY_CHANGED",
		"DRIVE_FILE_PRIVATE",
		"external.sharing.disabled",
		"drive.file.visibility.changed",
		"drive.file.private",
		"SUPER_ADMIN_GRANTED",
		"super.admin.granted",
		"ADMIN_ROLE_GRANTED",
		"admin.role.granted",
		"RISKY_OAUTH_GRANT",
		"risky.oauth.grant",
		"ADMIN_MFA_NOT_ENFORCED",
		"admin.mfa.not.enforced",
		"ADMIN_EXTERNAL_RECOVERY_EMAIL",
		"admin.external.recovery.email",
		"EMAIL_FORWARDING_ENABLED",
		"email.forwarding.enabled",
		"MAILBOX_DELEGATION_GRANTED",
		"mailbox.delegation.granted",
		"LEGACY_MAIL_AUTH_USED",
		"legacy.mail.auth.used",
		"FORWARDING_DELEGATE_SEND_AS_COMBO",
		"forwarding.delegate.send.as.combo",
	},
	"MICROSOFT_365": {
		"GUEST_USER_INVITED",
		"GUEST_INVITATION_CREATED",
		"USER_INVITED",
		"guest_user.invited",
		"guest_invitation.created",
		"user.invited",
		"CONDITIONAL_ACCESS_DISABLED",
		"CONDITIONAL_ACCESS_POLICY_DISABLED",
		"CONDITIONAL_ACCESS_POLICY_UPDATED",
		"conditional_access.disabled",
		"conditional_access_policy.disabled",
		"conditional_access_policy.updated",
		"GLOBAL_ADMIN_GRANTED",
		"DIRECTORY_ROLE_ASSIGNED",
		"ROLE_ASSIGNMENT_CREATED",
		"global_admin.granted",
		"directory_role.assigned",
		"role_assignment.created",
	},
	"ATLASSIAN": {
		"ANONYMOUS_ACCESS_ENABLED",
		"PUBLIC_ACCESS_ENABLED",
		"anonymous_access.enabled",
		"public_access.enabled",
		"PUBLIC_SPACE_CREATED",
		"SPACE_PUBLIC_ACCESS_ENABLED",
		"PROJECT_PUBLIC_ACCESS_ENABLED",
		"public_space.created",
		"space_public_access.enabled",
		"project_public_access.enabled",
		"ORG_ADMIN_GRANTED",
		"SITE_ADMIN_GRANTED",
		"PRODUCT_ADMIN_GRANTED",
		"org_admin.granted",
		"site_admin.granted",
		"product_admin.granted",
	},
	"SALESFORCE": {
		"ADMIN_PROFILE_ASSIGNED",
		"PERMISSION_SET_ASSIGNED",
		"PROFILE_ASSIGNED",
		"admin_profile.assigned",
		"permission_set.assigned",
		"profile.assigned",
		"CONNECTED_APP_POLICY_WEAKENED",
		"CONNECTED_APP_UPDATED",
		"connected_app_policy.weakened",
		"connected_app.updated",
		"REPORT_EXPORTED",
		"BULK_DATA_EXPORT",
		"DATA_EXPORT_DOWNLOADED",
		"report.exported",
		"bulk_data.export",
		"data_export.downloaded",
	},
}

type JobPayload struct {
	OrganizationID string         `json:"organizationId"`
	IntegrationID  string         `json:"integrationId"`
	Provider       string         `json:"provider"`
	EventType      string         `json:"eventType"`
	Source         string         `json:"source"`
	Actor          string         `json:"actor,omitempty"`
	OccurredAt     time.Time      `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

type Finding struct {
	RuleID           string
	RuleVersion      string
	Title            string
	Description      string
	Severity         string
	RiskScore        int
	RemediationSteps []string
	Target           string
	DedupeTarget     string
	Evidence         map[string]any
	// Tags is the canonical cross-provider categorization of the
	// finding (see internal/ingestionworker/tags.go). Always normalized
	// at persistence time so callers can pass duplicates or mixed case
	// without worrying about the on-disk shape.
	Tags []string
}

type persistedFinding struct {
	ID             string
	Status         string
	PreviousStatus string
}

type Result struct {
	Processed int
	Succeeded int
	Failed    int
}

type Worker struct {
	db             *sql.DB
	leaseOwner     string
	eventPublisher IngestionEventPublisher
	cerebroFanout  CerebroFindingFanout
}

type CerebroFindingFanout interface {
	FanoutFinding(context.Context, cerebrofanout.FindingPayload) (cerebrofanout.Result, error)
}

type IngestionJobLifecycleEvent struct {
	JobID          string
	OrganizationID string
	IntegrationID  string
	Provider       string
	EventType      string
	Source         string
	Actor          string
	Status         string
	Attempts       int
	SourceEventID  string
	OccurredAt     time.Time
	Payload        json.RawMessage
}

type FindingLifecycleEvent struct {
	FindingID      string
	OrganizationID string
	IntegrationID  string
	PreviousStatus string
	NextStatus     string
	OccurredAt     time.Time
	ResolutionNote string
}

type IngestionEventPublisher interface {
	PublishIngestionJobLifecycle(context.Context, IngestionJobLifecycleEvent) error
	PublishFindingLifecycle(context.Context, FindingLifecycleEvent) error
}

type noopIngestionEventPublisher struct{}

func (noopIngestionEventPublisher) PublishIngestionJobLifecycle(context.Context, IngestionJobLifecycleEvent) error {
	return nil
}

func (noopIngestionEventPublisher) PublishFindingLifecycle(context.Context, FindingLifecycleEvent) error {
	return nil
}

type job struct {
	ID             string
	OrganizationID string
	IntegrationID  string
	Provider       string
	EventType      string
	Source         string
	Actor          sql.NullString
	OccurredAt     time.Time
	Payload        json.RawMessage
	Attempts       int
	MaxAttempts    int
}

type integrationConfig struct {
	ID                                   string
	OrganizationID                       string
	Provider                             string
	ExternalAccountID                    string
	DisabledChecks                       []string
	SeverityOverrides                    map[string]string
	EncryptedAccessToken                 string
	EncryptedRefreshToken                sql.NullString
	EncryptedWebhookSecret               sql.NullString
	GoogleMailboxScanClientEmail         sql.NullString
	EncryptedGoogleMailboxScanPrivateKey sql.NullString
}

func New(db *sql.DB) *Worker {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	return &Worker{
		db:             db,
		leaseOwner:     fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), randomID()),
		eventPublisher: NewEnvEventPublisher(),
	}
}

func (w *Worker) WithCerebroFanout(fanout CerebroFindingFanout) *Worker {
	w.cerebroFanout = fanout
	return w
}

func Evaluate(payload JobPayload, disabledChecks []string) []Finding {
	return EvaluateWithSeverityOverrides(payload, disabledChecks, nil)
}

// EvaluateWithSeverityOverrides preserves the existing disabled_checks
// contract while allowing a tenant policy layer to lower or raise a rule's
// severity. The declarative migration slice is authoritative when its pack
// compiles; hardcoded rules remain the compatibility fallback.
func EvaluateWithSeverityOverrides(payload JobPayload, disabledChecks []string, severityOverrides map[string]string) []Finding {
	disabled := map[string]struct{}{}
	for _, check := range disabledChecks {
		disabled[check] = struct{}{}
	}
	declarativeFindings, declarativeLoaded := evaluateDeclarativeRules(payload, disabledChecks, severityOverrides)
	findings := append([]Finding{}, declarativeFindings...)
	if _, ok := disabled["github.public_repository_created"]; !ok && (!declarativeLoaded || !declarativeRuleIDs["github.public_repository_created"]) {
		if finding, ok := evaluateGitHubPublicRepository(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["github.branch_protection_disabled"]; !ok {
		if finding, ok := evaluateGitHubBranchProtectionDisabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["github.oauth_app_installed"]; !ok {
		if finding, ok := evaluateGitHubOAuthAppInstalled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["github.deploy_key_added"]; !ok {
		if finding, ok := evaluateGitHubDeployKeyAdded(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["slack.mfa_disabled"]; !ok && (!declarativeLoaded || !declarativeRuleIDs["slack.mfa_disabled"]) {
		if finding, ok := evaluateSlackMFADisabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["slack.external_shared_channel_created"]; !ok {
		if finding, ok := evaluateSlackExternalSharedChannelCreated(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["slack.workspace_invite_link_enabled"]; !ok {
		if finding, ok := evaluateSlackWorkspaceInviteLinkEnabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["slack.app_installed"]; !ok {
		if finding, ok := evaluateSlackAppInstalled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["okta.admin_role_assigned"]; !ok {
		if finding, ok := evaluateOktaAdminRoleAssigned(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["okta.mfa_factor_reset"]; !ok {
		if finding, ok := evaluateOktaMFAFactorReset(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["okta.password_policy_weakened"]; !ok {
		if finding, ok := evaluateOktaPasswordPolicyWeakened(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["okta.suspicious_signin"]; !ok {
		if finding, ok := evaluateOktaSuspiciousSignin(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.external_sharing_enabled"]; !ok && (!declarativeLoaded || !declarativeRuleIDs["google_workspace.external_sharing_enabled"]) {
		if finding, ok := evaluateGoogleExternalSharingEnabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.super_admin_granted"]; !ok {
		if finding, ok := evaluateGoogleSuperAdminGranted(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.admin_role_granted"]; !ok {
		if finding, ok := evaluateGoogleAdminRoleGranted(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.risky_oauth_grant"]; !ok {
		if finding, ok := evaluateGoogleRiskyOAuthGrant(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.admin_mfa_not_enforced"]; !ok {
		if finding, ok := evaluateGoogleAdminMFANotEnforced(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.admin_external_recovery_email"]; !ok {
		if finding, ok := evaluateGoogleAdminExternalRecoveryEmail(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.email_forwarding_enabled"]; !ok {
		if finding, ok := evaluateGoogleEmailForwardingEnabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.mailbox_delegation_granted"]; !ok {
		if finding, ok := evaluateGoogleMailboxDelegationGranted(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.legacy_mail_auth_used"]; !ok {
		if finding, ok := evaluateGoogleLegacyMailAuthUsed(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["google_workspace.forwarding_delegate_send_as_combo"]; !ok {
		if finding, ok := evaluateGoogleForwardingDelegateSendAsCombo(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["ms365.guest_user_invited"]; !ok {
		if finding, ok := evaluateMicrosoft365GuestUserInvited(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["ms365.conditional_access_disabled"]; !ok {
		if finding, ok := evaluateMicrosoft365ConditionalAccessDisabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["ms365.global_admin_granted"]; !ok {
		if finding, ok := evaluateMicrosoft365GlobalAdminGranted(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["atlassian.anonymous_access_enabled"]; !ok {
		if finding, ok := evaluateAtlassianAnonymousAccessEnabled(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["atlassian.public_space_created"]; !ok {
		if finding, ok := evaluateAtlassianPublicSpaceCreated(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["atlassian.org_admin_granted"]; !ok {
		if finding, ok := evaluateAtlassianOrgAdminGranted(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["salesforce.admin_profile_assigned"]; !ok {
		if finding, ok := evaluateSalesforceAdminProfileAssigned(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["salesforce.connected_app_policy_weakened"]; !ok {
		if finding, ok := evaluateSalesforceConnectedAppPolicyWeakened(payload); ok {
			findings = append(findings, finding)
		}
	}
	if _, ok := disabled["salesforce.report_exported"]; !ok {
		if finding, ok := evaluateSalesforceReportExported(payload); ok {
			findings = append(findings, finding)
		}
	}
	for index := range findings {
		if override := strings.ToUpper(strings.TrimSpace(severityOverrides[findings[index].RuleID])); override != "" && validFindingSeverity(override) {
			findings[index].Severity = override
			findings[index].RiskScore = RiskScoreFor(override)
		}
	}
	return findings
}

func validFindingSeverity(value string) bool {
	switch value {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

func evaluateGitHubPublicRepository(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GITHUB" {
		return Finding{}, false
	}
	normalized := normalizeEventType(payload.EventType)
	private, hasPrivate := nestedBool(payload.Payload, "repository", "private")
	visibility := nestedString(payload.Payload, "repository", "visibility")
	if normalized != "PUBLIC_REPOSITORY_CREATED" && normalized != "REPOSITORY_PUBLICIZED" {
		return Finding{}, false
	}
	if (!hasPrivate || private) && !strings.EqualFold(visibility, "public") {
		return Finding{}, false
	}
	repository := firstNonEmpty(
		nestedString(payload.Payload, "repository", "full_name"),
		nestedString(payload.Payload, "repository", "name"),
		"unknown repository",
	)
	return Finding{
		RuleID:      "github.public_repository_created",
		Title:       "Public GitHub repository created",
		Description: "A repository was created or changed to public visibility, which can expose source code, secrets, or customer data.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 5),
		Tags:        []string{TagDataPublicExposure},
		RemediationSteps: []string{
			"Confirm the repository is approved for public release.",
			"Set repository visibility to private if public access is not explicitly authorized.",
			"Run secret scanning and branch protection checks before allowing continued public access.",
		},
		Target: repository,
		Evidence: map[string]any{
			"repository": repository,
			"subject":    repository,
			"visibility": firstNonEmpty(visibility, "public"),
		},
	}, true
}

func evaluateGitHubBranchProtectionDisabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GITHUB" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "BRANCH_PROTECTION_DISABLED", "BRANCH_PROTECTION_RULE_DELETED", "BRANCH_PROTECTION_RULE_UPDATED":
	default:
		return Finding{}, false
	}
	if normalizeEventType(payload.EventType) == "BRANCH_PROTECTION_RULE_UPDATED" && !recordSuggestsWeakenedPolicy(payload.Payload) {
		return Finding{}, false
	}
	repository := firstNonEmpty(
		nestedString(payload.Payload, "repository", "full_name"),
		nestedString(payload.Payload, "repository", "name"),
		nestedString(payload.Payload, "repo"),
		"unknown repository",
	)
	branch := firstNonEmpty(
		nestedString(payload.Payload, "branch"),
		nestedString(payload.Payload, "ref"),
		nestedString(payload.Payload, "rule", "pattern"),
		nestedString(payload.Payload, "protection", "branch"),
		"default branch",
	)
	subject := repository + ":" + branch
	return Finding{
		RuleID:      "github.branch_protection_disabled",
		Title:       "GitHub branch protection disabled",
		Description: "Required reviews, status checks, signed commits, or linear history were removed from a protected branch.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 6),
		Tags:        []string{TagPolicyWeakened},
		RemediationSteps: []string{
			"Confirm the branch-protection change was approved through change control.",
			"Restore required reviews, status checks, signed commits, and linear history if not explicitly approved.",
			"Review commits merged while protection was weakened.",
		},
		Target:       repository,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"repository": repository,
			"branch":     branch,
			"actor":      payload.Actor,
			"subject":    subject,
		}),
	}, true
}

func evaluateGitHubOAuthAppInstalled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GITHUB" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "OAUTH_APP_INSTALLED", "GITHUB_APP_INSTALLED", "ORG_OAUTH_APP_ACCESS_APPROVED":
	default:
		return Finding{}, false
	}
	app := firstNonEmpty(
		nestedString(payload.Payload, "app", "name"),
		nestedString(payload.Payload, "oauth_app", "name"),
		nestedString(payload.Payload, "application", "name"),
		nestedString(payload.Payload, "application", "slug"),
		nestedString(payload.Payload, "client_id"),
		"unknown app",
	)
	scopes := uniqueStrings(append(
		stringArray(payload.Payload["scopes"]),
		stringArray(nestedRecord(payload.Payload, "application")["scopes"])...,
	))
	permissions := flattenedRecordStringValues(nestedRecord(payload.Payload, "permissions"))
	scopeBlob := strings.ToLower(strings.Join(append(scopes, permissions...), " "))
	risky := strings.Contains(scopeBlob, "admin") ||
		strings.Contains(scopeBlob, "repo") ||
		strings.Contains(scopeBlob, "write") ||
		strings.Contains(scopeBlob, "organization") ||
		strings.Contains(scopeBlob, "members")
	if !risky && len(scopes) > 0 {
		return Finding{}, false
	}
	return Finding{
		RuleID:      "github.oauth_app_installed",
		Title:       "Risky GitHub OAuth app installed",
		Description: "A GitHub OAuth or GitHub App installation requested organization, admin, repo, or write-level access.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 8),
		Tags:        []string{TagOAuthRiskyGrant, TagDataAccess},
		RemediationSteps: []string{
			"Confirm the GitHub app is approved for the organization.",
			"Restrict requested permissions or revoke the app if the access is not required.",
			"Review repository and organization audit activity performed by the app.",
		},
		Target:       app,
		DedupeTarget: app,
		Evidence: compactEvidence(map[string]any{
			"app":         app,
			"scopes":      scopes,
			"permissions": permissions,
			"actor":       payload.Actor,
			"subject":     app,
		}),
	}, true
}

func evaluateGitHubDeployKeyAdded(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GITHUB" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "DEPLOY_KEY_ADDED", "DEPLOY_KEY_CREATED":
	default:
		return Finding{}, false
	}
	repository := firstNonEmpty(
		nestedString(payload.Payload, "repository", "full_name"),
		nestedString(payload.Payload, "repository", "name"),
		nestedString(payload.Payload, "repo"),
	)
	key := firstNonEmpty(
		nestedString(payload.Payload, "key", "title"),
		nestedString(payload.Payload, "key", "name"),
		nestedString(payload.Payload, "deploy_key", "title"),
		nestedString(payload.Payload, "deploy_key", "id"),
		nestedString(payload.Payload, "key_id"),
	)
	// A deploy-key event without a repository and key identity cannot produce
	// a stable target or a trustworthy remediation. Leave it unsupported until
	// the provider adapter supplies the fields listed in the support matrix.
	if repository == "" || key == "" {
		return Finding{}, false
	}
	writeEnabled, hasWriteEnabled := nestedBool(payload.Payload, "key", "write_enabled")
	if !hasWriteEnabled {
		writeEnabled, hasWriteEnabled = nestedBool(payload.Payload, "deploy_key", "write_enabled")
	}
	severity := SeverityMedium
	riskScore := RiskScoreFor(SeverityMedium, 4)
	if hasWriteEnabled && writeEnabled {
		severity = SeverityHigh
		riskScore = RiskScoreFor(SeverityHigh, 7)
	}
	subject := repository + ":" + key
	return Finding{
		RuleID:      "github.deploy_key_added",
		RuleVersion: "1.0.0",
		Title:       "GitHub deploy key added",
		Description: "A deploy key was added to a GitHub repository; write-enabled keys can bypass normal user and review controls.",
		Severity:    severity,
		RiskScore:   riskScore,
		Tags:        []string{TagDataAccess, TagPolicyWeakened},
		RemediationSteps: []string{
			"Confirm the deploy key belongs to an approved automation system.",
			"Disable write access unless the automation requires repository writes.",
			"Remove the key and rotate its credential if it was not approved.",
		},
		Target:       repository,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"repository":   repository,
			"key":          key,
			"writeEnabled": writeEnabled,
			"actor":        payload.Actor,
			"subject":      subject,
		}),
	}, true
}

func evaluateSlackMFADisabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SLACK" {
		return Finding{}, false
	}
	normalized := normalizeEventType(payload.EventType)
	if normalized != "MFA_DISABLED" && normalized != "TWO_FACTOR_AUTH_DISABLED" {
		return Finding{}, false
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "user", "email"),
		nestedString(payload.Payload, "user", "id"),
		payload.Actor,
		"unknown user",
	)
	return Finding{
		RuleID:      "slack.mfa_disabled",
		Title:       "Slack multi-factor authentication disabled",
		Description: "A Slack user disabled MFA, increasing the likelihood of account takeover and lateral movement.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical),
		Tags:        []string{TagAuthMFAWeakened},
		RemediationSteps: []string{
			"Re-enable MFA for the affected Slack user immediately.",
			"Force a session reset for the affected account.",
			"Review recent login history and connected Slack apps for suspicious activity.",
		},
		Target: user,
		Evidence: map[string]any{
			"user":    user,
			"subject": user,
		},
	}, true
}

func evaluateSlackExternalSharedChannelCreated(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SLACK" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "EXTERNAL_SHARED_CHANNEL_CREATED", "SHARED_CHANNEL_INVITE_ACCEPTED":
	default:
		return Finding{}, false
	}
	channel := slackChannelLabel(payload)
	externalOrg := firstNonEmpty(
		nestedString(payload.Payload, "external_organization", "name"),
		nestedString(payload.Payload, "external_team", "name"),
		nestedString(payload.Payload, "target_team", "name"),
		"external organization",
	)
	subject := channel + ":" + externalOrg
	return Finding{
		RuleID:      "slack.external_shared_channel_created",
		Title:       "Slack external shared channel created",
		Description: "A Slack channel was shared with an external organization, expanding conversation and file visibility outside the tenant.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 4),
		Tags:        []string{TagDataExternalShare},
		RemediationSteps: []string{
			"Confirm the shared channel and external organization are approved.",
			"Restrict channel membership and file sharing if the collaboration is still required.",
			"Disconnect the shared channel if it was created unexpectedly.",
		},
		Target:       channel,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"channel":     channel,
			"externalOrg": externalOrg,
			"actor":       payload.Actor,
			"subject":     subject,
		}),
	}, true
}

func evaluateSlackWorkspaceInviteLinkEnabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SLACK" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "WORKSPACE_INVITE_LINK_ENABLED", "INVITE_LINK_CREATED":
	default:
		return Finding{}, false
	}
	workspace := firstNonEmpty(
		nestedString(payload.Payload, "team", "name"),
		nestedString(payload.Payload, "workspace", "name"),
		nestedString(payload.Payload, "enterprise", "name"),
		"Slack workspace",
	)
	return Finding{
		RuleID:      "slack.workspace_invite_link_enabled",
		Title:       "Slack workspace invite link enabled",
		Description: "A public workspace invite link was enabled, allowing uncontrolled joins if the link leaks.",
		Severity:    SeverityMedium,
		RiskScore:   RiskScoreFor(SeverityMedium, 5),
		Tags:        []string{TagPolicyWeakened},
		RemediationSteps: []string{
			"Confirm the public invite link is approved and time-bounded.",
			"Disable the invite link if broad self-service joins are not required.",
			"Review recent joins while the link was active.",
		},
		Target:       workspace,
		DedupeTarget: workspace,
		Evidence: compactEvidence(map[string]any{
			"workspace": workspace,
			"actor":     payload.Actor,
			"subject":   workspace,
		}),
	}, true
}

func evaluateSlackAppInstalled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SLACK" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "APP_INSTALLED", "APP_APPROVED", "APP_SCOPES_APPROVED":
	default:
		return Finding{}, false
	}
	app := firstNonEmpty(
		nestedString(payload.Payload, "app", "name"),
		nestedString(payload.Payload, "app", "id"),
		nestedString(payload.Payload, "entity", "name"),
		nestedString(payload.Payload, "application", "name"),
		"unknown Slack app",
	)
	scopes := uniqueStrings(append(
		stringArray(payload.Payload["scopes"]),
		stringArray(nestedRecord(payload.Payload, "app")["scopes"])...,
	))
	severity := SeverityMedium
	riskScore := RiskScoreFor(SeverityMedium, 7)
	scopeBlob := strings.ToLower(strings.Join(scopes, " "))
	if strings.Contains(scopeBlob, "admin") || strings.Contains(scopeBlob, "files:read") || strings.Contains(scopeBlob, "channels:history") {
		severity = SeverityHigh
		riskScore = RiskScoreFor(SeverityHigh, 6)
	}
	return Finding{
		RuleID:      "slack.app_installed",
		Title:       "Third-party Slack app installed",
		Description: "A third-party Slack app was installed with user, channel, admin, or file scopes.",
		Severity:    severity,
		RiskScore:   riskScore,
		Tags:        []string{TagOAuthRiskyGrant, TagDataAccess},
		RemediationSteps: []string{
			"Confirm the Slack app is approved for the workspace.",
			"Review requested scopes and app configuration for channel, file, user, or admin access.",
			"Uninstall the app if it is not business-approved.",
		},
		Target:       app,
		DedupeTarget: app,
		Evidence: compactEvidence(map[string]any{
			"app":     app,
			"scopes":  scopes,
			"actor":   payload.Actor,
			"subject": app,
		}),
	}, true
}

func evaluateOktaAdminRoleAssigned(payload JobPayload) (Finding, bool) {
	if payload.Provider != "OKTA" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "USER_ACCOUNT_PRIVILEGE_GRANT", "USER_ACCOUNT_PRIVILEGE_GRANTED", "ADMIN_ROLE_ASSIGNED", "ROLE_ASSIGNMENT_CREATED":
	default:
		return Finding{}, false
	}
	user := oktaUserTarget(payload)
	grantedRole := oktaRoleName(payload)
	if !isPrivilegedOktaRole(grantedRole) {
		return Finding{}, false
	}
	subject := user + ":" + grantedRole
	return Finding{
		RuleID:      "okta.admin_role_assigned",
		Title:       "Okta admin role assigned",
		Description: "An Okta account was granted a highly privileged administrator role.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 3),
		Tags:        []string{TagIAMPrivilegeEscalation},
		RemediationSteps: []string{
			"Validate that the Okta admin role assignment was approved through change control.",
			"Remove the role if the assignment is not explicitly authorized.",
			"Review recent sign-ins and admin activity for the affected Okta account.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":        user,
			"grantedRole": grantedRole,
			"actor":       oktaActor(payload),
			"subject":     subject,
		}),
	}, true
}

func evaluateOktaMFAFactorReset(payload JobPayload) (Finding, bool) {
	if payload.Provider != "OKTA" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "USER_MFA_FACTOR_RESET", "USER_MFA_FACTOR_RESET_ALL", "MFA_FACTOR_RESET":
	default:
		return Finding{}, false
	}
	user := oktaUserTarget(payload)
	actor := oktaActor(payload)
	if strings.EqualFold(actor, user) {
		return Finding{}, false
	}
	debugData := oktaDebugData(payload)
	factor := firstNonEmpty(
		nestedString(debugData, "factor"),
		nestedString(debugData, "factorType"),
		"all factors",
	)
	subject := user + ":" + actor
	return Finding{
		RuleID:      "okta.mfa_factor_reset",
		Title:       "Okta MFA factor reset by admin",
		Description: "An administrator reset MFA factors for another Okta user, which can be legitimate helpdesk activity or an account-takeover precursor.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 7),
		Tags:        []string{TagAuthMFAWeakened},
		RemediationSteps: []string{
			"Confirm the MFA reset was requested by the affected user.",
			"Force a password reset and session revocation if the reset was not approved.",
			"Review recent sign-ins and admin actions by the actor who reset the factor.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":    user,
			"actor":   actor,
			"factor":  factor,
			"subject": subject,
		}),
	}, true
}

func evaluateOktaPasswordPolicyWeakened(payload JobPayload) (Finding, bool) {
	if payload.Provider != "OKTA" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "POLICY_LIFECYCLE_UPDATE", "PASSWORD_POLICY_UPDATED":
	default:
		return Finding{}, false
	}
	if !oktaIsPasswordPolicy(payload) || !oktaPasswordPolicyWeakened(payload) {
		return Finding{}, false
	}
	policyName := oktaPasswordPolicyName(payload)
	return Finding{
		RuleID:      "okta.password_policy_weakened",
		Title:       "Okta password policy weakened",
		Description: "An Okta password policy was changed to reduce password length, complexity, rotation, history, or lockout protections.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 9),
		Tags:        []string{TagPolicyWeakened, TagAuthPassword},
		RemediationSteps: []string{
			"Review the policy change and confirm it was approved.",
			"Restore the previous password policy settings if the change was not authorized.",
			"Audit affected user sign-ins while the weaker policy was active.",
		},
		Target:       policyName,
		DedupeTarget: policyName,
		Evidence: compactEvidence(map[string]any{
			"policyName":       policyName,
			"actor":            oktaActor(payload),
			"weakenedSettings": oktaWeakenedSettingNames(payload),
			"subject":          policyName,
		}),
	}, true
}

func evaluateOktaSuspiciousSignin(payload JobPayload) (Finding, bool) {
	if payload.Provider != "OKTA" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "SECURITY_THREAT_DETECTED", "USER_AUTHENTICATION_FAILED", "USER_SESSION_START":
	default:
		return Finding{}, false
	}
	debugData := oktaDebugData(payload)
	securityContext := nestedRecord(payload.Payload, "securityContext")
	outcome := nestedRecord(payload.Payload, "outcome")
	risk := firstNonEmpty(
		nestedString(securityContext, "risk"),
		nestedString(debugData, "risk"),
		nestedString(outcome, "reason"),
	)
	threatSuspected := nestedBoolValue(debugData, "threatSuspected") ||
		nestedBoolValue(securityContext, "isProxy") ||
		oktaRiskHasThreatIndicator(risk)
	if !threatSuspected {
		return Finding{}, false
	}
	user := oktaActor(payload)
	ipAddress := firstNonEmpty(
		nestedString(payload.Payload, "client", "ipAddress"),
		nestedString(debugData, "ipAddress"),
	)
	dedupeSignal := ipAddress
	if dedupeSignal == "" {
		dedupeSignal = risk
	}
	subject := user + ":" + dedupeSignal
	return Finding{
		RuleID:      "okta.suspicious_signin",
		Title:       "Okta suspicious sign-in detected",
		Description: "Okta flagged sign-in activity with threat, proxy, or high-risk indicators.",
		Severity:    SeverityMedium,
		RiskScore:   RiskScoreFor(SeverityMedium, 7),
		Tags:        []string{TagAuthSuspiciousLogin},
		RemediationSteps: []string{
			"Verify the sign-in with the affected user.",
			"Reset the user's password and MFA factors if the sign-in was not expected.",
			"Block the source IP or strengthen sign-on policy if the pattern recurs.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":      user,
			"ipAddress": optionalString(ipAddress),
			"risk":      risk,
			"actor":     oktaActor(payload),
			"subject":   subject,
		}),
	}, true
}

func evaluateGoogleExternalSharingEnabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "EXTERNAL_SHARING_ENABLED" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	fileName := firstNonEmpty(
		nestedString(payload.Payload, "resource", "name"),
		nestedString(payload.Payload, "parameters", "doc_title"),
	)
	fileID := firstNonEmpty(
		nestedString(payload.Payload, "resource", "id"),
		nestedString(payload.Payload, "parameters", "doc_id"),
	)
	fileType := nestedString(payload.Payload, "parameters", "doc_type")
	owner := nestedString(payload.Payload, "parameters", "owner")
	visibility := firstNonEmpty(nestedString(payload.Payload, "parameters", "visibility"), "shared_externally")
	driveType := "User drive"
	if nestedBoolValue(payload.Payload, "parameters", "owner_is_shared_drive") ||
		nestedBoolValue(payload.Payload, "parameters", "owner_is_team_drive") {
		driveType = "Shared drive"
	}
	resource := firstNonEmpty(fileName, fileID, "unknown resource")
	ownerDomain := firstNonEmpty(nestedString(payload.Payload, "ownerDomain"), domainFromEmail(owner))
	externalRecipient := extractExternalRecipient(parameters, ownerDomain, payload.Actor)
	subject := firstNonEmpty(fileID, resource)

	return Finding{
		RuleID:      "google_workspace.external_sharing_enabled",
		Title:       "Google Workspace external sharing enabled",
		Description: "A Google Workspace resource was configured for external sharing, which may expose regulated or confidential data.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh),
		Tags:        []string{TagDataExternalShare, TagPolicyWeakened},
		RemediationSteps: []string{
			"Restrict the resource sharing policy to trusted domains.",
			"Confirm business justification with the resource owner.",
			"Audit downstream links and inherited folder permissions.",
		},
		Target:       resource,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"fileName":      fileName,
			"fileId":        fileID,
			"fileType":      fileType,
			"owner":         owner,
			"visibility":    visibility,
			"driveType":     driveType,
			"subject":       subject,
			"externalActor": optionalString(externalRecipient),
			"docTitle":      stringValue(parameters["doc_title"]),
			"docType":       stringValue(parameters["doc_type"]),
		}),
	}, true
}

func evaluateGoogleSuperAdminGranted(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "SUPER_ADMIN_GRANTED" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "target", "email"),
		nestedString(payload.Payload, "target", "name"),
		nestedString(parameters, "USER_EMAIL"),
		nestedString(parameters, "EMAIL"),
		nestedString(parameters, "user_email"),
		payload.Actor,
		"unknown user",
	)
	grantedRole := firstNonEmpty(
		nestedString(parameters, "ROLE_NAME"),
		nestedString(parameters, "role_name"),
		"Super admin",
	)
	return Finding{
		RuleID:      "google_workspace.super_admin_granted",
		Title:       "Google Workspace super admin granted",
		Description: "A Google Workspace account was granted super administrator privileges.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 5),
		Tags:        []string{TagIAMPrivilegeEscalation},
		RemediationSteps: []string{
			"Validate that the admin elevation was approved through change control.",
			"Remove the role if the assignment is not explicitly authorized.",
			"Review recent sign-ins and admin actions for the affected account.",
		},
		Target:       user,
		DedupeTarget: user,
		Evidence: map[string]any{
			"user":        user,
			"grantedRole": grantedRole,
			"subject":     user,
		},
	}, true
}

func evaluateGoogleAdminRoleGranted(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "ADMIN_ROLE_GRANTED" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "target", "email"),
		nestedString(parameters, "USER_EMAIL"),
		nestedString(parameters, "EMAIL"),
		nestedString(parameters, "user_email"),
		payload.Actor,
		"unknown user",
	)
	grantedRole := firstNonEmpty(
		nestedString(parameters, "ROLE_NAME"),
		nestedString(parameters, "PRIVILEGE_NAME"),
		nestedString(parameters, "role_name"),
		"Admin role",
	)
	subject := user + ":" + grantedRole
	return Finding{
		RuleID:      "google_workspace.admin_role_granted",
		Title:       "Google Workspace admin role granted",
		Description: "A Google Workspace account was granted an administrative role.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 11),
		Tags:        []string{TagIAMPrivilegeEscalation},
		RemediationSteps: []string{
			"Validate that the admin role assignment was approved through change control.",
			"Remove the role if the assignment is not required.",
			"Review recent admin actions and sign-ins for the affected account.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: map[string]any{
			"user":        user,
			"grantedRole": grantedRole,
			"subject":     subject,
		},
	}, true
}

func evaluateGoogleRiskyOAuthGrant(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "RISKY_OAUTH_GRANT" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	appName := nestedString(payload.Payload, "parameters", "app_name")
	clientID := nestedString(payload.Payload, "parameters", "client_id")
	clientType := nestedString(payload.Payload, "parameters", "client_type")
	scopes := stringArray(parameters["scope"])
	client := firstNonEmpty(appName, clientID, "unknown OAuth client")
	oauthRisk := googleOAuthGrantRisk(scopes)
	riskScore := oauthRisk.riskScore
	if override, ok := nestedNumber(payload.Payload, "oauth", "riskScore"); ok {
		riskScore = int(override)
	}
	subject := firstNonEmpty(clientID, client)

	return Finding{
		RuleID:      "google_workspace.risky_oauth_grant",
		Title:       oauthRisk.title,
		Description: "A Google Workspace user granted a third-party OAuth client access to sensitive Google scopes.",
		Severity:    oauthRisk.severity,
		RiskScore:   clampToSeverityBand(oauthRisk.severity, riskScore),
		Tags:        []string{TagOAuthRiskyGrant, TagDataAccess},
		RemediationSteps: []string{
			"Confirm the OAuth client is approved for the tenant.",
			"Revoke the grant if the client or scopes are not required.",
			"Review the scopes and affected user activity for possible abuse.",
		},
		Target:       client,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"appName":       appName,
			"clientId":      clientID,
			"clientType":    clientType,
			"scopes":        scopes,
			"matchedScopes": oauthRisk.matchedScopes,
			"riskReason":    oauthRisk.riskReason,
			"scopeCount":    len(scopes),
			"subject":       subject,
		}),
	}, true
}

func evaluateGoogleAdminMFANotEnforced(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "ADMIN_MFA_NOT_ENFORCED" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	user := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "user_email"),
		"unknown admin",
	)
	mfaEnrolled := nestedBoolValue(parameters, "mfa_enrolled")
	mfaEnforced := nestedBoolValue(parameters, "mfa_enforced")
	delegatedAdmin := nestedBoolValue(parameters, "is_delegated_admin")
	title := "Google Workspace admin MFA not enrolled"
	severity := SeverityCritical
	score := RiskScoreFor(SeverityCritical, 5)
	if mfaEnrolled {
		title = "Google Workspace admin MFA not enforced"
		severity = SeverityHigh
		score = RiskScoreFor(SeverityHigh, 11)
	}
	return Finding{
		RuleID:      "google_workspace.admin_mfa_not_enforced",
		Title:       title,
		Description: "A Google Workspace admin account lacks enforced multi-factor authentication, increasing the risk of privileged account takeover.",
		Severity:    severity,
		RiskScore:   score,
		Tags:        []string{TagAuthMFAWeakened, TagPolicyWeakened},
		RemediationSteps: []string{
			"Require 2-step verification for the affected admin account immediately.",
			"Confirm the account is still authorized to hold privileged access.",
			"Review recent admin actions and sign-ins for suspicious activity.",
		},
		Target:       user,
		DedupeTarget: user,
		Evidence: compactEvidence(map[string]any{
			"user":           user,
			"mfaEnrolled":    mfaEnrolled,
			"mfaEnforced":    mfaEnforced,
			"delegatedAdmin": delegatedAdmin,
			"subject":        user,
		}),
	}, true
}

func evaluateGoogleAdminExternalRecoveryEmail(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "ADMIN_EXTERNAL_RECOVERY_EMAIL" {
		return Finding{}, false
	}
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		parameters = map[string]any{}
	}
	user := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "user_email"),
		"unknown admin",
	)
	recoveryEmail := firstNonEmpty(nestedString(parameters, "recovery_email"), "unknown recovery email")
	delegatedAdmin := nestedBoolValue(parameters, "is_delegated_admin")
	subject := user + ":" + recoveryEmail
	return Finding{
		RuleID:      "google_workspace.admin_external_recovery_email",
		Title:       "Google Workspace admin uses external recovery email",
		Description: "A Google Workspace admin account has a recovery email outside the tenant domain, creating an external account-recovery path.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 8),
		Tags:        []string{TagAuthAccountRecovery},
		RemediationSteps: []string{
			"Validate that the recovery email is approved for the privileged account.",
			"Replace the external recovery address with a controlled corporate recovery path if not required.",
			"Review recent recovery, sign-in, and admin activity for the account.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":           user,
			"recoveryEmail":  recoveryEmail,
			"delegatedAdmin": delegatedAdmin,
			"subject":        subject,
		}),
	}, true
}

func evaluateGoogleEmailForwardingEnabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "EMAIL_FORWARDING_ENABLED" {
		return Finding{}, false
	}
	parameters := googleParameters(payload)
	addresses := uniqueStrings(googleForwardingAddresses(parameters))
	forwardedTo := ""
	for _, address := range addresses {
		if !strings.EqualFold(address, payload.Actor) {
			forwardedTo = address
			break
		}
	}
	forwardedTo = firstNonEmpty(forwardedTo, firstString(addresses), "unknown forwarding address")
	mailbox := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "mailbox"),
		"unknown mailbox",
	)
	disposition := firstNonEmpty(
		nestedString(parameters, "disposition"),
		nestedString(parameters, "forwarding_disposition"),
		nestedString(parameters, "action"),
		"forward",
	)
	subject := mailbox + ":" + forwardedTo
	return Finding{
		RuleID:      "google_workspace.email_forwarding_enabled",
		Title:       "Google Workspace email forwarding enabled",
		Description: "A Gmail mailbox was configured to forward messages to another address, which can exfiltrate sensitive email outside the tenant.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 3),
		Tags:        []string{TagEmailForwarding, TagDataExternalShare},
		RemediationSteps: []string{
			"Validate that the forwarding destination is approved for business use.",
			"Disable the forwarding rule if it is not explicitly authorized.",
			"Review recent mailbox activity and message access for possible data leakage.",
		},
		Target:       mailbox,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"mailbox":     mailbox,
			"forwardedTo": forwardedTo,
			"disposition": disposition,
			"subject":     subject,
		}),
	}, true
}

func evaluateGoogleMailboxDelegationGranted(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "MAILBOX_DELEGATION_GRANTED" {
		return Finding{}, false
	}
	parameters := googleParameters(payload)
	mailbox := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "mailbox"),
		"unknown mailbox",
	)
	delegates := uniqueStrings(googleDelegateAddresses(parameters))
	delegate := ""
	for _, candidate := range delegates {
		if !strings.EqualFold(candidate, mailbox) {
			delegate = candidate
			break
		}
	}
	delegate = firstNonEmpty(delegate, firstString(delegates), "unknown delegate")
	delegationStatus := firstNonEmpty(
		nestedString(parameters, "delegation_status"),
		nestedString(parameters, "verificationStatus"),
		"accepted",
	)
	subject := mailbox + ":" + delegate
	return Finding{
		RuleID:      "google_workspace.mailbox_delegation_granted",
		Title:       "Google Workspace mailbox delegation granted",
		Description: "A Gmail mailbox granted delegate access to another user, allowing them to read and send mail on behalf of the mailbox owner.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 9),
		Tags:        []string{TagEmailDelegation, TagDataAccess},
		RemediationSteps: []string{
			"Confirm the delegate is explicitly approved for the mailbox.",
			"Remove the delegate if the access is not required.",
			"Review recent mailbox activity for unexpected message access or sending.",
		},
		Target:       mailbox,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"mailbox":          mailbox,
			"delegate":         delegate,
			"delegateCount":    len(delegates),
			"delegationStatus": delegationStatus,
			"subject":          subject,
		}),
	}, true
}

func evaluateGoogleLegacyMailAuthUsed(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "LEGACY_MAIL_AUTH_USED" {
		return Finding{}, false
	}
	parameters := googleParameters(payload)
	parameterBlob := strings.ToLower(strings.Join(flattenRecordStrings(parameters), " "))
	mailbox := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "mailbox"),
		"unknown mailbox",
	)
	protocol := ""
	for _, candidate := range []string{"imap", "pop", "smtp"} {
		if strings.Contains(parameterBlob, candidate) {
			protocol = candidate
			break
		}
	}
	authMethod := protocol
	switch {
	case strings.Contains(parameterBlob, "app password"):
		authMethod = "app_password"
	case strings.Contains(parameterBlob, "basic"):
		authMethod = "basic_auth"
	case strings.Contains(parameterBlob, "legacy"):
		authMethod = "legacy_auth"
	case authMethod == "":
		authMethod = "legacy_mail_auth"
	}
	title := "Google Workspace legacy mail authentication used"
	score := RiskScoreFor(SeverityHigh, 7)
	if authMethod == "app_password" {
		title = "Google Workspace app password created or used"
		score = RiskScoreFor(SeverityHigh, 13)
	}
	subject := mailbox + ":" + authMethod
	return Finding{
		RuleID:      "google_workspace.legacy_mail_auth_used",
		Title:       title,
		Description: "A mailbox used app passwords or a legacy mail protocol, which weakens account protections and can allow long-lived mailbox access outside modern OAuth controls.",
		Severity:    SeverityHigh,
		RiskScore:   score,
		Tags:        []string{TagAuthLegacyProtocol},
		RemediationSteps: []string{
			"Disable app passwords or legacy mail access for the affected user if not required.",
			"Rotate the user's password and revoke active sessions if the usage is unexpected.",
			"Review the mailbox for suspicious IMAP, POP, or SMTP access.",
		},
		Target:       mailbox,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"mailbox":    mailbox,
			"authMethod": authMethod,
			"protocol":   optionalString(protocol),
			"subject":    subject,
		}),
	}, true
}

func evaluateGoogleForwardingDelegateSendAsCombo(payload JobPayload) (Finding, bool) {
	if payload.Provider != "GOOGLE_WORKSPACE" || normalizeEventType(payload.EventType) != "FORWARDING_DELEGATE_SEND_AS_COMBO" {
		return Finding{}, false
	}
	parameters := googleParameters(payload)
	mailbox := firstNonEmpty(
		payload.Actor,
		nestedString(parameters, "email"),
		nestedString(parameters, "mailbox"),
		"unknown mailbox",
	)
	forwardedTo := firstNonEmpty(firstString(uniqueStrings([]string{
		emailsFirst(parameters["forwarding_address"]),
		emailsFirst(parameters["forwarding_email"]),
		emailsFirst(parameters["forward_to"]),
	})), "unknown forwarding address")
	delegates := uniqueStrings(emailsFromValue(parameters["delegates"]))
	sendAsAliases := uniqueStrings(emailsFromValue(parameters["send_as_aliases"]))
	comboKinds := []string{}
	if len(delegates) > 0 {
		comboKinds = append(comboKinds, "delegate")
	}
	if len(sendAsAliases) > 0 {
		comboKinds = append(comboKinds, "send-as")
	}
	return Finding{
		RuleID:      "google_workspace.forwarding_delegate_send_as_combo",
		Title:       "Google Workspace forwarding with delegate/send-as combo",
		Description: "A mailbox has forwarding enabled alongside delegate or send-as access, creating multiple parallel paths for mailbox exfiltration or impersonation.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 3),
		Tags:        []string{TagEmailForwarding, TagEmailDelegation, TagDataExternalShare},
		RemediationSteps: []string{
			"Validate that forwarding, delegate access, and send-as aliases are all approved together.",
			"Disable the forwarding rule first if any destination is untrusted.",
			"Remove unnecessary delegates or send-as aliases and review recent sent-mail activity.",
		},
		Target:       mailbox,
		DedupeTarget: mailbox,
		Evidence: compactEvidence(map[string]any{
			"mailbox":       mailbox,
			"forwardedTo":   forwardedTo,
			"delegates":     delegates,
			"delegateCount": len(delegates),
			"sendAsAliases": sendAsAliases,
			"sendAsCount":   len(sendAsAliases),
			"comboKinds":    comboKinds,
			"subject":       mailbox,
		}),
	}, true
}

func evaluateMicrosoft365GuestUserInvited(payload JobPayload) (Finding, bool) {
	if payload.Provider != "MICROSOFT_365" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "GUEST_USER_INVITED", "GUEST_INVITATION_CREATED", "USER_INVITED":
	default:
		return Finding{}, false
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "target", "userPrincipalName"),
		nestedString(payload.Payload, "target", "email"),
		nestedString(payload.Payload, "invitedUserEmailAddress"),
		nestedString(payload.Payload, "properties", "invitedUserEmailAddress"),
		"unknown guest",
	)
	return Finding{
		RuleID:      "ms365.guest_user_invited",
		Title:       "Microsoft 365 guest user invited",
		Description: "An external guest identity was invited into the Microsoft 365 tenant.",
		Severity:    SeverityMedium,
		RiskScore:   RiskScoreFor(SeverityMedium, 4),
		Tags:        []string{TagDataAccess},
		RemediationSteps: []string{
			"Confirm the guest invitation has a business owner and expiry.",
			"Restrict guest access to the minimum required groups and apps.",
			"Remove the guest if the invitation was not approved.",
		},
		Target:       user,
		DedupeTarget: user,
		Evidence: compactEvidence(map[string]any{
			"user":    user,
			"actor":   payload.Actor,
			"subject": user,
		}),
	}, true
}

func evaluateMicrosoft365ConditionalAccessDisabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "MICROSOFT_365" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "CONDITIONAL_ACCESS_DISABLED", "CONDITIONAL_ACCESS_POLICY_DISABLED", "CONDITIONAL_ACCESS_POLICY_UPDATED":
	default:
		return Finding{}, false
	}
	if normalizeEventType(payload.EventType) == "CONDITIONAL_ACCESS_POLICY_UPDATED" && !recordSuggestsDisabledState(payload.Payload) {
		return Finding{}, false
	}
	policy := firstNonEmpty(
		nestedString(payload.Payload, "policy", "displayName"),
		nestedString(payload.Payload, "target", "displayName"),
		nestedString(payload.Payload, "properties", "displayName"),
		nestedString(payload.Payload, "displayName"),
		"conditional access policy",
	)
	return Finding{
		RuleID:      "ms365.conditional_access_disabled",
		Title:       "Microsoft 365 conditional access policy disabled",
		Description: "A conditional access policy was disabled or updated to a disabled state, weakening MFA, device posture, or risk-based controls.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 5),
		Tags:        []string{TagPolicyWeakened, TagAuthMFAWeakened},
		RemediationSteps: []string{
			"Confirm the conditional access change was approved.",
			"Re-enable the policy or restore the prior policy version if the change was not authorized.",
			"Review sign-ins while the policy was disabled.",
		},
		Target:       policy,
		DedupeTarget: policy,
		Evidence: compactEvidence(map[string]any{
			"policy":  policy,
			"actor":   payload.Actor,
			"subject": policy,
		}),
	}, true
}

func evaluateMicrosoft365GlobalAdminGranted(payload JobPayload) (Finding, bool) {
	if payload.Provider != "MICROSOFT_365" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "GLOBAL_ADMIN_GRANTED", "DIRECTORY_ROLE_ASSIGNED", "ROLE_ASSIGNMENT_CREATED":
	default:
		return Finding{}, false
	}
	role := firstNonEmpty(
		nestedString(payload.Payload, "role", "displayName"),
		nestedString(payload.Payload, "role", "name"),
		nestedString(payload.Payload, "target", "roleName"),
		nestedString(payload.Payload, "properties", "roleName"),
		"Global Administrator",
	)
	if normalizeEventType(payload.EventType) != "GLOBAL_ADMIN_GRANTED" && !strings.Contains(strings.ToLower(role), "global administrator") {
		return Finding{}, false
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "target", "userPrincipalName"),
		nestedString(payload.Payload, "target", "email"),
		nestedString(payload.Payload, "user", "userPrincipalName"),
		nestedString(payload.Payload, "user", "email"),
		"unknown user",
	)
	subject := user + ":" + role
	return Finding{
		RuleID:      "ms365.global_admin_granted",
		Title:       "Microsoft 365 Global Administrator granted",
		Description: "An identity was assigned the Microsoft 365 Global Administrator role.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 4),
		Tags:        []string{TagIAMPrivilegeEscalation},
		RemediationSteps: []string{
			"Validate the Global Administrator assignment through change control.",
			"Remove the role if the assignment is not required.",
			"Review recent sign-ins and administrative activity by the affected identity.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":    user,
			"role":    role,
			"actor":   payload.Actor,
			"subject": subject,
		}),
	}, true
}

func evaluateAtlassianAnonymousAccessEnabled(payload JobPayload) (Finding, bool) {
	if payload.Provider != "ATLASSIAN" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "ANONYMOUS_ACCESS_ENABLED", "PUBLIC_ACCESS_ENABLED":
	default:
		return Finding{}, false
	}
	resource := atlassianResource(payload)
	return Finding{
		RuleID:      "atlassian.anonymous_access_enabled",
		Title:       "Atlassian anonymous access enabled",
		Description: "Jira or Confluence content was opened to anonymous users.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 5),
		Tags:        []string{TagDataPublicExposure, TagPolicyWeakened},
		RemediationSteps: []string{
			"Confirm anonymous access is approved for the project or space.",
			"Disable anonymous access if the resource contains internal data.",
			"Review public pages, issues, and attachments exposed by the change.",
		},
		Target:       resource,
		DedupeTarget: resource,
		Evidence: compactEvidence(map[string]any{
			"resource": resource,
			"actor":    payload.Actor,
			"subject":  resource,
		}),
	}, true
}

func evaluateAtlassianPublicSpaceCreated(payload JobPayload) (Finding, bool) {
	if payload.Provider != "ATLASSIAN" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "PUBLIC_SPACE_CREATED", "SPACE_PUBLIC_ACCESS_ENABLED", "PROJECT_PUBLIC_ACCESS_ENABLED":
	default:
		return Finding{}, false
	}
	resource := atlassianResource(payload)
	return Finding{
		RuleID:      "atlassian.public_space_created",
		Title:       "Atlassian public space or project created",
		Description: "A Confluence space or Jira project was made globally readable.",
		Severity:    SeverityMedium,
		RiskScore:   RiskScoreFor(SeverityMedium, 7),
		Tags:        []string{TagDataPublicExposure},
		RemediationSteps: []string{
			"Confirm the public collaboration area is intentionally exposed.",
			"Restrict space or project permissions if public visibility is not required.",
			"Review pages, issues, and attachments created while public access was active.",
		},
		Target:       resource,
		DedupeTarget: resource,
		Evidence: compactEvidence(map[string]any{
			"resource": resource,
			"actor":    payload.Actor,
			"subject":  resource,
		}),
	}, true
}

func evaluateAtlassianOrgAdminGranted(payload JobPayload) (Finding, bool) {
	if payload.Provider != "ATLASSIAN" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "ORG_ADMIN_GRANTED", "SITE_ADMIN_GRANTED", "PRODUCT_ADMIN_GRANTED":
	default:
		return Finding{}, false
	}
	user := firstNonEmpty(
		nestedString(payload.Payload, "target", "email"),
		nestedString(payload.Payload, "user", "email"),
		nestedString(payload.Payload, "account", "email"),
		"unknown user",
	)
	role := firstNonEmpty(
		nestedString(payload.Payload, "role", "name"),
		nestedString(payload.Payload, "target", "role"),
		nestedString(payload.Payload, "permission"),
		"Atlassian administrator",
	)
	subject := user + ":" + role
	return Finding{
		RuleID:      "atlassian.org_admin_granted",
		Title:       "Atlassian administrator granted",
		Description: "A user was granted broad organization, site, or product administrator access in Atlassian.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 8),
		Tags:        []string{TagIAMPrivilegeEscalation},
		RemediationSteps: []string{
			"Validate the administrator grant through change control.",
			"Remove the administrator role if the assignment is not required.",
			"Review recent Atlassian configuration and access changes by the user.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":    user,
			"role":    role,
			"actor":   payload.Actor,
			"subject": subject,
		}),
	}, true
}

func evaluateSalesforceAdminProfileAssigned(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SALESFORCE" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "ADMIN_PROFILE_ASSIGNED", "PERMISSION_SET_ASSIGNED", "PROFILE_ASSIGNED":
	default:
		return Finding{}, false
	}
	entitlement := firstNonEmpty(
		nestedString(payload.Payload, "profile", "name"),
		nestedString(payload.Payload, "permissionSet", "name"),
		nestedString(payload.Payload, "permission_set", "name"),
		nestedString(payload.Payload, "role", "name"),
		"administrator entitlement",
	)
	normalized := strings.ToLower(entitlement)
	if normalizeEventType(payload.EventType) != "ADMIN_PROFILE_ASSIGNED" &&
		!strings.Contains(normalized, "admin") &&
		!strings.Contains(normalized, "modify all") &&
		!strings.Contains(normalized, "view all") {
		return Finding{}, false
	}
	user := salesforceUser(payload)
	subject := user + ":" + entitlement
	return Finding{
		RuleID:      "salesforce.admin_profile_assigned",
		Title:       "Salesforce admin profile assigned",
		Description: "A Salesforce user received an administrator profile or broad permission set.",
		Severity:    SeverityCritical,
		RiskScore:   RiskScoreFor(SeverityCritical, 4),
		Tags:        []string{TagIAMPrivilegeEscalation, TagDataAccess},
		RemediationSteps: []string{
			"Validate the Salesforce entitlement assignment through change control.",
			"Remove the profile or permission set if it is not required.",
			"Review recent setup, export, and data access activity for the user.",
		},
		Target:       user,
		DedupeTarget: subject,
		Evidence: compactEvidence(map[string]any{
			"user":        user,
			"entitlement": entitlement,
			"actor":       payload.Actor,
			"subject":     subject,
		}),
	}, true
}

func evaluateSalesforceConnectedAppPolicyWeakened(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SALESFORCE" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "CONNECTED_APP_POLICY_WEAKENED", "CONNECTED_APP_UPDATED":
	default:
		return Finding{}, false
	}
	if normalizeEventType(payload.EventType) == "CONNECTED_APP_UPDATED" && !recordSuggestsWeakenedPolicy(payload.Payload) {
		return Finding{}, false
	}
	app := firstNonEmpty(
		nestedString(payload.Payload, "connectedApp", "name"),
		nestedString(payload.Payload, "connected_app", "name"),
		nestedString(payload.Payload, "app", "name"),
		nestedString(payload.Payload, "client_id"),
		"Salesforce connected app",
	)
	return Finding{
		RuleID:      "salesforce.connected_app_policy_weakened",
		Title:       "Salesforce connected app policy weakened",
		Description: "A Salesforce connected app was changed to allow broader OAuth access or weaker session controls.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 9),
		Tags:        []string{TagOAuthRiskyGrant, TagPolicyWeakened},
		RemediationSteps: []string{
			"Confirm the connected app policy change was approved.",
			"Restore admin-approved users, IP relaxation, refresh token, and session policies if weakened unexpectedly.",
			"Review recent OAuth grants and API activity for the connected app.",
		},
		Target:       app,
		DedupeTarget: app,
		Evidence: compactEvidence(map[string]any{
			"app":     app,
			"actor":   payload.Actor,
			"subject": app,
		}),
	}, true
}

func evaluateSalesforceReportExported(payload JobPayload) (Finding, bool) {
	if payload.Provider != "SALESFORCE" {
		return Finding{}, false
	}
	switch normalizeEventType(payload.EventType) {
	case "REPORT_EXPORTED", "BULK_DATA_EXPORT", "DATA_EXPORT_DOWNLOADED":
	default:
		return Finding{}, false
	}
	report := firstNonEmpty(
		nestedString(payload.Payload, "report", "name"),
		nestedString(payload.Payload, "report", "id"),
		nestedString(payload.Payload, "export", "name"),
		nestedString(payload.Payload, "dataset", "name"),
		"Salesforce data export",
	)
	return Finding{
		RuleID:      "salesforce.report_exported",
		Title:       "Salesforce report or data export downloaded",
		Description: "Salesforce report, bulk export, or tenant data export activity was observed.",
		Severity:    SeverityHigh,
		RiskScore:   RiskScoreFor(SeverityHigh, 6),
		Tags:        []string{TagDataAccess, TagDataExternalShare},
		RemediationSteps: []string{
			"Confirm the export was approved and tied to a business process.",
			"Validate the destination and retention of exported Salesforce data.",
			"Review additional exports by the actor and revoke access if activity is unexpected.",
		},
		Target:       report,
		DedupeTarget: report + ":" + payload.Actor,
		Evidence: compactEvidence(map[string]any{
			"report":  report,
			"actor":   payload.Actor,
			"subject": report,
		}),
	}, true
}

type googleOAuthRisk struct {
	severity      string
	riskScore     int
	title         string
	riskReason    string
	matchedScopes []string
}

func googleOAuthGrantRisk(scopes []string) googleOAuthRisk {
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		normalized = append(normalized, strings.ToLower(scope))
	}
	criticalScopeSet := map[string]struct{}{
		"https://mail.google.com/":                               {},
		"https://www.googleapis.com/auth/gmail.modify":           {},
		"https://www.googleapis.com/auth/gmail.insert":           {},
		"https://www.googleapis.com/auth/gmail.settings.basic":   {},
		"https://www.googleapis.com/auth/gmail.settings.sharing": {},
	}
	highMailboxScopeSet := map[string]struct{}{
		"https://www.googleapis.com/auth/gmail.readonly":                        {},
		"https://www.googleapis.com/auth/gmail.metadata":                        {},
		"https://www.googleapis.com/auth/gmail.send":                            {},
		"https://www.googleapis.com/auth/gmail.compose":                         {},
		"https://www.googleapis.com/auth/gmail.labels":                          {},
		"https://www.googleapis.com/auth/gmail.addons.current.message.readonly": {},
		"https://www.googleapis.com/auth/gmail.addons.current.message.action":   {},
		"https://www.googleapis.com/auth/gmail.addons.execute":                  {},
	}
	criticalScopes := filterScopesBySet(normalized, criticalScopeSet)
	if len(criticalScopes) > 0 {
		return googleOAuthRisk{
			severity:      SeverityCritical,
			riskScore:     RiskScoreFor(SeverityCritical, 2+len(criticalScopes)),
			title:         "Critical Gmail-scoped OAuth grant",
			riskReason:    "Granted full mailbox or mailbox-settings access",
			matchedScopes: criticalScopes,
		}
	}
	highMailboxScopes := filterScopesBySet(normalized, highMailboxScopeSet)
	if len(highMailboxScopes) > 0 {
		return googleOAuthRisk{
			severity:      SeverityHigh,
			riskScore:     RiskScoreFor(SeverityHigh, 9+len(highMailboxScopes)),
			title:         "High-risk Gmail OAuth grant",
			riskReason:    "Granted mailbox read, send, or compose access",
			matchedScopes: highMailboxScopes,
		}
	}
	matchedScopes := []string{}
	for _, scope := range normalized {
		if strings.Contains(scope, "admin") || strings.Contains(scope, "drive") || strings.Contains(scope, "directory") {
			matchedScopes = append(matchedScopes, scope)
		}
	}
	return googleOAuthRisk{
		severity:      SeverityHigh,
		riskScore:     RiskScoreFor(SeverityHigh, 7),
		title:         "High-risk Google OAuth grant",
		riskReason:    "Granted high-value Google Workspace scopes",
		matchedScopes: matchedScopes,
	}
}

func filterScopesBySet(scopes []string, allowed map[string]struct{}) []string {
	matches := []string{}
	for _, scope := range scopes {
		if _, ok := allowed[scope]; ok {
			matches = append(matches, scope)
		}
	}
	return matches
}

func extractExternalRecipient(parameters map[string]any, ownerDomain string, sharerEmail string) string {
	keys := []string{
		"target_user",
		"email_address",
		"user_email",
		"recipient",
		"recipient_email",
		"permission_change_target",
		"permission_change_grantee",
		"shared_with",
		"new_value",
	}
	for _, key := range keys {
		for _, candidate := range externalRecipientCandidates(parameters[key]) {
			if isEmailLike(candidate) && isExternalEmail(candidate, ownerDomain, sharerEmail) {
				return strings.TrimSpace(candidate)
			}
		}
	}
	return ""
}

func externalRecipientCandidates(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		candidates := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok {
				candidates = append(candidates, text)
			}
		}
		return candidates
	case []string:
		return typed
	default:
		return nil
	}
}

var emailLikePattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
var emailExtractPattern = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)

func isEmailLike(value string) bool {
	return emailLikePattern.MatchString(strings.TrimSpace(value))
}

func isExternalEmail(email string, ownerDomain string, sharerEmail string) bool {
	lowered := strings.ToLower(strings.TrimSpace(email))
	recipientDomain := domainFromEmail(lowered)
	if recipientDomain == "" {
		return false
	}
	if ownerDomain != "" && recipientDomain == strings.ToLower(ownerDomain) {
		return false
	}
	sharerDomain := domainFromEmail(sharerEmail)
	if sharerDomain != "" && recipientDomain == sharerDomain {
		return false
	}
	if sharerEmail != "" && lowered == strings.ToLower(strings.TrimSpace(sharerEmail)) {
		return false
	}
	return true
}

func domainFromEmail(value string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "@")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

func stringArray(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		values := []string{}
		for _, item := range typed {
			text, ok := item.(string)
			if ok && strings.TrimSpace(text) != "" {
				values = append(values, text)
			}
		}
		return values
	case []string:
		values := []string{}
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				values = append(values, item)
			}
		}
		return values
	default:
		return nil
	}
}

func emailsFromValue(value any) []string {
	emails := []string{}
	for _, entry := range stringArray(value) {
		for _, match := range emailExtractPattern.FindAllString(entry, -1) {
			if !containsString(emails, match) {
				emails = append(emails, match)
			}
		}
	}
	return emails
}

func emailsFirst(value any) string {
	return firstString(emailsFromValue(value))
}

func uniqueStrings(values []string) []string {
	unique := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || containsString(unique, value) {
			continue
		}
		unique = append(unique, value)
	}
	return unique
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func flattenedRecordStringValues(record map[string]any) []string {
	if record == nil {
		return nil
	}
	values := []string{}
	for _, key := range sortedRecordKeys(record) {
		values = append(values, stringArray(record[key])...)
		if text := stringValue(record[key]); text != "" {
			values = append(values, text)
		}
	}
	return uniqueStrings(values)
}

func slackChannelLabel(payload JobPayload) string {
	return firstNonEmpty(
		nestedString(payload.Payload, "channel", "name"),
		nestedString(payload.Payload, "channel", "id"),
		nestedString(payload.Payload, "conversation", "name"),
		nestedString(payload.Payload, "conversation", "id"),
		"unknown channel",
	)
}

func atlassianResource(payload JobPayload) string {
	return firstNonEmpty(
		nestedString(payload.Payload, "space", "name"),
		nestedString(payload.Payload, "space", "key"),
		nestedString(payload.Payload, "project", "name"),
		nestedString(payload.Payload, "project", "key"),
		nestedString(payload.Payload, "resource", "name"),
		nestedString(payload.Payload, "target", "name"),
		"Atlassian resource",
	)
}

func salesforceUser(payload JobPayload) string {
	return firstNonEmpty(
		nestedString(payload.Payload, "target", "email"),
		nestedString(payload.Payload, "target", "username"),
		nestedString(payload.Payload, "user", "email"),
		nestedString(payload.Payload, "user", "username"),
		payload.Actor,
		"unknown user",
	)
}

func recordSuggestsDisabledState(record map[string]any) bool {
	blob := strings.ToLower(strings.Join(flattenAnyStrings(record), " "))
	for _, disabled := range []string{"disabled", "off", "false", "not enabled", "inactive"} {
		if strings.Contains(blob, disabled) {
			return true
		}
	}
	return false
}

func recordSuggestsWeakenedPolicy(record map[string]any) bool {
	blob := strings.ToLower(strings.Join(flattenAnyStrings(record), " "))
	for _, weakened := range []string{
		"disabled",
		"removed",
		"deleted",
		"false",
		"not required",
		"relaxed",
		"bypass",
		"allow all",
		"all users may self-authorize",
		"ip relaxation",
		"refresh token",
		"never expires",
		"admin approved users disabled",
	} {
		if strings.Contains(blob, weakened) {
			return true
		}
	}
	return false
}

func flattenAnyStrings(value any) []string {
	values := []string{}
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			values = append(values, typed)
		}
	case []string:
		values = append(values, typed...)
	case []any:
		for _, item := range typed {
			values = append(values, flattenAnyStrings(item)...)
		}
	case map[string]any:
		for _, key := range sortedRecordKeys(typed) {
			values = append(values, key)
			values = append(values, flattenAnyStrings(typed[key])...)
		}
	case bool:
		values = append(values, strconv.FormatBool(typed))
	case float64, float32, int, int64, int32, json.Number:
		values = append(values, fmt.Sprint(typed))
	}
	return values
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func googleParameters(payload JobPayload) map[string]any {
	parameters := nestedRecord(payload.Payload, "parameters")
	if parameters == nil {
		return map[string]any{}
	}
	return parameters
}

func sortedRecordKeys(record map[string]any) []string {
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func googleForwardingAddresses(parameters map[string]any) []string {
	addresses := []string{}
	for _, key := range []string{
		"forward_to",
		"forwarding_address",
		"forwarding_email",
		"forwarding_destination",
		"email_forwarding_destination",
	} {
		addresses = append(addresses, emailsFromValue(parameters[key])...)
	}
	for _, key := range sortedRecordKeys(parameters) {
		addresses = append(addresses, emailsFromValue(parameters[key])...)
	}
	return addresses
}

func googleDelegateAddresses(parameters map[string]any) []string {
	addresses := []string{}
	for _, key := range []string{"delegate", "delegate_email", "delegateAddress"} {
		addresses = append(addresses, emailsFromValue(parameters[key])...)
	}
	for _, key := range sortedRecordKeys(parameters) {
		if strings.Contains(strings.ToLower(key), "delegate") {
			addresses = append(addresses, emailsFromValue(parameters[key])...)
		}
	}
	return addresses
}

func flattenRecordStrings(record map[string]any) []string {
	values := []string{}
	for _, key := range sortedRecordKeys(record) {
		values = append(values, stringArray(record[key])...)
	}
	return values
}

func nestedNumber(value map[string]any, path ...string) (float64, bool) {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return 0, false
		}
		current = next[segment]
	}
	switch typed := current.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func DedupeKey(payload JobPayload, finding Finding) string {
	dedupeTarget := finding.Target
	if strings.TrimSpace(finding.DedupeTarget) != "" {
		dedupeTarget = finding.DedupeTarget
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		payload.OrganizationID,
		payload.IntegrationID,
		finding.RuleID,
		dedupeTarget,
	}, ":")))
	return hex.EncodeToString(sum[:])
}

func (w *Worker) Drain(ctx context.Context, limit int) (Result, error) {
	if w.db == nil {
		return Result{}, errors.New("database is required")
	}
	limit = boundedLimit(limit)
	if err := w.retireExhausted(ctx); err != nil {
		return Result{}, err
	}
	jobs, err := w.claim(ctx, limit)
	if err != nil {
		return Result{}, err
	}
	result := Result{Processed: len(jobs)}
	for _, item := range jobs {
		w.publishIngestionJobLifecycleEvent(ctx, item, "running", item.Attempts, "")
		startedAt := time.Now()
		err := w.process(ctx, item)
		emitIngestionJobWideEvent(item, err, time.Since(startedAt))
		if err != nil {
			result.Failed++
		} else {
			result.Succeeded++
		}
	}
	return result, nil
}

func (w *Worker) retireExhausted(ctx context.Context) error {
	_, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'DEAD_LETTER',
			lease_owner = NULL,
			lease_expires_at = NULL,
			last_error = COALESCE(last_error, 'maximum ingestion attempts exhausted'),
			updated_at = NOW()
		WHERE attempts >= max_attempts
		  AND status IN ('QUEUED', 'FAILED', 'RUNNING')
		  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
	`)
	return err
}

func (w *Worker) claim(ctx context.Context, limit int) ([]job, error) {
	rows, err := w.db.QueryContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'RUNNING', lease_owner = $1, lease_expires_at = $2, updated_at = NOW()
		WHERE id IN (
			SELECT id
			FROM ingestion_jobs
			WHERE attempts < max_attempts
			  AND next_attempt_at <= NOW()
			  AND (
					(status IN ('QUEUED', 'FAILED') AND (lease_expires_at IS NULL OR lease_expires_at <= NOW()))
				 OR (status = 'RUNNING' AND lease_expires_at <= NOW())
			  )
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		RETURNING id, organization_id, integration_id, provider::text, event_type, source, actor, occurred_at, payload, attempts, max_attempts
	`, w.leaseOwner, time.Now().UTC().Add(leaseDuration), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []job{}
	for rows.Next() {
		var item job
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.IntegrationID, &item.Provider, &item.EventType, &item.Source, &item.Actor, &item.OccurredAt, &item.Payload, &item.Attempts, &item.MaxAttempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, item)
	}
	return jobs, rows.Err()
}

func isSupportedIngestionWork(provider string, eventType string) bool {
	for _, supportedEventType := range supportedIngestionEventTypes[provider] {
		if eventType == supportedEventType {
			return true
		}
	}
	return false
}

func (w *Worker) deadLetterUnsupported(ctx context.Context, item job) error {
	message := "unsupported ingestion work: provider/event type is outside the final Go ingestion matrix"
	attempts := item.Attempts + 1
	res, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'DEAD_LETTER',
			attempts = $1,
			next_attempt_at = NOW(),
			lease_owner = NULL,
			lease_expires_at = NULL,
			last_error = $2,
			updated_at = NOW()
		WHERE id = $3 AND lease_owner = $4
	`, attempts, safeIngestionFailureMessage(message), item.ID, w.leaseOwner)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		return errIngestionLeaseLost
	}
	w.publishIngestionJobLifecycleEvent(ctx, item, "dead_letter", attempts, "")
	return fmt.Errorf("%w: provider/event type is outside the final Go ingestion matrix", errUnsupportedIngestionWork)
}

func (w *Worker) process(ctx context.Context, item job) error {
	if !isSupportedIngestionWork(item.Provider, item.EventType) {
		return w.deadLetterUnsupported(ctx, item)
	}
	payload, err := item.toPayload()
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("parse payload: %w", err).Error())
	}
	findings, resolutions, err := w.evaluateJob(ctx, payload, item)
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("load findings: %w", err).Error())
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return w.fail(ctx, item, fmt.Errorf("begin transaction: %w", err).Error())
	}
	txDone := false
	defer func() {
		if !txDone {
			_ = tx.Rollback()
		}
	}()
	fail := func(err error) error {
		txDone = true
		_ = tx.Rollback()
		return w.fail(ctx, item, err.Error())
	}
	lifecycleEvents := []FindingLifecycleEvent{}
	cerebroPayloads := []cerebrofanout.FindingPayload{}
	eventID := "evt_" + randomID()
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO ingested_events (id, organization_id, integration_id, ingestion_job_id, provider, event_type, source, actor, severity, payload, processing_status, occurred_at, processed_at, created_at)
		VALUES ($1,$2,$3,$4,$5::"SaaSProvider",$6,$7,$8,'INFO'::"Severity",$9::jsonb,'RECEIVED'::"EventProcessingStatus",$10,NULL,NOW())
		ON CONFLICT (ingestion_job_id) DO UPDATE SET payload = EXCLUDED.payload, processing_status = 'RECEIVED'::"EventProcessingStatus", processed_at = NULL, severity = 'INFO'::"Severity"
		RETURNING id
	`, eventID, item.OrganizationID, item.IntegrationID, item.ID, item.Provider, item.EventType, item.Source, nullableString(item.Actor), string(item.Payload), item.OccurredAt).Scan(&eventID); err != nil {
		return fail(fmt.Errorf("upsert ingested event: %w", err))
	}
	for _, resolution := range resolutions {
		resolvedID, changed, err := resolveDeclarativeFinding(ctx, tx, payload, resolution, eventID)
		if err != nil {
			return fail(fmt.Errorf("auto-resolve finding: %w", err))
		}
		if changed {
			lifecycleEvents = append(lifecycleEvents, FindingLifecycleEvent{
				FindingID:      resolvedID,
				OrganizationID: payload.OrganizationID,
				IntegrationID:  payload.IntegrationID,
				PreviousStatus: "OPEN",
				NextStatus:     "RESOLVED",
				OccurredAt:     payload.OccurredAt,
				ResolutionNote: "Declarative rule observed a clean provider state",
			})
		}
	}
	for _, finding := range findings {
		persisted, err := upsertFinding(ctx, tx, payload, finding, eventID)
		if err != nil {
			return fail(fmt.Errorf("upsert finding: %w", err))
		}
		if err := enqueueFindingDelivery(ctx, tx, payload, finding, eventID, persisted); err != nil {
			return fail(fmt.Errorf("enqueue SIEM delivery: %w", err))
		}
		cerebroPayloads = append(cerebroPayloads, cerebroFindingPayload(findingPayload(payload, finding, eventID, persisted)))
		if shouldPublishFindingLifecycle(persisted) {
			lifecycleEvents = append(lifecycleEvents, FindingLifecycleEvent{
				FindingID:      persisted.ID,
				OrganizationID: payload.OrganizationID,
				IntegrationID:  payload.IntegrationID,
				PreviousStatus: persisted.PreviousStatus,
				NextStatus:     persisted.Status,
				OccurredAt:     payload.OccurredAt,
				ResolutionNote: lifecycleResolutionNote(persisted),
			})
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE ingested_events
		SET severity = $2::"Severity", processing_status = 'PROCESSED'::"EventProcessingStatus", processed_at = NOW()
		WHERE id = $1 AND organization_id = $3
	`, eventID, eventSeverity(findings), item.OrganizationID); err != nil {
		return fail(fmt.Errorf("finalize ingested event: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE integration_connections
		SET last_sync_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND organization_id = $2
	`, item.IntegrationID, item.OrganizationID); err != nil {
		return fail(fmt.Errorf("update integration last sync: %w", err))
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
		WHERE id = $1 AND lease_owner = $2
	`, item.ID, w.leaseOwner)
	if err != nil {
		return fail(fmt.Errorf("mark job succeeded: %w", err))
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		txDone = true
		_ = tx.Rollback()
		return errIngestionLeaseLost
	}
	if err := tx.Commit(); err != nil {
		txDone = true
		return w.fail(ctx, item, fmt.Errorf("commit transaction: %w", err).Error())
	}
	txDone = true
	w.fanoutCerebroFindings(ctx, cerebroPayloads)
	w.publishFindingLifecycleEvents(ctx, lifecycleEvents)
	w.publishIngestionJobLifecycleEvent(ctx, item, "succeeded", item.Attempts+1, eventID)
	return nil
}

func (w *Worker) fail(ctx context.Context, item job, message string) error {
	if err := w.finish(ctx, item, false, message); err != nil {
		return err
	}
	attempts := item.Attempts + 1
	status := "failed"
	if attempts >= item.MaxAttempts {
		status = "dead_letter"
	}
	w.publishIngestionJobLifecycleEvent(ctx, item, status, attempts, "")
	return errors.New(message)
}

func (w *Worker) findingsForJob(ctx context.Context, payload JobPayload, item job) ([]Finding, error) {
	findings, _, err := w.evaluateJob(ctx, payload, item)
	return findings, err
}

func (w *Worker) evaluateJob(ctx context.Context, payload JobPayload, item job) ([]Finding, []declarativeResolution, error) {
	builtinRun := observability.StartRuleRun(ctx, w.db, item.OrganizationID, item.IntegrationID, item.Provider, item.ID, observability.RulePackBuiltIn, "v1", builtInRuleCount(item.Provider))
	config, err := w.loadIntegrationConfig(ctx, item)
	if err != nil {
		builtinRun.Finish(ctx, "FAILED", 0, err)
		return nil, nil, err
	}
	if err := config.validateForJob(item); err != nil {
		builtinRun.Finish(ctx, "FAILED", 0, err)
		return nil, nil, err
	}
	findings := EvaluateWithSeverityOverrides(payload, config.DisabledChecks, config.SeverityOverrides)
	builtinRun.Finish(ctx, "SUCCEEDED", len(findings), nil)
	resolutions, loaded := declarativeResolutionTargets(payload, config.DisabledChecks)
	if !loaded {
		resolutions = nil
	}
	customRun := observability.StartRuleRun(ctx, w.db, item.OrganizationID, item.IntegrationID, item.Provider, item.ID, observability.RulePackCustom, "v1", 0)
	customRules, err := w.loadCustomRules(ctx, item.IntegrationID)
	if err != nil {
		// A custom-rule load failure must NOT block built-in findings; a
		// schema migration glitch or transient pgx connection blip would
		// otherwise mask real-finding ingestion. Log via the caller's
		// observability surface and fall through with the built-ins.
		customRun.Finish(ctx, "FAILED", 0, err)
		return findings, resolutions, nil
	}
	if len(customRules) > 0 {
		customRun.SetRulesEvaluated(len(customRules))
		customFindings := EvaluateCustomRules(payload, customRules)
		customRun.Finish(ctx, "SUCCEEDED", len(customFindings), nil)
		findings = append(findings, customFindings...)
	} else {
		customRun.Finish(ctx, "SUCCEEDED", 0, nil)
	}
	return findings, resolutions, nil
}

func (w *Worker) loadCustomRules(ctx context.Context, integrationID string) ([]CustomRule, error) {
	rows, err := w.db.QueryContext(ctx, `
		SELECT id, organization_id, integration_id, name, severity::text, event_type, subject_field, predicate, enabled
		FROM custom_finding_rules
		WHERE integration_id = $1 AND enabled = true
	`, integrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomRule
	for rows.Next() {
		var r CustomRule
		var predicateRaw []byte
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.IntegrationID, &r.Name, &r.Severity, &r.EventType, &r.SubjectField, &predicateRaw, &r.Enabled); err != nil {
			return nil, err
		}
		r.Predicate = predicateRaw
		out = append(out, r)
	}
	return out, rows.Err()
}

func (w *Worker) loadIntegrationConfig(ctx context.Context, item job) (integrationConfig, error) {
	var config integrationConfig
	var rawDisabledChecks string
	var rawDisabledMetadata string
	if err := w.db.QueryRowContext(ctx, `
		SELECT
			id,
			organization_id,
			provider::text,
			external_account_id,
			COALESCE(array_to_json(disabled_checks)::text, '[]'),
			COALESCE(disabled_check_metadata::text, '{}'),
			encrypted_access_token,
			encrypted_refresh_token,
			encrypted_webhook_secret,
			google_mailbox_scan_client_email,
			encrypted_google_mailbox_scan_private_key
		FROM integration_connections
		WHERE id = $1 AND organization_id = $2 AND provider = $3::"SaaSProvider" AND status = 'CONNECTED'
	`, item.IntegrationID, item.OrganizationID, item.Provider).Scan(
		&config.ID,
		&config.OrganizationID,
		&config.Provider,
		&config.ExternalAccountID,
		&rawDisabledChecks,
		&rawDisabledMetadata,
		&config.EncryptedAccessToken,
		&config.EncryptedRefreshToken,
		&config.EncryptedWebhookSecret,
		&config.GoogleMailboxScanClientEmail,
		&config.EncryptedGoogleMailboxScanPrivateKey,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return integrationConfig{}, errIntegrationNotConnected
		}
		return integrationConfig{}, err
	}
	if err := json.Unmarshal([]byte(rawDisabledChecks), &config.DisabledChecks); err != nil {
		return integrationConfig{}, errIntegrationConfigurationIncomplete
	}
	metadata := decodeDisabledCheckMetadata(rawDisabledMetadata)
	now := time.Now().UTC()
	config.DisabledChecks = applyDisabledCheckExpiry(config.DisabledChecks, metadata, now)
	config.SeverityOverrides = severityOverridesFromMetadata(metadata, now)
	return config, nil
}

func (config integrationConfig) validateForJob(item job) error {
	if strings.TrimSpace(config.ID) == "" ||
		strings.TrimSpace(config.OrganizationID) == "" ||
		strings.TrimSpace(config.Provider) == "" ||
		strings.TrimSpace(config.ExternalAccountID) == "" {
		return errIntegrationConfigurationIncomplete
	}
	if config.ID != item.IntegrationID || config.OrganizationID != item.OrganizationID || config.Provider != item.Provider {
		return errIntegrationNotConnected
	}
	if _, err := config.decryptRequiredSecret("access_token", 8); err != nil {
		return err
	}
	if requiresRefreshToken(config.Provider) && strings.TrimSpace(nullStringValue(config.EncryptedRefreshToken)) == "" {
		return errIntegrationConfigurationIncomplete
	}
	if _, err := config.decryptOptionalSecret(config.EncryptedRefreshToken, "refresh_token"); err != nil {
		return err
	}
	if _, err := config.decryptOptionalSecret(config.EncryptedWebhookSecret, "webhook_secret"); err != nil {
		return err
	}
	if err := config.validateGoogleMailboxConfig(item.EventType); err != nil {
		return err
	}
	return nil
}

func (config integrationConfig) decryptRequiredSecret(suffix string, minLength int) (string, error) {
	encrypted := strings.TrimSpace(config.EncryptedAccessToken)
	if encrypted == "" {
		return "", errIntegrationCredentialMissing
	}
	return config.decryptSecret(encrypted, suffix, minLength)
}

func (config integrationConfig) decryptOptionalSecret(value sql.NullString, suffix string) (string, error) {
	encrypted := strings.TrimSpace(nullStringValue(value))
	if encrypted == "" {
		return "", nil
	}
	return config.decryptSecret(encrypted, suffix, 1)
}

func (config integrationConfig) decryptSecret(encrypted string, suffix string, minLength int) (string, error) {
	plaintext, err := runtimeutil.DecryptIntegrationSecret(encrypted, config.OrganizationID, config.ID, config.Provider, config.ExternalAccountID, suffix)
	if err != nil {
		return "", errIntegrationCredentialUnavailable
	}
	if len(strings.TrimSpace(plaintext)) < minLength {
		return "", errIntegrationCredentialIntegrity
	}
	return plaintext, nil
}

func (config integrationConfig) validateGoogleMailboxConfig(_ string) error {
	if config.Provider != "GOOGLE_WORKSPACE" {
		return nil
	}
	clientEmail := strings.TrimSpace(nullStringValue(config.GoogleMailboxScanClientEmail))
	encryptedPrivateKey := strings.TrimSpace(nullStringValue(config.EncryptedGoogleMailboxScanPrivateKey))
	if clientEmail != "" || encryptedPrivateKey != "" {
		if clientEmail == "" || encryptedPrivateKey == "" {
			return errIntegrationConfigurationIncomplete
		}
		privateKey, err := runtimeutil.DecryptGoogleMailboxPrivateKey(encryptedPrivateKey, config.OrganizationID, config.ID, config.ExternalAccountID)
		if err != nil {
			return errIntegrationCredentialUnavailable
		}
		if len(strings.TrimSpace(privateKey)) < 8 {
			return errIntegrationCredentialIntegrity
		}
	}
	return nil
}

func requiresRefreshToken(provider string) bool {
	switch provider {
	case "GITHUB", "OKTA", "MICROSOFT_365", "GOOGLE_WORKSPACE":
		return true
	default:
		return false
	}
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func upsertFinding(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding, eventID string) (persistedFinding, error) {
	dedupe := DedupeKey(payload, finding)
	previousStatus := "NEW"
	var existingStatus string
	err := tx.QueryRowContext(ctx, `
		SELECT status::text
		FROM security_findings
		WHERE organization_id = $1 AND dedupe_key = $2
	`, payload.OrganizationID, dedupe).Scan(&existingStatus)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return persistedFinding{}, err
	}
	if err == nil {
		previousStatus = existingStatus
	}
	evidence := buildFindingEvidence(payload, finding, eventID)
	evidenceJSON, _ := json.Marshal(evidence)
	tags := normalizeTags(finding.Tags)
	persisted := persistedFinding{PreviousStatus: previousStatus}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO security_findings (
			id, organization_id, integration_id, event_id, dedupe_key, title, description, severity,
			status, risk_score, remediation_steps, tags, evidence, detected_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::"Severity",'OPEN'::"FindingStatus",$9,$10::text[],$11::text[],$12::jsonb,$13)
		ON CONFLICT (organization_id, dedupe_key) DO UPDATE SET
			event_id = EXCLUDED.event_id,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			severity = EXCLUDED.severity,
			status = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN 'MUTED'::"FindingStatus" ELSE 'OPEN'::"FindingStatus" END,
			resolved_at = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN security_findings.resolved_at ELSE NULL END,
			resolved_by_id = CASE WHEN security_findings.status = 'MUTED'::"FindingStatus" THEN security_findings.resolved_by_id ELSE NULL END,
			risk_score = EXCLUDED.risk_score,
			remediation_steps = EXCLUDED.remediation_steps,
			tags = EXCLUDED.tags,
			evidence = EXCLUDED.evidence
		RETURNING id, status::text
	`, "fnd_"+randomID(), payload.OrganizationID, payload.IntegrationID, eventID, dedupe, finding.Title, finding.Description, finding.Severity, finding.RiskScore, postgresTextArray(finding.RemediationSteps), postgresTextArray(tags), string(evidenceJSON), payload.OccurredAt).Scan(&persisted.ID, &persisted.Status)
	return persisted, err
}

// resolveDeclarativeFinding performs the state transition requested by a
// pure auto-resolve draft. The lookup is tenant and integration scoped, and
// only OPEN findings transition; muted, already-resolved, or another
// integration's finding is never changed by a clean provider event.
func resolveDeclarativeFinding(ctx context.Context, tx *sql.Tx, payload JobPayload, resolution declarativeResolution, eventID string) (string, bool, error) {
	placeholder := Finding{
		RuleID:       resolution.RuleID,
		RuleVersion:  resolution.RuleVersion,
		Target:       resolution.DedupeTarget,
		DedupeTarget: resolution.DedupeTarget,
	}
	dedupe := DedupeKey(payload, placeholder)
	evidence, err := json.Marshal(map[string]any{
		"ruleId":        resolution.RuleID,
		"ruleVersion":   resolution.RuleVersion,
		"subject":       resolution.DedupeTarget,
		"sourceEventId": eventID,
		"eventType":     payload.EventType,
		"resolution":    "auto_resolve_when",
	})
	if err != nil {
		return "", false, err
	}
	var findingID string
	err = tx.QueryRowContext(ctx, `
		UPDATE security_findings
		SET status = 'RESOLVED'::"FindingStatus",
			resolved_at = $1,
			resolved_by_id = NULL,
			evidence = COALESCE(evidence, '{}'::jsonb) || $2::jsonb
		WHERE organization_id = $3
		  AND integration_id = $4
		  AND dedupe_key = $5
		  AND COALESCE(evidence->>'ruleId', '') = $6
		  AND status = 'OPEN'::"FindingStatus"
		RETURNING id
	`, payload.OccurredAt, string(evidence), payload.OrganizationID, payload.IntegrationID, dedupe, resolution.RuleID).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return findingID, true, nil
}

func buildFindingEvidence(payload JobPayload, finding Finding, eventID string) map[string]any {
	subject := finding.Target
	if strings.TrimSpace(finding.DedupeTarget) != "" {
		subject = finding.DedupeTarget
	}
	evidence := map[string]any{
		"ruleId":        finding.RuleID,
		"target":        finding.Target,
		"subject":       subject,
		"provider":      payload.Provider,
		"source":        payload.Source,
		"eventType":     payload.EventType,
		"sourceEventId": eventID,
	}
	if strings.TrimSpace(finding.RuleVersion) != "" {
		evidence["ruleVersion"] = finding.RuleVersion
	}
	addNonEmptyEvidence(evidence, "actor", payload.Actor)
	addNonEmptyEvidence(evidence, "application", nestedString(payload.Payload, "application"))
	addNonEmptyEvidence(evidence, "sourceIp", nestedString(payload.Payload, "ipAddress"))
	for key, value := range finding.Evidence {
		if value != nil {
			evidence[key] = value
		}
	}
	return evidence
}

func addNonEmptyEvidence(evidence map[string]any, key string, value string) {
	if strings.TrimSpace(value) != "" {
		evidence[key] = strings.TrimSpace(value)
	}
}

func eventSeverity(findings []Finding) string {
	for _, finding := range findings {
		if finding.Severity == "CRITICAL" {
			return "CRITICAL"
		}
	}
	if len(findings) > 0 && strings.TrimSpace(findings[0].Severity) != "" {
		return findings[0].Severity
	}
	return "INFO"
}

func shouldPublishFindingLifecycle(finding persistedFinding) bool {
	return finding.PreviousStatus == "NEW" || (finding.PreviousStatus != "" && finding.PreviousStatus != finding.Status)
}

func lifecycleResolutionNote(finding persistedFinding) string {
	if finding.PreviousStatus == "RESOLVED" && finding.Status == "OPEN" {
		return "Finding observed again during ingestion"
	}
	return "Finding observed during ingestion"
}

func (w *Worker) publisher() IngestionEventPublisher {
	if w.eventPublisher != nil {
		return w.eventPublisher
	}
	return noopIngestionEventPublisher{}
}

func (w *Worker) publishIngestionJobLifecycleEvent(ctx context.Context, item job, status string, attempts int, sourceEventID string) {
	_ = w.publisher().PublishIngestionJobLifecycle(ctx, IngestionJobLifecycleEvent{
		JobID:          item.ID,
		OrganizationID: item.OrganizationID,
		IntegrationID:  item.IntegrationID,
		Provider:       item.Provider,
		EventType:      item.EventType,
		Source:         item.Source,
		Actor:          nullableString(item.Actor),
		Status:         status,
		Attempts:       attempts,
		SourceEventID:  sourceEventID,
		OccurredAt:     item.OccurredAt,
		Payload:        item.Payload,
	})
}

func (w *Worker) publishFindingLifecycleEvents(ctx context.Context, events []FindingLifecycleEvent) {
	if len(events) == 0 {
		return
	}
	publisher := w.publisher()
	for _, event := range events {
		_ = publisher.PublishFindingLifecycle(ctx, event)
	}
}

func (w *Worker) fanoutCerebroFindings(ctx context.Context, payloads []cerebrofanout.FindingPayload) {
	if w.cerebroFanout == nil || len(payloads) == 0 {
		return
	}
	for _, payload := range payloads {
		_, _ = w.cerebroFanout.FanoutFinding(ctx, payload)
	}
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

func enqueueFindingDelivery(ctx context.Context, tx *sql.Tx, payload JobPayload, finding Finding, eventID string, persisted persistedFinding) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id
		FROM siem_destinations
		WHERE organization_id = $1 AND status IN ('ACTIVE', 'ERROR') AND 'FINDINGS' = ANY(streams)
	`, payload.OrganizationID)
	if err != nil {
		return err
	}
	destinationIDs := []string{}
	for rows.Next() {
		var destinationID string
		if err := rows.Scan(&destinationID); err != nil {
			_ = rows.Close()
			return err
		}
		destinationIDs = append(destinationIDs, destinationID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	deliveryPayload := findingPayload(payload, finding, eventID, persisted)
	for _, destinationID := range destinationIDs {
		payloadJSON, _ := json.Marshal(deliveryPayload)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO siem_deliveries (id, organization_id, destination_id, stream, dedupe_key, payload, created_at, updated_at)
			VALUES ($1,$2,$3,'FINDINGS'::"SiemStreamType",$4,$5::jsonb,NOW(),NOW())
			ON CONFLICT (organization_id, destination_id, stream, dedupe_key) DO NOTHING
		`, "sdel_"+randomID(), payload.OrganizationID, destinationID, siemdispatcher.StableDeliveryKey(deliveryPayload, destinationID, "FINDINGS"), string(payloadJSON))
		if err != nil {
			return err
		}
	}
	return nil
}

func findingPayload(payload JobPayload, finding Finding, eventID string, persisted persistedFinding) siemdispatcher.Payload {
	status := persisted.Status
	if status == "" {
		status = "OPEN"
	}
	var actor any
	if payload.Actor != "" {
		actor = payload.Actor
	}
	record := map[string]any{
		"schemaVersion":    "aperio.finding.v1",
		"findingId":        persisted.ID,
		"dedupeKey":        DedupeKey(payload, finding),
		"sourceEventId":    eventID,
		"status":           status,
		"ruleId":           finding.RuleID,
		"title":            finding.Title,
		"description":      finding.Description,
		"severity":         finding.Severity,
		"riskScore":        finding.RiskScore,
		"remediationSteps": finding.RemediationSteps,
		"tags":             normalizeTags(finding.Tags),
		"target":           finding.Target,
		"provider":         payload.Provider,
		"integrationId":    payload.IntegrationID,
		"source":           payload.Source,
		"eventType":        payload.EventType,
		"actor":            actor,
	}
	if strings.TrimSpace(finding.RuleVersion) != "" {
		record["ruleVersion"] = finding.RuleVersion
	}
	addOAuthClaimRecordFields(record, payload, finding)
	return siemdispatcher.Payload{
		Kind:           "finding",
		OrganizationID: payload.OrganizationID,
		OccurredAt:     payload.OccurredAt.UTC().Format(time.RFC3339Nano),
		Record:         record,
	}
}

func addOAuthClaimRecordFields(record map[string]any, payload JobPayload, finding Finding) {
	if !containsString(normalizeTags(finding.Tags), TagOAuthRiskyGrant) && !strings.Contains(strings.ToLower(finding.RuleID), "oauth") {
		return
	}
	evidence := finding.Evidence
	appName := firstNonEmpty(
		evidenceString(evidence, "appName", "app", "oauthAppName", "application"),
		finding.Target,
	)
	appID := firstNonEmpty(
		evidenceString(evidence, "clientId", "clientID", "oauthAppId", "externalAppId", "applicationId"),
		evidenceString(evidence, "subject"),
		appName,
	)
	scopes := uniqueStrings(append(
		stringArray(evidence["scopes"]),
		stringArray(evidence["scope"])...,
	))
	userEmail := firstNonEmpty(
		evidenceString(evidence, "userEmail", "user", "actor"),
		payload.Actor,
	)
	addRecordString(record, "oauthAppName", appName)
	addRecordString(record, "oauthAppId", appID)
	addRecordString(record, "oauthClientType", evidenceString(evidence, "clientType"))
	addRecordString(record, "oauthRiskReason", evidenceString(evidence, "riskReason"))
	addRecordString(record, "oauthUserEmail", userEmail)
	if len(scopes) > 0 {
		record["oauthScopes"] = scopes
		record["oauthScopeCount"] = len(scopes)
	}
	if matchedScopes := uniqueStrings(stringArray(evidence["matchedScopes"])); len(matchedScopes) > 0 {
		record["oauthMatchedScopes"] = matchedScopes
	}
}

func addRecordString(record map[string]any, key string, value string) {
	if strings.TrimSpace(value) != "" {
		record[key] = strings.TrimSpace(value)
	}
}

func evidenceString(evidence map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := evidence[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case json.Number:
			if string(value) != "" {
				return string(value)
			}
		case int:
			return strconv.Itoa(value)
		case int64:
			return strconv.FormatInt(value, 10)
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64)
		}
	}
	return ""
}

func cerebroFindingPayload(payload siemdispatcher.Payload) cerebrofanout.FindingPayload {
	return cerebrofanout.FindingPayload{
		OrganizationID: payload.OrganizationID,
		Kind:           payload.Kind,
		OccurredAt:     payload.OccurredAt,
		Record:         payload.Record,
	}
}

func (w *Worker) finish(ctx context.Context, item job, ok bool, message string) error {
	if ok {
		res, err := w.db.ExecContext(ctx, `
			UPDATE ingestion_jobs
			SET status = 'SUCCEEDED', attempts = attempts + 1, processed_at = NOW(), lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW()
			WHERE id = $1 AND lease_owner = $2
		`, item.ID, w.leaseOwner)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil && rows != 1 {
			return errIngestionLeaseLost
		}
		return nil
	}
	attempts := item.Attempts + 1
	status := "FAILED"
	if attempts >= item.MaxAttempts {
		status = "DEAD_LETTER"
	}
	res, err := w.db.ExecContext(ctx, `
		UPDATE ingestion_jobs
		SET status = $1, attempts = $2, next_attempt_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = $4, updated_at = NOW()
		WHERE id = $5 AND lease_owner = $6
	`, status, attempts, time.Now().UTC().Add(nextRetryDelay(attempts)), safeIngestionFailureMessage(message), item.ID, w.leaseOwner)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err == nil && rows != 1 {
		return errIngestionLeaseLost
	}
	return nil
}

func (j job) toPayload() (JobPayload, error) {
	var record map[string]any
	if err := json.Unmarshal(j.Payload, &record); err != nil {
		return JobPayload{}, err
	}
	if record == nil {
		return JobPayload{}, errIngestionPayloadNotObject
	}
	return JobPayload{
		OrganizationID: j.OrganizationID,
		IntegrationID:  j.IntegrationID,
		Provider:       j.Provider,
		EventType:      j.EventType,
		Source:         j.Source,
		Actor:          nullableString(j.Actor),
		OccurredAt:     j.OccurredAt,
		Payload:        record,
	}, nil
}

func normalizeEventType(value string) string {
	var builder strings.Builder
	lastWasSeparator := false
	for _, char := range strings.ToUpper(value) {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
			lastWasSeparator = false
			continue
		}
		if !lastWasSeparator {
			builder.WriteByte('_')
			lastWasSeparator = true
		}
	}
	return strings.Trim(builder.String(), "_")
}

func recordArray(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	records := []map[string]any{}
	for _, item := range items {
		record, ok := item.(map[string]any)
		if ok {
			records = append(records, record)
		}
	}
	return records
}

func topLevelRecord(value map[string]any, key string) map[string]any {
	record, _ := value[key].(map[string]any)
	return record
}

func stringValue(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func optionalString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func nestedRecord(value map[string]any, path ...string) map[string]any {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = next[segment]
	}
	record, _ := current.(map[string]any)
	return record
}

func nestedString(value map[string]any, path ...string) string {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[segment]
	}
	text, _ := current.(string)
	return strings.TrimSpace(text)
}

func nestedBool(value map[string]any, path ...string) (bool, bool) {
	var current any = value
	for _, segment := range path {
		next, ok := current.(map[string]any)
		if !ok {
			return false, false
		}
		current = next[segment]
	}
	result, ok := current.(bool)
	return result, ok
}

func nestedBoolValue(value map[string]any, path ...string) bool {
	result, ok := nestedBool(value, path...)
	return ok && result
}

func numericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func booleanValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func oktaEntityLabel(entity map[string]any) string {
	if entity == nil {
		return ""
	}
	return firstNonEmpty(
		stringValue(entity["alternateId"]),
		stringValue(entity["id"]),
		stringValue(entity["displayName"]),
		stringValue(entity["login"]),
	)
}

func oktaActor(payload JobPayload) string {
	return firstNonEmpty(
		oktaEntityLabel(topLevelRecord(payload.Payload, "actor")),
		payload.Actor,
		"unknown actor",
	)
}

func oktaTargets(payload JobPayload) []map[string]any {
	return recordArray(payload.Payload["target"])
}

func oktaTargetByType(payload JobPayload, fragments []string) map[string]any {
	normalized := make([]string, 0, len(fragments))
	for _, fragment := range fragments {
		normalized = append(normalized, strings.ToLower(fragment))
	}
	for _, target := range oktaTargets(payload) {
		targetType := strings.ToLower(stringValue(target["type"]))
		for _, fragment := range normalized {
			if strings.Contains(targetType, fragment) {
				return target
			}
		}
	}
	return nil
}

func oktaUserTarget(payload JobPayload) string {
	targets := oktaTargets(payload)
	firstTarget := map[string]any(nil)
	if len(targets) > 0 {
		firstTarget = targets[0]
	}
	return firstNonEmpty(
		oktaEntityLabel(oktaTargetByType(payload, []string{"user"})),
		oktaEntityLabel(firstTarget),
		payload.Actor,
		"unknown user",
	)
}

func oktaDebugData(payload JobPayload) map[string]any {
	if debugData := nestedRecord(payload.Payload, "debugContext", "debugData"); debugData != nil {
		return debugData
	}
	return map[string]any{}
}

func oktaRoleName(payload JobPayload) string {
	debugData := oktaDebugData(payload)
	roleTarget := oktaTargetByType(payload, []string{"role", "privilege"})
	return firstNonEmpty(
		nestedString(debugData, "role"),
		nestedString(debugData, "roleName"),
		nestedString(debugData, "privilege"),
		nestedString(debugData, "privilegeName"),
		oktaEntityLabel(roleTarget),
		"admin role",
	)
}

func isPrivilegedOktaRole(role string) bool {
	normalized := normalizeEventType(role)
	return strings.Contains(normalized, "SUPER_ADMIN") ||
		strings.Contains(normalized, "SUPER_ADMINISTRATOR") ||
		strings.Contains(normalized, "ORG_ADMIN") ||
		strings.Contains(normalized, "ORGANIZATION_ADMINISTRATOR") ||
		strings.Contains(normalized, "APP_ADMIN") ||
		strings.Contains(normalized, "APPLICATION_ADMINISTRATOR")
}

func oktaPasswordPolicyName(payload JobPayload) string {
	debugData := oktaDebugData(payload)
	return firstNonEmpty(
		nestedString(debugData, "policyName"),
		nestedString(debugData, "policy"),
		oktaEntityLabel(oktaTargetByType(payload, []string{"policy"})),
		"Okta password policy",
	)
}

func oktaIsPasswordPolicy(payload JobPayload) bool {
	debugData := oktaDebugData(payload)
	candidates := []string{
		nestedString(debugData, "policyType"),
		nestedString(debugData, "type"),
		nestedString(debugData, "policyName"),
		nestedString(debugData, "policy"),
	}
	for _, target := range oktaTargets(payload) {
		candidates = append(candidates,
			stringValue(target["type"]),
			stringValue(target["displayName"]),
			stringValue(target["name"]),
		)
	}
	for _, candidate := range candidates {
		if strings.Contains(strings.ToLower(candidate), "password") {
			return true
		}
	}
	return false
}

func valueByKeys(record map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := record[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func oktaChangeDetails(payload JobPayload) []map[string]any {
	debugData := oktaDebugData(payload)
	changes := []map[string]any{}
	changes = append(changes, recordArray(payload.Payload["changeDetails"])...)
	changes = append(changes, recordArray(debugData["changeDetails"])...)
	return changes
}

func oktaPasswordPolicyWeakened(payload JobPayload) bool {
	debugData := oktaDebugData(payload)
	if nestedBoolValue(debugData, "policyWeakened") {
		return true
	}
	for _, change := range oktaChangeDetails(payload) {
		field := strings.ToLower(firstNonEmpty(
			stringValue(change["field"]),
			stringValue(change["name"]),
			stringValue(change["setting"]),
		))
		oldValue, _ := valueByKeys(change, "oldValue", "old", "from")
		newValue, _ := valueByKeys(change, "newValue", "new", "to")
		oldNumber, hasOldNumber := numericValue(oldValue)
		newNumber, hasNewNumber := numericValue(newValue)
		if hasOldNumber && hasNewNumber {
			if strings.Contains(field, "length") && newNumber < oldNumber {
				return true
			}
			if strings.Contains(field, "history") && newNumber < oldNumber {
				return true
			}
			if strings.Contains(field, "min") && newNumber < oldNumber {
				return true
			}
			if (strings.Contains(field, "max") || strings.Contains(field, "rotation") || strings.Contains(field, "expire")) && newNumber > oldNumber {
				return true
			}
			if (strings.Contains(field, "attempt") || strings.Contains(field, "lockout")) && newNumber > oldNumber {
				return true
			}
		}
		oldBool, hasOldBool := booleanValue(oldValue)
		newBool, hasNewBool := booleanValue(newValue)
		if hasOldBool && hasNewBool && oldBool && !newBool &&
			(strings.Contains(field, "complex") ||
				strings.Contains(field, "uppercase") ||
				strings.Contains(field, "lowercase") ||
				strings.Contains(field, "symbol") ||
				strings.Contains(field, "number") ||
				strings.Contains(field, "dictionary") ||
				strings.Contains(field, "history")) {
			return true
		}
	}
	return false
}

func oktaWeakenedSettingNames(payload JobPayload) []string {
	settings := []string{}
	for _, change := range oktaChangeDetails(payload) {
		settings = append(settings, firstNonEmpty(
			stringValue(change["field"]),
			stringValue(change["name"]),
			stringValue(change["setting"]),
			"unknown",
		))
	}
	return settings
}

func oktaRiskHasThreatIndicator(risk string) bool {
	normalized := strings.ToLower(risk)
	for _, indicator := range []string{"threat", "risk", "proxy", "impossible", "suspicious"} {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}
	return false
}

func compactEvidence(value map[string]any) map[string]any {
	compacted := map[string]any{}
	for key, entry := range value {
		if entry == nil {
			continue
		}
		switch typed := entry.(type) {
		case []string:
			if len(typed) == 0 {
				continue
			}
		case []any:
			if len(typed) == 0 {
				continue
			}
		}
		compacted[key] = entry
	}
	return compacted
}

func nullableString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func boundedLimit(limit int) int {
	if limit < 1 {
		return 25
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func emitIngestionJobWideEvent(item job, processErr error, duration time.Duration) {
	telemetry.EmitWide(ingestionJobWideEvent(item, processErr, duration))
	telemetry.IncCounter("aperio_ingestion_jobs_total", map[string]string{
		"provider": item.Provider,
		"outcome":  ingestionJobOutcome(item, processErr),
	})
}

func ingestionJobWideEvent(item job, processErr error, duration time.Duration) telemetry.WideEvent {
	dimensions := map[string]string{
		"outcome":    ingestionJobOutcome(item, processErr),
		"provider":   item.Provider,
		"event_type": item.EventType,
	}
	if kind := ingestionErrorKind(processErr); kind != "" {
		dimensions["error_kind"] = kind
	}
	return telemetry.WideEvent{
		Name:         "ingestion.job.process",
		Service:      "ingestion-worker",
		Organization: item.OrganizationID,
		Dimensions:   dimensions,
		Measurements: map[string]int64{
			"attempt":      int64(item.Attempts + 1),
			"max_attempts": int64(item.MaxAttempts),
			"duration_ms":  duration.Milliseconds(),
		},
	}
}

func ingestionJobOutcome(item job, processErr error) string {
	if processErr == nil {
		return "succeeded"
	}
	if errors.Is(processErr, errIngestionLeaseLost) {
		return "lost_lease"
	}
	if errors.Is(processErr, errUnsupportedIngestionWork) {
		return "dead_letter"
	}
	if item.Attempts+1 >= item.MaxAttempts {
		return "dead_letter"
	}
	return "failed"
}

func ingestionErrorKind(processErr error) string {
	if processErr == nil {
		return ""
	}
	if errors.Is(processErr, errIngestionLeaseLost) {
		return "lease_lost"
	}
	if errors.Is(processErr, errUnsupportedIngestionWork) {
		return "unsupported"
	}
	return "error"
}

func nextRetryDelay(attempt int) time.Duration {
	delay := 30 * time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return delay
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func safeIngestionFailureMessage(message string) string {
	return truncate(runtimeutil.RedactText(
		message,
		os.Getenv("APERIO_ENCRYPTION_KEY"),
		os.Getenv("DATABASE_URL"),
		os.Getenv("APERIO_TEST_DATABASE_URL"),
	), 500)
}

func randomID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
