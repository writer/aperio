package bootstrap

import "strings"

// This file ports the canonical connector and SIEM catalogs from
// packages/shared/src/connectors.ts and packages/shared/src/siem.ts into Go.
// The web renders these definitions directly (connect dialogs, catalog cards,
// SIEM destination forms), so the Go API must serve the full field, scope, and
// check metadata rather than generic placeholders.

type connectorField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Helper      string `json:"helper,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
}

type remediationAction struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	SeverityHint string `json:"severityHint"`
}

type findingCheck struct {
	Key            string `json:"key"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	SeverityHint   string `json:"severityHint"`
	DefaultEnabled bool   `json:"defaultEnabled"`
}

type findingCheckStatus struct {
	findingCheck
	Enabled bool `json:"enabled"`
}

type connectorDefinition struct {
	Provider           string              `json:"provider"`
	Name               string              `json:"name"`
	Category           string              `json:"category"`
	Availability       string              `json:"availability"`
	ReadinessNote      string              `json:"readinessNote,omitempty"`
	Description        string              `json:"description"`
	ReadScopes         []string            `json:"readScopes"`
	RemediationScopes  []string            `json:"remediationScopes"`
	RemediationActions []remediationAction `json:"remediationActions"`
	FindingChecks      []findingCheck      `json:"findingChecks"`
	DocsURL            string              `json:"docsUrl"`
	Fields             []connectorField    `json:"fields"`
}

type siemField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Helper      string `json:"helper,omitempty"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
}

type siemDestinationDefinition struct {
	Kind           string      `json:"kind"`
	Name           string      `json:"name"`
	Vendor         string      `json:"vendor"`
	Description    string      `json:"description"`
	Category       string      `json:"category"`
	DocsURL        string      `json:"docsUrl"`
	DefaultStreams []string    `json:"defaultStreams"`
	Fields         []siemField `json:"fields"`
}

func compatConnectorCatalog() []connectorDefinition {
	return catalogWithExecutableRemediationActions(rawConnectorCatalog())
}

func rawConnectorCatalog() []connectorDefinition {
	return []connectorDefinition{
		{
			Provider:     "GITHUB",
			Name:         "GitHub",
			Category:     "Source Control",
			Availability: "production_ready",
			Description:  "Monitor repository visibility, branch protection drift, and risky app activity using a GitHub App installed on your organization.",
			ReadScopes: []string{
				"Organization administration: read",
				"Members: read",
				"Metadata: read",
				"Audit log events: read",
			},
			RemediationScopes: []string{
				"Administration: write",
				"Contents: write",
				"Webhooks: write",
			},
			RemediationActions: []remediationAction{
				{Key: "github.revoke_oauth_app", Label: "Revoke OAuth App install", Description: "Removes a third-party OAuth app from the org.", SeverityHint: "HIGH"},
				{Key: "github.enforce_branch_protection", Label: "Enforce branch protection on default branch", Description: "Applies required reviews, signed commits, and linear history to the default branch.", SeverityHint: "MEDIUM"},
			},
			FindingChecks: []findingCheck{
				{Key: "github.public_repository_created", Title: "Public repository created", Description: "Flag when a repository is created public or flipped from private to public.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "github.branch_protection_disabled", Title: "Branch protection disabled", Description: "Flag when required reviews or status checks are removed from a protected branch.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "github.oauth_app_installed", Title: "Risky OAuth app installed", Description: "Flag installs of OAuth apps requesting admin scopes.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "github.deploy_key_added", Title: "Deploy key added", Description: "Flag new deploy keys, especially write-enabled.", SeverityHint: "MEDIUM", DefaultEnabled: false},
			},
			DocsURL: "https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Installation ID", Placeholder: "12345678", Helper: "Install the GitHub App on the target organization, then paste the numeric installation ID.", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "GitHub App Private Key (PEM)", Placeholder: "-----BEGIN RSA PRIVATE KEY-----", Helper: "Paste the PEM private key from your GitHub App. Aperio encrypts it at rest and uses it to mint short-lived installation tokens.", Type: "password", Required: true, Secret: true},
				{Key: "refreshToken", Label: "GitHub App ID", Placeholder: "1234567", Helper: "Use the numeric App ID from the GitHub App settings page.", Type: "text", Required: true, Secret: false},
				{Key: "webhookSecret", Label: "Webhook Signing Secret", Helper: "Recommended if you enable GitHub App webhooks for near real-time event delivery.", Type: "password", Required: false, Secret: true},
			},
		},
		{
			Provider:          "SLACK",
			Name:              "Slack",
			Category:          "Messaging",
			Availability:      "production_ready",
			Description:       "Stream Slack Enterprise Grid audit logs to detect MFA disablement, risky app installs, and external channel exposure.",
			ReadScopes:        []string{"auditlogs:read", "team:read", "users:read"},
			RemediationScopes: []string{"admin.users:write", "admin.apps:write", "admin.conversations:write"},
			RemediationActions: []remediationAction{
				{Key: "slack.deactivate_user", Label: "Deactivate Slack user", Description: "Disables the user account across the Enterprise Grid.", SeverityHint: "CRITICAL"},
				{Key: "slack.revoke_app_install", Label: "Uninstall risky Slack app", Description: "Removes the installed third-party app from the workspace.", SeverityHint: "HIGH"},
			},
			FindingChecks: []findingCheck{
				{Key: "slack.mfa_disabled", Title: "MFA disabled for user", Description: "Flag when a member disables MFA on their Slack account.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "slack.external_shared_channel_created", Title: "External shared channel created", Description: "Flag the creation of channels shared with outside organizations.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "slack.workspace_invite_link_enabled", Title: "Workspace invite link enabled", Description: "Flag toggling the public invite link on for a workspace.", SeverityHint: "MEDIUM", DefaultEnabled: true},
				{Key: "slack.app_installed", Title: "Third-party Slack app installed", Description: "Flag installs of any third-party Slack app.", SeverityHint: "MEDIUM", DefaultEnabled: false},
			},
			DocsURL: "https://api.slack.com/admins/audit-logs",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Workspace ID", Placeholder: "T01ABCDE2FG", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Audit Logs API Token", Placeholder: "xoxp-...", Type: "password", Required: true, Secret: true},
				{Key: "webhookSecret", Label: "Slack Signing Secret", Type: "password", Required: false, Secret: true},
			},
		},
		{
			Provider:     "GOOGLE_WORKSPACE",
			Name:         "Google Workspace",
			Category:     "Productivity",
			Availability: "production_ready",
			Description:  "Connect through a Aperio-managed Google OAuth app to ingest Admin SDK audit events for Drive sharing changes, admin role grants, mailbox delegation, Gmail forwarding changes, legacy mail auth usage, and OAuth third-party app risks. Current-state scans also flag privileged accounts without enforced MFA or with external recovery email, and populate privileged Google identities for the Security tab, while optional domain-wide Gmail settings scanning inventories forwarding and delegate/send-as combinations.",
			ReadScopes: []string{
				"https://www.googleapis.com/auth/admin.reports.audit.readonly",
				"https://www.googleapis.com/auth/admin.directory.user.readonly",
				"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
				"https://www.googleapis.com/auth/admin.directory.user.security",
			},
			RemediationScopes: []string{"https://www.googleapis.com/auth/admin.directory.user"},
			RemediationActions: []remediationAction{
				{Key: "google.suspend_user", Label: "Suspend Workspace user", Description: "Suspends sign-in for the affected user account.", SeverityHint: "CRITICAL"},
				{Key: "google.revoke_oauth_grants", Label: "Revoke OAuth grants for user", Description: "Removes all third-party OAuth tokens for the user.", SeverityHint: "HIGH"},
			},
			FindingChecks: []findingCheck{
				{Key: "google_workspace.external_sharing_enabled", Title: "External Drive sharing enabled", Description: "Flag Drive sharing changes that allow access outside trusted domains.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.super_admin_granted", Title: "Super admin role granted", Description: "Flag any new super admin assignment.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "google_workspace.admin_role_granted", Title: "Admin role granted", Description: "Flag new privileged admin role assignments beyond super admin.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.admin_mfa_not_enforced", Title: "Admin MFA not enforced", Description: "Flag privileged Google Workspace accounts that are not enrolled in or enforced for 2-step verification.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "google_workspace.admin_external_recovery_email", Title: "Admin external recovery email", Description: "Flag privileged accounts whose recovery email points outside the tenant domain.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.risky_oauth_grant", Title: "High-risk OAuth grant", Description: "Flag third-party OAuth grants for risky scopes (Gmail, Drive, Admin).", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.email_forwarding_enabled", Title: "Email forwarding enabled", Description: "Flag Gmail forwarding rules that route mailbox traffic to another address.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.mailbox_delegation_granted", Title: "Mailbox delegation granted", Description: "Flag Gmail delegate access that lets another user read and send mail on behalf of a mailbox.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.legacy_mail_auth_used", Title: "App password or legacy auth used", Description: "Flag app-password creation or IMAP/POP/SMTP style legacy mailbox access.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "google_workspace.forwarding_delegate_send_as_combo", Title: "Forwarding plus delegate/send-as combo", Description: "Flag mailboxes that combine forwarding with delegate access or custom send-as aliases.", SeverityHint: "CRITICAL", DefaultEnabled: true},
			},
			DocsURL: "https://developers.google.com/admin-sdk/directory/v1/guides/delegation",
			Fields:  []connectorField{},
		},
		{
			Provider:           "ONE_PASSWORD",
			Name:               "1Password",
			Category:           "Identity",
			Availability:       "preview",
			ReadinessNote:      "Catalog and SaaS detection surfacing are available, but production ingestion coverage is still being expanded.",
			Description:        "Monitor 1Password Events API activity for vault access changes, admin grants, and risky account configuration drift.",
			ReadScopes:         []string{"events:read", "vaults:read", "groups:read"},
			RemediationScopes:  []string{},
			RemediationActions: []remediationAction{},
			FindingChecks: []findingCheck{
				{Key: "one_password.vault_exported", Title: "Vault data exported", Description: "Flag exports of vault items or bulk data from the 1Password account.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "one_password.admin_granted", Title: "Administrator granted", Description: "Flag when a user is granted administrative permissions in 1Password.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "one_password.travel_mode_enabled", Title: "Travel Mode enabled", Description: "Flag Travel Mode changes that can hide vaults from devices before border crossings.", SeverityHint: "MEDIUM", DefaultEnabled: false},
			},
			DocsURL: "https://developer.1password.com/docs/events-api/",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "1Password Account Domain", Placeholder: "acme.1password.com", Helper: "Your 1Password account domain without the https:// prefix.", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Events API bearer token", Placeholder: "ops_...", Helper: "Use a 1Password Events API token. The value is encrypted with AES-256-GCM before storage.", Type: "password", Required: true, Secret: true},
			},
		},
		{
			Provider:          "OKTA",
			Name:              "Okta",
			Category:          "Identity",
			Availability:      "preview",
			ReadinessNote:     "Connector shape exists, but production-grade ingestion and remediation depth are not complete yet.",
			Description:       "Detect risky admin role grants, MFA factor changes, password policy weakening, and suspicious SSO behavior. Authenticates via OAuth for Okta (API Services app with private-key JWT) instead of long-lived SSWS tokens.",
			ReadScopes:        []string{"okta.users.read", "okta.logs.read", "okta.groups.read"},
			RemediationScopes: []string{"okta.users.manage", "okta.apps.manage", "okta.policies.manage"},
			RemediationActions: []remediationAction{
				{Key: "okta.suspend_user", Label: "Suspend Okta user", Description: "Marks the user as SUSPENDED, blocking all sign-in.", SeverityHint: "CRITICAL"},
				{Key: "okta.reset_mfa_factors", Label: "Reset MFA factors", Description: "Resets all enrolled factors so the user must re-enroll on next sign-in.", SeverityHint: "HIGH"},
			},
			FindingChecks: []findingCheck{
				{Key: "okta.admin_role_assigned", Title: "Admin role assigned", Description: "Flag any new SUPER_ADMIN, ORG_ADMIN, or APP_ADMIN role assignment.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "okta.mfa_factor_reset", Title: "MFA factor reset by admin", Description: "Flag when an admin resets factors for another user.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "okta.password_policy_weakened", Title: "Password policy weakened", Description: "Flag reductions in password length, complexity, or rotation cadence.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "okta.suspicious_signin", Title: "Suspicious sign-in detected", Description: "Flag risky sign-ins flagged by Okta ThreatInsight.", SeverityHint: "MEDIUM", DefaultEnabled: false},
			},
			DocsURL: "https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Okta Domain", Placeholder: "acme.okta.com", Helper: "Your Okta org URL without the https:// prefix.", Type: "url", Required: true, Secret: false},
				{Key: "refreshToken", Label: "OAuth Client ID", Placeholder: "<your Okta OIDC client ID>", Helper: "Client ID of the OIDC API Services app you created in Okta. Aperio requests scoped access tokens from your org authorization server using this client.", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Private Key (PEM)", Placeholder: "-----BEGIN PRIVATE KEY-----", Helper: "Paste the PEM private key whose public key is registered on your Okta API Services app. Aperio signs a short-lived JWT client assertion with this key to mint OAuth access tokens. Stored encrypted with AES-256-GCM.", Type: "password", Required: true, Secret: true},
			},
		},
		{
			Provider:          "MICROSOFT_365",
			Name:              "Microsoft 365",
			Category:          "Productivity",
			Availability:      "preview",
			ReadinessNote:     "Connector catalog exists, but real-data support is still in preview pending deeper detection coverage.",
			Description:       "Pull Microsoft 365 / Entra ID audit logs to surface conditional access drift, guest user sprawl, and risky OAuth grants.",
			ReadScopes:        []string{"AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All"},
			RemediationScopes: []string{"User.ReadWrite.All", "Directory.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess"},
			RemediationActions: []remediationAction{
				{Key: "ms365.revoke_sessions", Label: "Revoke all sessions for user", Description: "Revokes refresh tokens so the user must reauthenticate everywhere.", SeverityHint: "HIGH"},
				{Key: "ms365.disable_user", Label: "Disable Entra ID user", Description: "Sets accountEnabled=false on the directory user.", SeverityHint: "CRITICAL"},
			},
			FindingChecks: []findingCheck{
				{Key: "ms365.guest_user_invited", Title: "Guest (B2B) user invited", Description: "Flag invitations of external guest accounts.", SeverityHint: "MEDIUM", DefaultEnabled: true},
				{Key: "ms365.conditional_access_disabled", Title: "Conditional access policy disabled", Description: "Flag toggling off any conditional access policy on the tenant.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "ms365.global_admin_granted", Title: "Global Administrator role granted", Description: "Flag assignment of the Global Administrator role.", SeverityHint: "CRITICAL", DefaultEnabled: true},
			},
			DocsURL: "https://learn.microsoft.com/en-us/graph/api/resources/auditlogroot",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Tenant ID", Placeholder: "00000000-0000-0000-0000-000000000000", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Client Secret", Type: "password", Required: true, Secret: true},
				{Key: "refreshToken", Label: "Application (Client) ID", Type: "text", Required: true, Secret: false},
			},
		},
		{
			Provider:          "ATLASSIAN",
			Name:              "Atlassian (Jira & Confluence)",
			Category:          "Productivity",
			Availability:      "preview",
			ReadinessNote:     "Preview-only until production event ingestion and remediation coverage are completed.",
			Description:       "Monitor Jira and Confluence permission changes, anonymous access, and risky public space configurations.",
			ReadScopes:        []string{"read:audit-log:admin", "read:user:admin"},
			RemediationScopes: []string{"write:user:admin", "manage:jira-configuration"},
			RemediationActions: []remediationAction{
				{Key: "atlassian.revoke_user_access", Label: "Revoke organization access", Description: "Removes the user from the Atlassian organization across all sites.", SeverityHint: "HIGH"},
			},
			FindingChecks: []findingCheck{
				{Key: "atlassian.anonymous_access_enabled", Title: "Anonymous access enabled", Description: "Flag Jira or Confluence projects/spaces opened to anonymous users.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "atlassian.public_space_created", Title: "Public Confluence space created", Description: "Flag creation of globally readable Confluence spaces.", SeverityHint: "MEDIUM", DefaultEnabled: true},
				{Key: "atlassian.org_admin_granted", Title: "Atlassian administrator granted", Description: "Flag organization, site, or product administrator grants.", SeverityHint: "HIGH", DefaultEnabled: true},
			},
			DocsURL: "https://developer.atlassian.com/cloud/admin/organization/rest/api-group-audit-log/",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Organization ID", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Admin API Key", Type: "password", Required: true, Secret: true},
			},
		},
		{
			Provider:           "SALESFORCE",
			Name:               "Salesforce",
			Category:           "Productivity",
			Availability:       "production_ready",
			Description:        "Connect Salesforce through OAuth connected apps so Aperio can ingest org telemetry and evaluate custom rules on high-risk admin and data-sharing activity.",
			ReadScopes:         []string{"api", "refresh_token"},
			RemediationScopes:  []string{},
			RemediationActions: []remediationAction{},
			FindingChecks: []findingCheck{
				{Key: "salesforce.admin_profile_assigned", Title: "Admin profile assigned", Description: "Flag administrator profile or broad permission set assignments.", SeverityHint: "CRITICAL", DefaultEnabled: true},
				{Key: "salesforce.connected_app_policy_weakened", Title: "Connected app policy weakened", Description: "Flag connected-app OAuth policy changes that broaden access or weaken session controls.", SeverityHint: "HIGH", DefaultEnabled: true},
				{Key: "salesforce.report_exported", Title: "Report or data export downloaded", Description: "Flag report exports, bulk data exports, or tenant data export downloads.", SeverityHint: "HIGH", DefaultEnabled: true},
			},
			DocsURL: "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_rest.htm",
			Fields: []connectorField{
				{Key: "externalAccountId", Label: "Salesforce instance domain", Placeholder: "acme.my.salesforce.com", Helper: "Use your My Domain host without https://.", Type: "url", Required: true, Secret: false},
				{Key: "refreshToken", Label: "Connected App client ID", Placeholder: "3MVG9....", Helper: "Consumer Key from the Salesforce Connected App (OAuth) configuration.", Type: "text", Required: true, Secret: false},
				{Key: "accessToken", Label: "Connected App client secret", Placeholder: "1955279925675241571", Helper: "Consumer Secret from the Salesforce Connected App documentation flow.", Type: "password", Required: true, Secret: true},
			},
		},
	}
}

func compatSiemCatalog() []siemDestinationDefinition {
	splunkFields := []siemField{
		{Key: "endpointUrl", Label: "HEC Endpoint", Placeholder: "https://splunk.example.com:8088/services/collector", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "HEC Token", Placeholder: "00000000-0000-0000-0000-000000000000", Helper: "Token is encrypted with AES-256-GCM before storage and decrypted only inside the dispatcher.", Type: "password", Required: true, Secret: true},
		{Key: "index", Label: "Index (optional)", Placeholder: "aperio", Type: "text", Required: false, Secret: false},
	}
	pantherFields := []siemField{
		{Key: "endpointUrl", Label: "Panther HTTP Log Source URL", Placeholder: "https://logs.runpanther.io/http/source/...", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "Shared secret / Bearer token", Type: "password", Required: true, Secret: true},
	}
	panopticonFields := []siemField{
		{Key: "endpointUrl", Label: "Panopticon ingest URL", Placeholder: "https://panopticon.example.com/api/aperio/findings", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "Bearer token / shared secret", Helper: "Panopticon is treated as a schema-flexible JSON destination until its private ingestion contract is available.", Type: "password", Required: false, Secret: true},
	}
	elasticFields := []siemField{
		{Key: "endpointUrl", Label: "Elasticsearch _bulk URL", Placeholder: "https://es.example.com:9200/_bulk", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "API key (base64)", Type: "password", Required: true, Secret: true},
		{Key: "index", Label: "Index", Placeholder: "aperio-findings", Type: "text", Required: true, Secret: false},
	}
	datadogFields := []siemField{
		{Key: "endpointUrl", Label: "Datadog Logs intake URL", Placeholder: "https://http-intake.logs.datadoghq.com/api/v2/logs", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "DD-API-KEY", Type: "password", Required: true, Secret: true},
	}
	webhookFields := []siemField{
		{Key: "endpointUrl", Label: "Webhook URL", Placeholder: "https://siem.example.com/aperio", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "HMAC signing secret (optional)", Helper: "If provided, each payload is signed with HMAC-SHA256.", Type: "password", Required: false, Secret: true},
	}
	cerebroFields := []siemField{
		{Key: "endpointUrl", Label: "Cerebro API base URL", Placeholder: "https://cerebro.example.com", Helper: "Base URL for the Writer/Cerebro API. Aperio writes claims to /source-runtimes/{runtime}/claims.", Type: "url", Required: true, Secret: false},
		{Key: "token", Label: "Cerebro API token", Helper: "Bearer token with permission to write claims for the target source runtime.", Type: "password", Required: true, Secret: true},
		{Key: "index", Label: "Source runtime ID", Placeholder: "writer-aperio-sspm", Helper: "Existing Cerebro source runtime ID, typically backed by the sdk source.", Type: "text", Required: true, Secret: false},
	}
	fileFields := []siemField{
		{Key: "filePath", Label: "Export file path", Placeholder: "tenant-a/findings.jsonl", Helper: "Findings are appended one JSON object per line inside the server's dedicated SIEM export directory.", Type: "text", Required: true, Secret: false},
	}

	return []siemDestinationDefinition{
		{Kind: "SPLUNK_HEC", Name: "Splunk HEC", Vendor: "Splunk", Category: "Cloud SIEM", Description: "Ship findings to Splunk via the HTTP Event Collector. Supports custom index and source type.", DocsURL: "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector", DefaultStreams: []string{"FINDINGS"}, Fields: splunkFields},
		{Kind: "PANTHER", Name: "Panther", Vendor: "Panther Labs", Category: "Cloud SIEM", Description: "Stream findings into a Panther HTTP Log Source for detection-as-code workflows.", DocsURL: "https://docs.panther.com/data-onboarding/data-transports/http", DefaultStreams: []string{"FINDINGS", "EVENTS"}, Fields: pantherFields},
		{Kind: "PANOPTICON", Name: "Panopticon", Vendor: "Panopticon", Category: "Cloud SIEM", Description: "Stream canonical Aperio findings into a Panopticon-compatible JSON ingest endpoint.", DocsURL: "https://github.com/search?q=panopticon+siem&type=repositories", DefaultStreams: []string{"FINDINGS", "EVENTS"}, Fields: panopticonFields},
		{Kind: "ELASTIC", Name: "Elasticsearch", Vendor: "Elastic", Category: "Hosted Search", Description: "Bulk index findings into Elasticsearch. Supply the target index and an API key.", DocsURL: "https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html", DefaultStreams: []string{"FINDINGS"}, Fields: elasticFields},
		{Kind: "DATADOG", Name: "Datadog Logs", Vendor: "Datadog", Category: "Observability", Description: "Forward findings into Datadog Logs with the standard logs intake.", DocsURL: "https://docs.datadoghq.com/api/latest/logs/", DefaultStreams: []string{"FINDINGS"}, Fields: datadogFields},
		{Kind: "GENERIC_WEBHOOK", Name: "Generic Webhook", Vendor: "Custom", Category: "Generic", Description: "POST findings as JSON to any HTTPS endpoint. Optional HMAC-SHA256 signature header.", DocsURL: "https://en.wikipedia.org/wiki/Webhook", DefaultStreams: []string{"FINDINGS"}, Fields: webhookFields},
		{Kind: "CEREBRO_CLAIMS", Name: "Writer/Cerebro Claims", Vendor: "Writer", Category: "Graph", Description: "Project Aperio findings into Writer/Cerebro as source-runtime claims for graph, workflow, and reporting use cases.", DocsURL: "https://github.com/writer/cerebro", DefaultStreams: []string{"FINDINGS"}, Fields: cerebroFields},
		{Kind: "JSON_FILE", Name: "JSON Lines File", Vendor: "Local", Category: "Generic", Description: "Append findings to a local JSONL file. Useful for development, air-gapped audits, or downstream filebeat-style shippers.", DocsURL: "https://jsonlines.org/", DefaultStreams: []string{"FINDINGS"}, Fields: fileFields},
	}
}

func findConnectorDefinition(provider string) *connectorDefinition {
	catalog := rawConnectorCatalog()
	for index := range catalog {
		if catalog[index].Provider == provider {
			return &catalog[index]
		}
	}
	return nil
}

func catalogWithExecutableRemediationActions(catalog []connectorDefinition) []connectorDefinition {
	filtered := make([]connectorDefinition, 0, len(catalog))
	for _, definition := range catalog {
		next := definition
		next.RemediationActions = make([]remediationAction, 0, len(definition.RemediationActions))
		for _, action := range definition.RemediationActions {
			if isExecutableRemediationAction(action.Key) {
				next.RemediationActions = append(next.RemediationActions, action)
			}
		}
		filtered = append(filtered, next)
	}
	return filtered
}

// compatScopesForMode returns the catalog read scopes, plus remediation scopes
// when the integration is created in REMEDIATION mode, mirroring scopesForMode
// in packages/shared/src/connectors.ts.
func compatScopesForMode(provider string, mode string) []string {
	definition := findConnectorDefinition(provider)
	if definition == nil {
		return []string{}
	}
	scopes := append([]string{}, definition.ReadScopes...)
	if strings.EqualFold(mode, "REMEDIATION") {
		scopes = append(scopes, definition.RemediationScopes...)
	}
	return scopes
}

// compatDefaultDisabledChecks returns the catalog checks that default to
// disabled, mirroring defaultDisabledChecks in packages/shared.
func compatDefaultDisabledChecks(provider string) []string {
	definition := findConnectorDefinition(provider)
	disabled := []string{}
	if definition == nil {
		return disabled
	}
	for _, check := range definition.FindingChecks {
		if !check.DefaultEnabled {
			disabled = append(disabled, check.Key)
		}
	}
	return disabled
}

func validCompatDisabledChecks(provider string, requested []string) []string {
	definition := findConnectorDefinition(provider)
	if definition == nil {
		return []string{}
	}
	valid := map[string]struct{}{}
	for _, check := range definition.FindingChecks {
		valid[check.Key] = struct{}{}
	}
	seen := map[string]struct{}{}
	disabled := []string{}
	for _, key := range requested {
		if _, ok := valid[key]; !ok {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		disabled = append(disabled, key)
	}
	return disabled
}

// compatFindingChecksForProvider returns the full ordered FindingChecks
// list registered for a provider. It exists so callers like the connector
// rules dialog can iterate the same universe of toggles the catalog
// surfaces elsewhere, avoiding the silent-drop bug where a partial list
// (e.g. only ingestionworker.RuleCatalog entries) drops checks that
// default to disabled and so are seeded into integration_connections.
// disabled_checks at connect time.
func compatFindingChecksForProvider(provider string) []findingCheck {
	definition := findConnectorDefinition(provider)
	if definition == nil {
		return nil
	}
	out := make([]findingCheck, len(definition.FindingChecks))
	copy(out, definition.FindingChecks)
	return out
}

func compatCriticalBaselineCheckSet(provider string) map[string]struct{} {
	checks := compatFindingChecksForProvider(provider)
	baseline := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		if !check.DefaultEnabled {
			continue
		}
		if !strings.EqualFold(check.SeverityHint, "CRITICAL") {
			continue
		}
		baseline[check.Key] = struct{}{}
	}
	return baseline
}

// compatFindingCheckStatuses overlays the integration's disabled set onto the
// catalog check definitions to produce the IntegrationCheckState.checks shape.
func compatFindingCheckStatuses(provider string, disabledChecks []string) []findingCheckStatus {
	disabledSet := make(map[string]struct{}, len(disabledChecks))
	for _, key := range disabledChecks {
		disabledSet[key] = struct{}{}
	}
	definition := findConnectorDefinition(provider)
	statuses := []findingCheckStatus{}
	if definition == nil {
		return statuses
	}
	for _, check := range definition.FindingChecks {
		_, disabled := disabledSet[check.Key]
		statuses = append(statuses, findingCheckStatus{findingCheck: check, Enabled: !disabled})
	}
	return statuses
}
