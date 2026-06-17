import { z } from "zod";
import { providerSchema, type Provider } from "./types";

export type ConnectorField = {
  key: string;
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type RemediationActionKey =
  | "github.revoke_oauth_app"
  | "github.enforce_branch_protection"
  | "slack.deactivate_user"
  | "slack.revoke_app_install"
  | "google.suspend_user"
  | "google.revoke_oauth_grants"
  | "okta.suspend_user"
  | "okta.reset_mfa_factors"
  | "ms365.revoke_sessions"
  | "ms365.disable_user"
  | "atlassian.revoke_user_access";

export type RemediationAction = {
  key: RemediationActionKey;
  label: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM";
};

export type IntegrationModeKey = "READ_ONLY" | "REMEDIATION";

export type FindingCheck = {
  key: string;
  title: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  defaultEnabled: boolean;
};

export type ConnectorDefinition = {
  provider: Provider;
  name: string;
  category: "Identity" | "Productivity" | "Source Control" | "Messaging";
  availability: "production_ready" | "preview";
  readinessNote?: string;
  description: string;
  readScopes: string[];
  remediationScopes: string[];
  remediationActions: RemediationAction[];
  findingChecks: FindingCheck[];
  docsUrl: string;
  fields: ConnectorField[];
};

const rawConnectorCatalog: ConnectorDefinition[] = [
  {
    provider: "GITHUB",
    name: "GitHub",
    category: "Source Control",
    availability: "production_ready",
    description:
      "Monitor repository visibility, branch protection drift, and risky app activity using a GitHub App installed on your organization.",
    readScopes: [
      "Organization administration: read",
      "Members: read",
      "Metadata: read",
      "Audit log events: read"
    ],
    remediationScopes: [
      "Administration: write",
      "Contents: write",
      "Webhooks: write"
    ],
    remediationActions: [
      {
        key: "github.revoke_oauth_app",
        label: "Revoke OAuth App install",
        description: "Removes a third-party OAuth app from the org.",
        severityHint: "HIGH"
      },
      {
        key: "github.enforce_branch_protection",
        label: "Enforce branch protection on default branch",
        description:
          "Applies required reviews, signed commits, and linear history to the default branch.",
        severityHint: "MEDIUM"
      }
    ],
    findingChecks: [
      {
        key: "github.public_repository_created",
        title: "Public repository created",
        description:
          "Flag when a repository is created public or flipped from private to public.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "github.branch_protection_disabled",
        title: "Branch protection disabled",
        description:
          "Flag when required reviews or status checks are removed from a protected branch.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "github.oauth_app_installed",
        title: "Risky OAuth app installed",
        description: "Flag installs of OAuth apps requesting admin scopes.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "github.deploy_key_added",
        title: "Deploy key added",
        description: "Flag new deploy keys, especially write-enabled.",
        severityHint: "MEDIUM",
        defaultEnabled: false
      }
    ],
    docsUrl:
      "https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps",
    fields: [
      {
        key: "externalAccountId",
        label: "Installation ID",
        placeholder: "12345678",
        helper:
          "Install the GitHub App on the target organization, then paste the numeric installation ID.",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "GitHub App Private Key (PEM)",
        placeholder: "-----BEGIN RSA PRIVATE KEY-----",
        helper:
          "Paste the PEM private key from your GitHub App. Aperio encrypts it at rest and uses it to mint short-lived installation tokens.",
        type: "password",
        required: true,
        secret: true
      },
      {
        key: "refreshToken",
        label: "GitHub App ID",
        placeholder: "1234567",
        helper:
          "Use the numeric App ID from the GitHub App settings page.",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "webhookSecret",
        label: "Webhook Signing Secret",
        helper:
          "Recommended if you enable GitHub App webhooks for near real-time event delivery.",
        type: "password",
        required: false,
        secret: true
      }
    ]
  },
  {
    provider: "SLACK",
    name: "Slack",
    category: "Messaging",
    availability: "production_ready",
    description:
      "Stream Slack Enterprise Grid audit logs to detect MFA disablement, risky app installs, and external channel exposure.",
    readScopes: ["auditlogs:read", "team:read", "users:read"],
    remediationScopes: [
      "admin.users:write",
      "admin.apps:write",
      "admin.conversations:write"
    ],
    remediationActions: [
      {
        key: "slack.deactivate_user",
        label: "Deactivate Slack user",
        description: "Disables the user account across the Enterprise Grid.",
        severityHint: "CRITICAL"
      },
      {
        key: "slack.revoke_app_install",
        label: "Uninstall risky Slack app",
        description: "Removes the installed third-party app from the workspace.",
        severityHint: "HIGH"
      }
    ],
    findingChecks: [
      {
        key: "slack.mfa_disabled",
        title: "MFA disabled for user",
        description: "Flag when a member disables MFA on their Slack account.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "slack.external_shared_channel_created",
        title: "External shared channel created",
        description:
          "Flag the creation of channels shared with outside organizations.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "slack.workspace_invite_link_enabled",
        title: "Workspace invite link enabled",
        description:
          "Flag toggling the public invite link on for a workspace.",
        severityHint: "MEDIUM",
        defaultEnabled: true
      },
      {
        key: "slack.app_installed",
        title: "Third-party Slack app installed",
        description: "Flag installs of any third-party Slack app.",
        severityHint: "MEDIUM",
        defaultEnabled: false
      }
    ],
    docsUrl: "https://api.slack.com/admins/audit-logs",
    fields: [
      {
        key: "externalAccountId",
        label: "Workspace ID",
        placeholder: "T01ABCDE2FG",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Audit Logs API Token",
        placeholder: "xoxp-...",
        type: "password",
        required: true,
        secret: true
      },
      {
        key: "webhookSecret",
        label: "Slack Signing Secret",
        type: "password",
        required: false,
        secret: true
      }
    ]
  },
  {
    provider: "GOOGLE_WORKSPACE",
    name: "Google Workspace",
    category: "Productivity",
    availability: "production_ready",
    description:
      "Connect through a Aperio-managed Google OAuth app to ingest Admin SDK audit events for Drive sharing changes, admin role grants, mailbox delegation, Gmail forwarding changes, legacy mail auth usage, and OAuth third-party app risks. Current-state scans also flag privileged accounts without enforced MFA or with external recovery email, and populate privileged Google identities for the Security tab, while optional domain-wide Gmail settings scanning inventories forwarding and delegate/send-as combinations.",
    readScopes: [
      "https://www.googleapis.com/auth/admin.reports.audit.readonly",
      "https://www.googleapis.com/auth/admin.directory.user.readonly",
      "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
      "https://www.googleapis.com/auth/admin.directory.user.security"
    ],
    remediationScopes: [
      "https://www.googleapis.com/auth/admin.directory.user"
    ],
    remediationActions: [
      {
        key: "google.suspend_user",
        label: "Suspend Workspace user",
        description: "Suspends sign-in for the affected user account.",
        severityHint: "CRITICAL"
      },
      {
        key: "google.revoke_oauth_grants",
        label: "Revoke OAuth grants for user",
        description: "Removes all third-party OAuth tokens for the user.",
        severityHint: "HIGH"
      }
    ],
    findingChecks: [
      {
        key: "google_workspace.external_sharing_enabled",
        title: "External Drive sharing enabled",
        description:
          "Flag Drive sharing changes that allow access outside trusted domains.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.super_admin_granted",
        title: "Super admin role granted",
        description: "Flag any new super admin assignment.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "google_workspace.admin_role_granted",
        title: "Admin role granted",
        description:
          "Flag new privileged admin role assignments beyond super admin.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.admin_mfa_not_enforced",
        title: "Admin MFA not enforced",
        description:
          "Flag privileged Google Workspace accounts that are not enrolled in or enforced for 2-step verification.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "google_workspace.admin_external_recovery_email",
        title: "Admin external recovery email",
        description:
          "Flag privileged accounts whose recovery email points outside the tenant domain.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.risky_oauth_grant",
        title: "High-risk OAuth grant",
        description:
          "Flag third-party OAuth grants for risky scopes (Gmail, Drive, Admin).",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.email_forwarding_enabled",
        title: "Email forwarding enabled",
        description:
          "Flag Gmail forwarding rules that route mailbox traffic to another address.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.mailbox_delegation_granted",
        title: "Mailbox delegation granted",
        description:
          "Flag Gmail delegate access that lets another user read and send mail on behalf of a mailbox.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.legacy_mail_auth_used",
        title: "App password or legacy auth used",
        description:
          "Flag app-password creation or IMAP/POP/SMTP style legacy mailbox access.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "google_workspace.forwarding_delegate_send_as_combo",
        title: "Forwarding plus delegate/send-as combo",
        description:
          "Flag mailboxes that combine forwarding with delegate access or custom send-as aliases.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      }
    ],
    docsUrl:
      "https://developers.google.com/admin-sdk/directory/v1/guides/delegation",
    fields: []
  },
  {
    provider: "ONE_PASSWORD",
    name: "1Password",
    category: "Identity",
    availability: "preview",
    readinessNote:
      "Catalog and SaaS detection surfacing are available, but production ingestion coverage is still being expanded.",
    description:
      "Monitor 1Password Events API activity for vault access changes, admin grants, and risky account configuration drift.",
    readScopes: ["events:read", "vaults:read", "groups:read"],
    remediationScopes: [],
    remediationActions: [],
    findingChecks: [
      {
        key: "one_password.vault_exported",
        title: "Vault data exported",
        description:
          "Flag exports of vault items or bulk data from the 1Password account.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "one_password.admin_granted",
        title: "Administrator granted",
        description:
          "Flag when a user is granted administrative permissions in 1Password.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "one_password.travel_mode_enabled",
        title: "Travel Mode enabled",
        description:
          "Flag Travel Mode changes that can hide vaults from devices before border crossings.",
        severityHint: "MEDIUM",
        defaultEnabled: false
      }
    ],
    docsUrl: "https://developer.1password.com/docs/events-api/",
    fields: [
      {
        key: "externalAccountId",
        label: "1Password Account Domain",
        placeholder: "acme.1password.com",
        helper: "Your 1Password account domain without the https:// prefix.",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Events API bearer token",
        placeholder: "ops_...",
        helper:
          "Use a 1Password Events API token. The value is encrypted with AES-256-GCM before storage.",
        type: "password",
        required: true,
        secret: true
      }
    ]
  },
  {
    provider: "OKTA",
    name: "Okta",
    category: "Identity",
    availability: "preview",
    readinessNote:
      "Connector shape exists, but production-grade ingestion and remediation depth are not complete yet.",
    description:
      "Detect risky admin role grants, MFA factor changes, password policy weakening, and suspicious SSO behavior. Authenticates via OAuth for Okta (API Services app with private-key JWT) instead of long-lived SSWS tokens.",
    readScopes: ["okta.users.read", "okta.logs.read", "okta.groups.read"],
    remediationScopes: [
      "okta.users.manage",
      "okta.apps.manage",
      "okta.policies.manage"
    ],
    remediationActions: [
      {
        key: "okta.suspend_user",
        label: "Suspend Okta user",
        description: "Marks the user as SUSPENDED, blocking all sign-in.",
        severityHint: "CRITICAL"
      },
      {
        key: "okta.reset_mfa_factors",
        label: "Reset MFA factors",
        description:
          "Resets all enrolled factors so the user must re-enroll on next sign-in.",
        severityHint: "HIGH"
      }
    ],
    findingChecks: [
      {
        key: "okta.admin_role_assigned",
        title: "Admin role assigned",
        description:
          "Flag any new SUPER_ADMIN, ORG_ADMIN, or APP_ADMIN role assignment.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "okta.mfa_factor_reset",
        title: "MFA factor reset by admin",
        description: "Flag when an admin resets factors for another user.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "okta.password_policy_weakened",
        title: "Password policy weakened",
        description:
          "Flag reductions in password length, complexity, or rotation cadence.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "okta.suspicious_signin",
        title: "Suspicious sign-in detected",
        description: "Flag risky sign-ins flagged by Okta ThreatInsight.",
        severityHint: "MEDIUM",
        defaultEnabled: false
      }
    ],
    docsUrl:
      "https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/",
    fields: [
      {
        key: "externalAccountId",
        label: "Okta Domain",
        placeholder: "acme.okta.com",
        helper: "Your Okta org URL without the https:// prefix.",
        type: "url",
        required: true,
        secret: false
      },
      {
        key: "refreshToken",
        label: "OAuth Client ID",
        placeholder: "<your Okta OIDC client ID>",
        helper:
          "Client ID of the OIDC API Services app you created in Okta. Aperio requests scoped access tokens from your org authorization server using this client.",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Private Key (PEM)",
        placeholder: "-----BEGIN PRIVATE KEY-----",
        helper:
          "Paste the PEM private key whose public key is registered on your Okta API Services app. Aperio signs a short-lived JWT client assertion with this key to mint OAuth access tokens. Stored encrypted with AES-256-GCM.",
        type: "password",
        required: true,
        secret: true
      }
    ]
  },
  {
    provider: "MICROSOFT_365",
    name: "Microsoft 365",
    category: "Productivity",
    availability: "preview",
    readinessNote:
      "Connector catalog exists, but real-data support is still in preview pending deeper detection coverage.",
    description:
      "Pull Microsoft 365 / Entra ID audit logs to surface conditional access drift, guest user sprawl, and risky OAuth grants.",
    readScopes: ["AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All"],
    remediationScopes: [
      "User.ReadWrite.All",
      "Directory.ReadWrite.All",
      "Policy.ReadWrite.ConditionalAccess"
    ],
    remediationActions: [
      {
        key: "ms365.revoke_sessions",
        label: "Revoke all sessions for user",
        description:
          "Revokes refresh tokens so the user must reauthenticate everywhere.",
        severityHint: "HIGH"
      },
      {
        key: "ms365.disable_user",
        label: "Disable Entra ID user",
        description: "Sets accountEnabled=false on the directory user.",
        severityHint: "CRITICAL"
      }
    ],
    findingChecks: [
      {
        key: "ms365.guest_user_invited",
        title: "Guest (B2B) user invited",
        description: "Flag invitations of external guest accounts.",
        severityHint: "MEDIUM",
        defaultEnabled: true
      },
      {
        key: "ms365.conditional_access_disabled",
        title: "Conditional access policy disabled",
        description:
          "Flag toggling off any conditional access policy on the tenant.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      },
      {
        key: "ms365.global_admin_granted",
        title: "Global Administrator role granted",
        description: "Flag assignment of the Global Administrator role.",
        severityHint: "CRITICAL",
        defaultEnabled: true
      }
    ],
    docsUrl:
      "https://learn.microsoft.com/en-us/graph/api/resources/auditlogroot",
    fields: [
      {
        key: "externalAccountId",
        label: "Tenant ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Client Secret",
        type: "password",
        required: true,
        secret: true
      },
      {
        key: "refreshToken",
        label: "Application (Client) ID",
        type: "text",
        required: true,
        secret: false
      }
    ]
  },
  {
    provider: "ATLASSIAN",
    name: "Atlassian (Jira & Confluence)",
    category: "Productivity",
    availability: "preview",
    readinessNote:
      "Preview-only until production event ingestion and remediation coverage are completed.",
    description:
      "Monitor Jira and Confluence permission changes, anonymous access, and risky public space configurations.",
    readScopes: ["read:audit-log:admin", "read:user:admin"],
    remediationScopes: ["write:user:admin", "manage:jira-configuration"],
    remediationActions: [
      {
        key: "atlassian.revoke_user_access",
        label: "Revoke organization access",
        description:
          "Removes the user from the Atlassian organization across all sites.",
        severityHint: "HIGH"
      }
    ],
    findingChecks: [
      {
        key: "atlassian.anonymous_access_enabled",
        title: "Anonymous access enabled",
        description:
          "Flag Jira or Confluence projects/spaces opened to anonymous users.",
        severityHint: "HIGH",
        defaultEnabled: true
      },
      {
        key: "atlassian.public_space_created",
        title: "Public Confluence space created",
        description: "Flag creation of globally readable Confluence spaces.",
        severityHint: "MEDIUM",
        defaultEnabled: true
      }
    ],
    docsUrl:
      "https://developer.atlassian.com/cloud/admin/organization/rest/api-group-audit-log/",
    fields: [
      {
        key: "externalAccountId",
        label: "Organization ID",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Admin API Key",
        type: "password",
        required: true,
        secret: true
      }
    ]
  },
  {
    provider: "SALESFORCE",
    name: "Salesforce",
    category: "Productivity",
    availability: "production_ready",
    description:
      "Connect Salesforce through OAuth connected apps so Aperio can ingest org telemetry and evaluate custom rules on high-risk admin and data-sharing activity.",
    readScopes: ["api", "refresh_token"],
    remediationScopes: [],
    remediationActions: [],
    findingChecks: [],
    docsUrl:
      "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_rest.htm",
    fields: [
      {
        key: "externalAccountId",
        label: "Salesforce instance domain",
        placeholder: "acme.my.salesforce.com",
        helper: "Use your My Domain host without https://.",
        type: "url",
        required: true,
        secret: false
      },
      {
        key: "refreshToken",
        label: "Connected App client ID",
        placeholder: "3MVG9....",
        helper:
          "Consumer Key from the Salesforce Connected App (OAuth) configuration.",
        type: "text",
        required: true,
        secret: false
      },
      {
        key: "accessToken",
        label: "Connected App client secret",
        placeholder: "1955279925675241571",
        helper:
          "Consumer Secret from the Salesforce Connected App documentation flow.",
        type: "password",
        required: true,
        secret: true
      }
    ]
  }
];

const executableRemediationActionKeys = new Set<RemediationActionKey>([
  "slack.revoke_app_install"
]);

export const connectorCatalog: ConnectorDefinition[] = rawConnectorCatalog.map(
  (connector) => ({
    ...connector,
    remediationActions: connector.remediationActions.filter((action) =>
      executableRemediationActionKeys.has(action.key)
    )
  })
);

const credentialFieldsSchema = z
  .object({
    accessToken: z.string().trim().min(8).max(8192),
    refreshToken: z.string().trim().min(1).max(4096).optional(),
    webhookSecret: z.string().trim().min(1).max(4096).optional()
  })
  .strict();

export const integrationModeSchema = z.enum(["READ_ONLY", "REMEDIATION"]);

export const connectIntegrationSchema = z
  .object({
    provider: providerSchema,
    displayName: z.string().trim().min(1).max(160),
    externalAccountId: z.string().trim().min(1).max(255),
    mode: integrationModeSchema.default("READ_ONLY"),
    credentials: credentialFieldsSchema
  })
  .superRefine((value, ctx) => {
    if (value.provider !== "GITHUB") {
      return;
    }

    if (!/^\d+$/.test(value.externalAccountId)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["externalAccountId"],
        message: "GitHub App installation ID must be numeric"
      });
    }

    if (!value.credentials.refreshToken?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["credentials", "refreshToken"],
        message: "GitHub App ID is required"
      });
    } else if (!/^\d+$/.test(value.credentials.refreshToken.trim())) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["credentials", "refreshToken"],
        message: "GitHub App ID must be numeric"
      });
    }

    if (
      !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value.credentials.accessToken) ||
      !/-----END [A-Z ]*PRIVATE KEY-----/.test(value.credentials.accessToken)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["credentials", "accessToken"],
        message: "GitHub App private key must be a PEM block"
      });
    }
  });

export type ConnectIntegrationInput = z.infer<typeof connectIntegrationSchema>;

export function findConnector(provider: Provider): ConnectorDefinition | undefined {
  return connectorCatalog.find((connector) => connector.provider === provider);
}

export function isConnectorProductionReady(
  connector: ConnectorDefinition
): boolean {
  return connector.availability === "production_ready";
}

export function scopesForMode(
  connector: ConnectorDefinition,
  mode: IntegrationModeKey
): string[] {
  return mode === "REMEDIATION"
    ? [...connector.readScopes, ...connector.remediationScopes]
    : [...connector.readScopes];
}

export function defaultDisabledChecks(
  connector: ConnectorDefinition
): string[] {
  return connector.findingChecks
    .filter((check) => !check.defaultEnabled)
    .map((check) => check.key);
}

export function isCheckEnabled(
  checkKey: string,
  disabledChecks: string[]
): boolean {
  return !disabledChecks.includes(checkKey);
}
