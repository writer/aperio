import { prisma } from "../packages/db/src/client";
import { encryptString, hashPassword } from "../packages/security/src/crypto";

const organizationId =
  process.env.DEMO_ORGANIZATION_ID ?? "org_demo_000000000000000000000001";
const userId = process.env.DEMO_USER_ID ?? "usr_demo_000000000000000000000001";
const roleId = "role_demo_owner";
const adminUserId = "usr_demo_breakglass_admin";
const analystUserId = "usr_demo_security_analyst";
const githubIntegrationId = "int_demo_github";
const slackIntegrationId = "int_demo_slack";
const googleIntegrationId = "int_demo_google";
const siemDestinationId = "siem_demo_json_file";
const saasIncidentId = "inc_demo_vendor_drive_response";
const saasResponseActionId = "act_demo_revoke_vendor_drive";

const githubAppAssetId = "asset_demo_app_github";
const slackAppAssetId = "asset_demo_app_slack";
const googleAppAssetId = "asset_demo_app_google";
const paymentsRepoAssetId = "asset_demo_repo_payments";
const githubOauthAssetId = "asset_demo_oauth_ci";
const githubBotAssetId = "asset_demo_sa_github_actions";
const boardMaterialsAssetId = "asset_demo_data_board_materials";
const vendorAnalyticsAssetId = "asset_demo_oauth_vendor_analytics";
const demoPassword =
  process.env.DEMO_OWNER_PASSWORD ?? "DemoPass1234";

async function upsertSaasIdentity(
  id: string,
  data: Omit<
    Parameters<typeof prisma.saasIdentity.upsert>[0]["create"],
    "id" | "organizationId"
  >
) {
  await prisma.saasIdentity.upsert({
    where: {
      organizationId_provider_externalId: {
        organizationId,
        provider: data.provider,
        externalId: data.externalId
      }
    },
    update: data,
    create: {
      id,
      organizationId,
      ...data
    }
  });
}

async function upsertOauthAppGrant(
  id: string,
  data: Omit<
    Parameters<typeof prisma.oauthAppGrant.upsert>[0]["create"],
    "id" | "organizationId"
  >
) {
  await prisma.oauthAppGrant.upsert({
    where: {
      organizationId_integrationId_externalAppId_userEmail: {
        organizationId,
        integrationId: data.integrationId,
        externalAppId: data.externalAppId,
        userEmail: data.userEmail
      }
    },
    update: data,
    create: {
      id,
      organizationId,
      ...data
    }
  });
}

async function upsertIntegration(
  id: string,
  provider: "GITHUB" | "SLACK" | "GOOGLE_WORKSPACE",
  displayName: string,
  externalAccountId: string
) {
  await prisma.integrationConnection.upsert({
    where: {
      organizationId_provider_externalAccountId: {
        organizationId,
        provider,
        externalAccountId
      }
    },
    update: { status: "CONNECTED" },
    create: {
      id,
      organizationId,
      provider,
      displayName,
      externalAccountId,
      scopes: ["audit:read", "admin:read"],
      encryptedAccessToken: encryptString(
        `demo-provider-token-${provider}`,
        `${organizationId}:${provider}:${externalAccountId}:access_token`
      ),
      tokenKeyVersion: "v1",
      status: "CONNECTED"
    }
  });
}

async function upsertAsset(
  id: string,
  data: Omit<
    Parameters<typeof prisma.securityAsset.upsert>[0]["create"],
    "id" | "organizationId"
  >
) {
  await prisma.securityAsset.upsert({
    where: { id },
    update: data,
    create: {
      id,
      organizationId,
      ...data
    }
  });
}

async function main() {
  await prisma.organization.upsert({
    where: { id: organizationId },
    update: {},
    create: {
      id: organizationId,
      name: "Aperio Demo Security",
      slug: "aperio-demo"
    }
  });

  const ownerRole = await prisma.role.upsert({
    where: {
      organizationId_name: {
        organizationId,
        name: "OWNER"
      }
    },
    update: { permissions: ["*"] },
    create: {
      id: roleId,
      organizationId,
      name: "OWNER",
      permissions: ["*"]
    }
  });

  await prisma.user.upsert({
    where: {
      organizationId_email: {
        organizationId,
        email: "security@aperio.local"
      }
    },
    update: {
      roleId: ownerRole.id,
      isActive: true,
      passwordHash: hashPassword(demoPassword)
    },
    create: {
      id: userId,
      organizationId,
      roleId: ownerRole.id,
      email: "security@aperio.local",
      displayName: "Aperio Security Owner",
      passwordHash: hashPassword(demoPassword)
    }
  });

  const adminRole = await prisma.role.upsert({
    where: {
      organizationId_name: {
        organizationId,
        name: "ADMIN"
      }
    },
    update: { permissions: ["*"] },
    create: {
      organizationId,
      name: "ADMIN",
      permissions: ["*"]
    }
  });

  const analystRole = await prisma.role.upsert({
    where: {
      organizationId_name: {
        organizationId,
        name: "SECURITY_ANALYST"
      }
    },
    update: { permissions: ["read", "triage"] },
    create: {
      organizationId,
      name: "SECURITY_ANALYST",
      permissions: ["read", "triage"]
    }
  });

  await prisma.user.upsert({
    where: {
      organizationId_email: {
        organizationId,
        email: "breakglass@aperio.local"
      }
    },
    update: {
      roleId: adminRole.id,
      isActive: true,
      passwordHash: hashPassword(demoPassword),
      mfaEnabled: false,
      isBreakGlass: true,
      lastLoginAt: new Date("2026-04-02T08:00:00.000Z")
    },
    create: {
      id: adminUserId,
      organizationId,
      roleId: adminRole.id,
      email: "breakglass@aperio.local",
      displayName: "Break Glass Admin",
      passwordHash: hashPassword(demoPassword),
      mfaEnabled: false,
      isBreakGlass: true,
      lastLoginAt: new Date("2026-04-02T08:00:00.000Z")
    }
  });

  await prisma.user.upsert({
    where: {
      organizationId_email: {
        organizationId,
        email: "finance-security@aperio.local"
      }
    },
    update: {
      roleId: analystRole.id,
      isActive: true,
      passwordHash: hashPassword(demoPassword),
      mfaEnabled: true,
      isBreakGlass: false,
      lastLoginAt: new Date("2026-05-29T15:00:00.000Z")
    },
    create: {
      id: analystUserId,
      organizationId,
      roleId: analystRole.id,
      email: "finance-security@aperio.local",
      displayName: "Finance Security Analyst",
      passwordHash: hashPassword(demoPassword),
      mfaEnabled: true,
      isBreakGlass: false,
      lastLoginAt: new Date("2026-05-29T15:00:00.000Z")
    }
  });

  await upsertIntegration(
    githubIntegrationId,
    "GITHUB",
    "GitHub Enterprise",
    "github-demo"
  );
  await upsertIntegration(slackIntegrationId, "SLACK", "Slack Grid", "slack-demo");
  await upsertIntegration(
    googleIntegrationId,
    "GOOGLE_WORKSPACE",
    "Google Workspace",
    "google-demo"
  );

  await upsertAsset(githubAppAssetId, {
    integrationId: githubIntegrationId,
    ownerUserId: userId,
    businessOwnerUserId: adminUserId,
    type: "APPLICATION",
    provider: "GITHUB",
    name: "GitHub Enterprise",
    summary: "Primary source-control control plane for engineering.",
    externalId: "github-demo",
    labels: ["integration", "source-control"],
    criticality: "CRITICAL",
    exposureLevel: "INTERNAL",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: false,
    isPrivileged: true,
    riskScore: 58,
    lastObservedAt: new Date("2026-05-29T18:00:00.000Z")
  });

  await upsertAsset(slackAppAssetId, {
    integrationId: slackIntegrationId,
    ownerUserId: adminUserId,
    businessOwnerUserId: userId,
    type: "APPLICATION",
    provider: "SLACK",
    name: "Slack Grid",
    summary: "Enterprise messaging workspace used for company-wide collaboration.",
    externalId: "slack-demo",
    labels: ["integration", "messaging"],
    criticality: "HIGH",
    exposureLevel: "INTERNAL",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: false,
    isPrivileged: false,
    riskScore: 32,
    lastObservedAt: new Date("2026-05-29T18:10:00.000Z")
  });

  await upsertAsset(googleAppAssetId, {
    integrationId: googleIntegrationId,
    ownerUserId: analystUserId,
    businessOwnerUserId: userId,
    type: "APPLICATION",
    provider: "GOOGLE_WORKSPACE",
    name: "Google Workspace",
    summary: "Productivity suite that stores board documents and shared drives.",
    externalId: "google-demo",
    labels: ["integration", "productivity"],
    criticality: "CRITICAL",
    exposureLevel: "INTERNAL",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: true,
    isPrivileged: true,
    riskScore: 61,
    lastObservedAt: new Date("2026-05-29T18:20:00.000Z")
  });

  await upsertAsset(paymentsRepoAssetId, {
    integrationId: githubIntegrationId,
    ownerUserId: analystUserId,
    businessOwnerUserId: userId,
    type: "REPOSITORY",
    provider: "GITHUB",
    name: "payments-service",
    summary: "Production payments repository with deployment workflows and secrets scanning.",
    externalId: "acme/payments-service",
    labels: ["pci", "source-code", "production"],
    criticality: "CRITICAL",
    exposureLevel: "PUBLIC",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: true,
    isPrivileged: false,
    riskScore: 92,
    lastObservedAt: new Date("2026-05-29T17:45:00.000Z")
  });

  await upsertAsset(githubOauthAssetId, {
    integrationId: githubIntegrationId,
    ownerUserId: adminUserId,
    businessOwnerUserId: userId,
    type: "OAUTH_APP",
    provider: "GITHUB",
    name: "Acme CI Deploy",
    summary: "Third-party CI orchestrator with broad repository administration scopes.",
    externalId: "oauth-app-acme-ci",
    labels: ["repo:admin", "workflow", "third-party", "shadow-it"],
    criticality: "HIGH",
    exposureLevel: "TRUSTED_EXTERNAL",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: false,
    isPrivileged: true,
    riskScore: 88,
    lastObservedAt: new Date("2026-05-29T16:30:00.000Z")
  });

  await upsertAsset(githubBotAssetId, {
    integrationId: githubIntegrationId,
    ownerUserId: adminUserId,
    businessOwnerUserId: userId,
    type: "SERVICE_ACCOUNT",
    provider: "GITHUB",
    name: "github-actions-prod",
    summary: "Automation identity that deploys payments changes into production.",
    externalId: "svc-github-actions-prod",
    labels: ["automation", "deploy", "production"],
    criticality: "HIGH",
    exposureLevel: "INTERNAL",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: false,
    isPrivileged: true,
    riskScore: 82,
    lastObservedAt: new Date("2026-05-27T03:00:00.000Z")
  });

  await upsertAsset(boardMaterialsAssetId, {
    integrationId: googleIntegrationId,
    ownerUserId: analystUserId,
    businessOwnerUserId: userId,
    type: "DATA_RESOURCE",
    provider: "GOOGLE_WORKSPACE",
    name: "Board Materials",
    summary: "Restricted board deck folder containing M&A and quarterly planning documents.",
    externalId: "drive://board-materials",
    labels: ["restricted", "finance", "board"],
    criticality: "CRITICAL",
    exposureLevel: "PUBLIC",
    ownershipStatus: "ASSIGNED",
    containsSensitiveData: true,
    isPrivileged: false,
    riskScore: 94,
    lastObservedAt: new Date("2026-05-29T14:00:00.000Z")
  });

  await upsertAsset(vendorAnalyticsAssetId, {
    integrationId: googleIntegrationId,
    type: "OAUTH_APP",
    provider: "GOOGLE_WORKSPACE",
    name: "Vendor Analytics Add-on",
    summary: "Unowned reporting add-on retaining access to Drive and mail metadata.",
    externalId: "vendor-analytics-addon",
    labels: ["third-party", "drive", "mail", "shadow-it"],
    criticality: "MEDIUM",
    exposureLevel: "TRUSTED_EXTERNAL",
    ownershipStatus: "UNASSIGNED",
    containsSensitiveData: false,
    isPrivileged: true,
    riskScore: 68,
    lastObservedAt: new Date("2026-05-12T09:30:00.000Z")
  });

  await upsertSaasIdentity("sid_demo_github_admin", {
    integrationId: githubIntegrationId,
    provider: "GITHUB",
    externalId: "github:user:alex-platform-admin",
    email: "alex@acme.test",
    displayName: "Alex Platform Admin",
    kind: "USER",
    status: "ACTIVE",
    role: "Organization Admin",
    groups: ["github-admins", "engineering"],
    scopeHints: ["repo:admin", "workflow", "org:admin"],
    linkedAssetIds: [githubAppAssetId, paymentsRepoAssetId],
    mfaEnabled: true,
    isPrivileged: true,
    isExternal: false,
    lastObservedAt: new Date("2026-05-29T18:30:00.000Z"),
    riskScore: 83
  });

  await upsertSaasIdentity("sid_demo_github_actions", {
    integrationId: githubIntegrationId,
    provider: "GITHUB",
    externalId: "github:svc:actions-prod",
    email: null,
    displayName: "github-actions-prod",
    kind: "SERVICE_ACCOUNT",
    status: "ACTIVE",
    role: "Deployment automation",
    groups: ["ci", "production-deployments"],
    scopeHints: ["repo:write", "workflow", "deployments"],
    linkedAssetIds: [githubAppAssetId, githubBotAssetId, paymentsRepoAssetId],
    mfaEnabled: null,
    isPrivileged: true,
    isExternal: false,
    lastObservedAt: new Date("2026-05-27T03:00:00.000Z"),
    riskScore: 82
  });

  await upsertSaasIdentity("sid_demo_google_board", {
    integrationId: googleIntegrationId,
    provider: "GOOGLE_WORKSPACE",
    externalId: "google:user:morgan-finance",
    email: "morgan.finance@acme.test",
    displayName: "Morgan Finance",
    kind: "USER",
    status: "ACTIVE",
    role: "Workspace Super Admin",
    groups: ["finance", "board-access"],
    scopeHints: ["drive:admin", "workspace:admin"],
    linkedAssetIds: [googleAppAssetId, boardMaterialsAssetId],
    mfaEnabled: false,
    isPrivileged: true,
    isExternal: false,
    lastObservedAt: new Date("2026-05-29T14:05:00.000Z"),
    riskScore: 91
  });

  await upsertSaasIdentity("sid_demo_google_vendor", {
    integrationId: googleIntegrationId,
    provider: "GOOGLE_WORKSPACE",
    externalId: "google:bot:vendor-analytics",
    email: null,
    displayName: "Vendor Analytics Bot",
    kind: "BOT",
    status: "DORMANT",
    role: "OAuth add-on",
    groups: ["third-party-apps"],
    scopeHints: ["drive.read", "mail.metadata"],
    linkedAssetIds: [googleAppAssetId, vendorAnalyticsAssetId, boardMaterialsAssetId],
    mfaEnabled: null,
    isPrivileged: true,
    isExternal: true,
    lastObservedAt: new Date("2026-05-12T09:30:00.000Z"),
    riskScore: 74
  });

  await upsertSaasIdentity("sid_demo_slack_guest", {
    integrationId: slackIntegrationId,
    provider: "SLACK",
    externalId: "slack:user:finance-guest",
    email: "guest.contractor@vendor.test",
    displayName: "Finance Shared Channel Guest",
    kind: "USER",
    status: "ACTIVE",
    role: "Guest",
    groups: ["finance-shared-channel"],
    scopeHints: ["shared-channel"],
    linkedAssetIds: [slackAppAssetId],
    mfaEnabled: null,
    isPrivileged: false,
    isExternal: true,
    lastObservedAt: new Date("2026-05-28T17:12:00.000Z"),
    riskScore: 46
  });

  await upsertOauthAppGrant("grant_demo_ci_deploy_breakglass", {
    integrationId: githubIntegrationId,
    assetId: githubOauthAssetId,
    provider: "GITHUB",
    externalAppId: "oauth-app-acme-ci",
    appDisplayName: "Acme CI Deploy",
    userEmail: "breakglass@aperio.local",
    userExternalId: "github:user:breakglass",
    userDisplayName: "Break Glass Admin",
    scopes: ["repo", "admin:org", "workflow"],
    anonymous: false,
    nativeApp: false,
    lastObservedAt: new Date("2026-05-29T16:45:00.000Z")
  });

  await upsertOauthAppGrant("grant_demo_vendor_analytics_morgan", {
    integrationId: googleIntegrationId,
    assetId: vendorAnalyticsAssetId,
    provider: "GOOGLE_WORKSPACE",
    externalAppId: "vendor-analytics-addon",
    appDisplayName: "Vendor Analytics Add-on",
    userEmail: "morgan.finance@acme.test",
    userExternalId: "google:user:morgan-finance",
    userDisplayName: "Morgan Finance",
    scopes: ["drive.readonly", "gmail.metadata"],
    anonymous: false,
    nativeApp: false,
    lastObservedAt: new Date("2026-05-12T09:30:00.000Z")
  });

  await upsertOauthAppGrant("grant_demo_vendor_analytics_guest", {
    integrationId: googleIntegrationId,
    assetId: vendorAnalyticsAssetId,
    provider: "GOOGLE_WORKSPACE",
    externalAppId: "vendor-analytics-addon",
    appDisplayName: "Vendor Analytics Add-on",
    userEmail: "guest.contractor@vendor.test",
    userExternalId: "google:user:guest-contractor",
    userDisplayName: "Finance Shared Channel Guest",
    scopes: ["drive.readonly"],
    anonymous: false,
    nativeApp: false,
    lastObservedAt: new Date("2026-05-13T10:15:00.000Z")
  });

  const detectedAt = new Date();
  const findings = [
    {
      id: "fnd_demo_public_repo",
      integrationId: githubIntegrationId,
      assetId: paymentsRepoAssetId,
      dedupeKey: "demo_public_repo",
      title: "Public GitHub repository created",
      description:
        "A repository was created with public visibility and may expose source code or secrets.",
      severity: "CRITICAL" as const,
      riskScore: 95,
      remediationSteps: [
        "Confirm public release approval.",
        "Set repository visibility to private.",
        "Run secret scanning before restoring access."
      ],
      evidence: { repository: "acme/payment-service", actor: "dev@acme.test" }
    },
    {
      id: "fnd_demo_oauth_admin_scopes",
      integrationId: githubIntegrationId,
      assetId: githubOauthAssetId,
      dedupeKey: "demo_oauth_admin_scopes",
      title: "Third-party GitHub OAuth app has admin scopes",
      description:
        "A CI orchestration app retains repository administration and workflow scopes across the engineering org.",
      severity: "HIGH" as const,
      riskScore: 88,
      remediationSteps: [
        "Review the app publisher and legal approval.",
        "Revoke unneeded repository administration scopes.",
        "Move deployments to a tenant-owned GitHub App."
      ],
      evidence: { app: "Acme CI Deploy", owner: "breakglass@aperio.local" }
    },
    {
      id: "fnd_demo_stale_service_account",
      integrationId: githubIntegrationId,
      assetId: githubBotAssetId,
      dedupeKey: "demo_stale_service_account",
      title: "Privileged service account token is stale",
      description:
        "A production deployment identity has not rotated credentials in more than 180 days.",
      severity: "HIGH" as const,
      riskScore: 81,
      remediationSteps: [
        "Rotate the token and invalidate the previous credential.",
        "Move the automation identity to workload identity federation.",
        "Reduce repository and environment access to the minimum set."
      ],
      evidence: { serviceAccount: "github-actions-prod", tokenAgeDays: 187 }
    },
    {
      id: "fnd_demo_external_sharing",
      integrationId: googleIntegrationId,
      assetId: boardMaterialsAssetId,
      dedupeKey: "demo_external_sharing",
      title: "Board materials publicly shared",
      description:
        "A restricted Drive folder containing board documents is accessible through a public sharing link.",
      severity: "HIGH" as const,
      riskScore: 93,
      remediationSteps: [
        "Disable public sharing and scope access to named users.",
        "Verify whether the link was distributed externally.",
        "Apply DLP controls to the containing shared drive."
      ],
      evidence: { resource: "Board Materials", classification: "restricted" }
    },
    {
      id: "fnd_demo_unowned_vendor_app",
      integrationId: googleIntegrationId,
      assetId: vendorAnalyticsAssetId,
      dedupeKey: "demo_unowned_vendor_app",
      title: "Unowned third-party app retains Drive access",
      description:
        "A reporting add-on still holds Drive scopes, but no technical or business owner is recorded.",
      severity: "HIGH" as const,
      riskScore: 72,
      remediationSteps: [
        "Assign a technical owner and business owner.",
        "Review granted scopes and last usage with the vendor.",
        "Remove access if the app is no longer required."
      ],
      evidence: { app: "Vendor Analytics Add-on" }
    }
  ];

  for (const finding of findings) {
    await prisma.securityFinding.upsert({
      where: {
        organizationId_dedupeKey: {
          organizationId,
          dedupeKey: finding.dedupeKey
        }
      },
      update: {
        status: "OPEN",
        resolvedAt: null,
        resolvedById: null
      },
      create: {
        ...finding,
        organizationId,
        status: "OPEN",
        detectedAt
      }
    });
  }

  await prisma.saasIncident.upsert({
    where: { id: saasIncidentId },
    update: {
      title: "Vendor app Drive access may expose board materials",
      summary:
        "Google Workspace and OAuth context indicate a third-party analytics add-on retains Drive access while restricted board materials are externally shared.",
      severity: "HIGH",
      status: "INVESTIGATING",
      confidenceScore: 86,
      ownerTeam: "SecOps",
      assigneeUserId: analystUserId,
      slaDueAt: new Date(Date.now() + 18 * 60 * 60 * 1000),
      resolvedAt: null,
      cerebroContext: {
        source: "cerebro",
        mode: "context-only",
        graphSignals: [
          "restricted data asset",
          "unowned OAuth application",
          "external collaborator path"
        ],
        findingContract: "cerebro.v1.Finding"
      }
    },
    create: {
      id: saasIncidentId,
      organizationId,
      title: "Vendor app Drive access may expose board materials",
      summary:
        "Google Workspace and OAuth context indicate a third-party analytics add-on retains Drive access while restricted board materials are externally shared.",
      severity: "HIGH",
      status: "INVESTIGATING",
      confidenceScore: 86,
      ownerTeam: "SecOps",
      assigneeUserId: analystUserId,
      firstDetectedAt: detectedAt,
      lastActivityAt: new Date(),
      slaDueAt: new Date(Date.now() + 18 * 60 * 60 * 1000),
      cerebroContext: {
        source: "cerebro",
        mode: "context-only",
        graphSignals: [
          "restricted data asset",
          "unowned OAuth application",
          "external collaborator path"
        ],
        findingContract: "cerebro.v1.Finding"
      }
    }
  });

  for (const findingId of [
    "fnd_demo_external_sharing",
    "fnd_demo_unowned_vendor_app"
  ]) {
    await prisma.saasIncidentFinding.upsert({
      where: {
        incidentId_findingId: {
          incidentId: saasIncidentId,
          findingId
        }
      },
      update: { organizationId },
      create: {
        id: `iln_demo_${findingId}`,
        organizationId,
        incidentId: saasIncidentId,
        findingId
      }
    });
  }

  await prisma.saasResponseAction.upsert({
    where: { id: saasResponseActionId },
    update: {
      status: "PROPOSED",
      provider: "GOOGLE_WORKSPACE",
      targetType: "oauth_app",
      targetIdentifier: "Vendor Analytics Add-on",
      rationale:
        "Remove Drive scopes until ownership, legal approval, and data exposure review are complete.",
      approvedByUserId: null,
      approvedAt: null,
      executedAt: null,
      errorMessage: null,
      result: {}
    },
    create: {
      id: saasResponseActionId,
      organizationId,
      incidentId: saasIncidentId,
      findingId: "fnd_demo_unowned_vendor_app",
      action: "REVOKE_OAUTH_GRANT",
      provider: "GOOGLE_WORKSPACE",
      targetType: "oauth_app",
      targetIdentifier: "Vendor Analytics Add-on",
      status: "PROPOSED",
      approvalRequired: true,
      rationale:
        "Remove Drive scopes until ownership, legal approval, and data exposure review are complete.",
      result: {}
    }
  });

  const timeline = [
    {
      id: "tle_demo_vendor_drive_detected",
      kind: "DETECTION" as const,
      title: "Incident opened",
      description:
        "Aperio grouped external Drive sharing with an unowned OAuth app retaining Drive scopes.",
      actor: "aperio",
      responseActionId: undefined
    },
    {
      id: "tle_demo_vendor_drive_cerebro",
      kind: "CEREBRO_CONTEXT" as const,
      title: "Cerebro context attached",
      description:
        "Cerebro context highlights restricted data, ownership gaps, and an external collaborator path.",
      actor: "cerebro",
      responseActionId: undefined
    },
    {
      id: "tle_demo_vendor_drive_response",
      kind: "RESPONSE_ACTION" as const,
      title: "Response proposed",
      description:
        "Revoke the vendor analytics OAuth grant after analyst approval.",
      actor: "finance-security@aperio.local",
      responseActionId: saasResponseActionId
    }
  ];

  for (const event of timeline) {
    await prisma.saasIncidentTimelineEvent.upsert({
      where: { id: event.id },
      update: {
        kind: event.kind,
        title: event.title,
        description: event.description,
        actor: event.actor,
        responseActionId: event.responseActionId ?? null,
        evidence: {
          source: event.actor,
          incidentId: saasIncidentId
        }
      },
      create: {
        id: event.id,
        organizationId,
        incidentId: saasIncidentId,
        responseActionId: event.responseActionId ?? null,
        kind: event.kind,
        title: event.title,
        description: event.description,
        actor: event.actor,
        source: event.actor === "cerebro" ? "CEREBRO" : "APERIO",
        evidence: {
          source: event.actor,
          incidentId: saasIncidentId
        },
        occurredAt: detectedAt
      }
    });
  }

  await prisma.riskException.upsert({
    where: { id: "exc_demo_board_portal" },
    update: {
      title: "Investor diligence portal remains enabled until next board meeting",
      rationale:
        "Leadership approved temporary public link distribution for an investor diligence process.",
      compensatingControls: [
        "Monitor link access daily",
        "Expire access after the next board meeting",
        "Restrict copy and download in Google Drive"
      ],
      status: "ACTIVE",
      expiresAt: new Date("2026-06-15T18:00:00.000Z"),
      approvedByUserId: userId,
      approvedAt: new Date("2026-05-29T19:00:00.000Z")
    },
    create: {
      id: "exc_demo_board_portal",
      organizationId,
      assetId: boardMaterialsAssetId,
      createdByUserId: analystUserId,
      approvedByUserId: userId,
      title: "Investor diligence portal remains enabled until next board meeting",
      rationale:
        "Leadership approved temporary public link distribution for an investor diligence process.",
      compensatingControls: [
        "Monitor link access daily",
        "Expire access after the next board meeting",
        "Restrict copy and download in Google Drive"
      ],
      status: "ACTIVE",
      expiresAt: new Date("2026-06-15T18:00:00.000Z"),
      approvedAt: new Date("2026-05-29T19:00:00.000Z")
    }
  });

  await prisma.riskException.upsert({
    where: { id: "exc_demo_vendor_review" },
    update: {
      title: "Vendor analytics add-on pending legal and owner assignment",
      rationale:
        "The app still supports finance reporting, but engineering has not completed ownership transfer and contract review.",
      compensatingControls: [
        "Limit scopes to read-only",
        "Review activity weekly",
        "Complete owner assignment before renewal"
      ],
      status: "ACTIVE",
      expiresAt: new Date("2026-06-07T18:00:00.000Z"),
      approvedByUserId: adminUserId,
      approvedAt: new Date("2026-05-29T20:00:00.000Z")
    },
    create: {
      id: "exc_demo_vendor_review",
      organizationId,
      assetId: vendorAnalyticsAssetId,
      findingId: "fnd_demo_unowned_vendor_app",
      createdByUserId: analystUserId,
      approvedByUserId: adminUserId,
      title: "Vendor analytics add-on pending legal and owner assignment",
      rationale:
        "The app still supports finance reporting, but engineering has not completed ownership transfer and contract review.",
      compensatingControls: [
        "Limit scopes to read-only",
        "Review activity weekly",
        "Complete owner assignment before renewal"
      ],
      status: "ACTIVE",
      expiresAt: new Date("2026-06-07T18:00:00.000Z"),
      approvedAt: new Date("2026-05-29T20:00:00.000Z")
    }
  });

  await prisma.siemDestination.upsert({
    where: { id: siemDestinationId },
    update: {
      kind: "JSON_FILE",
      name: "Demo local JSONL",
      endpointUrl: null,
      filePath: "demo/findings.jsonl",
      index: null,
      encryptedToken: null,
      streams: ["FINDINGS"],
      status: "ACTIVE",
      lastError: null
    },
    create: {
      id: siemDestinationId,
      organizationId,
      kind: "JSON_FILE",
      name: "Demo local JSONL",
      endpointUrl: null,
      filePath: "demo/findings.jsonl",
      index: null,
      encryptedToken: null,
      streams: ["FINDINGS"],
      status: "ACTIVE"
    }
  });
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
