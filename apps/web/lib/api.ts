import { aperioConnectClient } from "@aperio/connect/client";

export type TenantRole = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export type AuthSession = {
  user: {
    id: string;
    email: string;
    displayName: string | null;
    mfaEnabled: boolean;
    role: TenantRole;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
  };
};

export type DashboardMetrics = {
  totalRiskScore: number;
  openCriticalFindings: number;
  connectedApps: number;
  eventIngestionRate: number;
};

export type Provider =
  | "GITHUB"
  | "SLACK"
  | "GOOGLE_WORKSPACE"
  | "ONE_PASSWORD"
  | "OKTA"
  | "MICROSOFT_365"
  | "ATLASSIAN";

export type SignupPayload = {
  organizationName: string;
  organizationSlug: string;
  notificationEmail?: string;
  ownerEmail: string;
  ownerDisplayName?: string;
  password: string;
};

export type LoginPayload = {
  organizationSlug: string;
  email: string;
  password: string;
  totpCode?: string;
};

export type Finding = {
  id: string;
  assetId?: string | null;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "OPEN" | "RESOLVED" | "MUTED";
  riskScore: number;
  detectedAt: string;
  resolvedAt?: string | null;
  evidence?: Record<string, unknown>;
  remediationSteps: string[];
  tags: string[];
  integration: {
    id?: string;
    provider: Provider;
    displayName: string;
  };
};

export type FindingsFilters = {
  severity?: Finding["severity"];
  status?: Finding["status"] | "ALL";
  provider?: Provider;
  integrationId?: string;
  limit?: number;
  cursor?: string;
};

export type ConnectorField = {
  key: string;
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type IntegrationMode = "READ_ONLY" | "REMEDIATION";

export type RemediationAction = {
  key: string;
  label: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM";
};

export type FindingCheck = {
  key: string;
  title: string;
  description: string;
  severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  defaultEnabled: boolean;
};

export type FindingCheckStatus = FindingCheck & { enabled: boolean };

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

export type IntegrationConnection = {
  id: string;
  provider: Provider;
  displayName: string;
  externalAccountId: string;
  status: "CONNECTED" | "DISABLED" | "ERROR";
  mode: IntegrationMode;
  scopes: string[];
  disabledChecks: string[];
  googleMailboxScanEnabled: boolean;
  googleMailboxScanClientEmail: string | null;
  lastSyncAt: string | null;
  createdAt: string;
};

export type GoogleMailboxScanConfig = {
  enabled: boolean;
  serviceAccountClientEmail: string | null;
};

export type GoogleWorkspaceBigQueryConfig = {
  enabled: boolean;
  projectId: string;
  rawDatasetId: string;
  datasetId: string;
  location: string;
  serviceAccountEmail: string;
  workloadIdentityProvider: string;
  accessMode: "views" | "dataset" | "";
  updatedAt: string | null;
};

export type IntegrationCheckState = {
  integrationId: string;
  disabledChecks: string[];
  checks: FindingCheckStatus[];
};

export type SiemKind =
  | "SPLUNK_HEC"
  | "PANTHER"
  | "PANOPTICON"
  | "ELASTIC"
  | "DATADOG"
  | "GENERIC_WEBHOOK"
  | "CEREBRO_CLAIMS"
  | "JSON_FILE";

export type SiemStream = "FINDINGS" | "EVENTS" | "AUDIT_LOGS";

export type SiemField = {
  key: "endpointUrl" | "token" | "filePath" | "index";
  label: string;
  placeholder?: string;
  helper?: string;
  type: "text" | "password" | "url";
  required: boolean;
  secret: boolean;
};

export type SiemDestinationDefinition = {
  kind: SiemKind;
  name: string;
  vendor: string;
  description: string;
  category: "Cloud SIEM" | "Hosted Search" | "Observability" | "Graph" | "Generic";
  docsUrl: string;
  defaultStreams: SiemStream[];
  fields: SiemField[];
};

export type SiemDestination = {
  id: string;
  kind: SiemKind;
  name: string;
  endpointUrl: string | null;
  filePath: string | null;
  index: string | null;
  streams: SiemStream[];
  status: "ACTIVE" | "PAUSED" | "ERROR";
  lastDeliveryAt: string | null;
  lastError: string | null;
  deliveriesOk: number;
  deliveriesFail: number;
  createdAt: string;
};

export type CreateSiemPayload = {
  kind: SiemKind;
  name: string;
  endpointUrl?: string;
  filePath?: string;
  index?: string;
  token?: string;
  streams: SiemStream[];
};

export type SiemTestResult = {
  destinationId: string;
  ok: boolean;
  message: string;
};

export type ConnectIntegrationPayload = {
  provider: Provider;
  displayName: string;
  externalAccountId: string;
  mode: IntegrationMode;
  credentials: {
    accessToken: string;
    refreshToken?: string;
    webhookSecret?: string;
  };
};

export type RemediationResult = {
  findingId: string;
  action: string;
  success: boolean;
  message: string;
  providerRequestId: string;
  effects: string[];
};

export async function signup(payload: SignupPayload) {
  return aperioConnectClient.signup(payload) as Promise<{ data: AuthSession }>;
}

export async function login(payload: LoginPayload) {
  return aperioConnectClient.login(payload) as Promise<{ data: AuthSession }>;
}

export async function fetchCurrentSession() {
  return aperioConnectClient.getCurrentSession() as Promise<{
    data: AuthSession;
  }>;
}

export async function logoutCurrentSession() {
  return aperioConnectClient.logoutCurrentSession();
}

export type WorkspaceMembership = {
  id: string;
  name: string;
  slug: string;
  role: TenantRole;
  current: boolean;
};

export async function fetchWorkspaces() {
  return aperioConnectClient.listWorkspaces() as Promise<{
    data: WorkspaceMembership[];
  }>;
}

export async function switchWorkspace(payload: {
  organizationSlug: string;
  password: string;
  totpCode?: string;
}) {
  return aperioConnectClient.switchWorkspace(payload) as Promise<{
    data: AuthSession;
  }>;
}

export async function requestPasswordReset(payload: {
  organizationSlug: string;
  email: string;
}) {
  return aperioConnectClient.requestPasswordReset(payload) as Promise<{
    data: {
      accepted: boolean;
      delivery?: "manual_link" | "email";
      resetUrl?: string;
      expiresAt?: string;
    };
  }>;
}

export async function resetPassword(payload: {
  token: string;
  password: string;
}) {
  return aperioConnectClient.resetPassword(payload) as Promise<{
    data: AuthSession;
  }>;
}

export async function acceptInvite(payload: {
  token: string;
  displayName?: string;
  password: string;
}) {
  return aperioConnectClient.acceptInvite(payload) as Promise<{
    data: AuthSession;
  }>;
}

export type MfaEnrollment = {
  secret: string;
  otpauthUrl: string;
};

export async function beginMfaEnrollment() {
  return aperioConnectClient.beginMfaEnrollment() as Promise<{
    data: MfaEnrollment;
  }>;
}

export async function enableMfa(code: string) {
  return aperioConnectClient.enableMfa(code) as Promise<{
    data: AuthSession;
  }>;
}

export async function disableMfa(payload: {
  password: string;
  code?: string;
}) {
  return aperioConnectClient.disableMfa(payload) as Promise<{
    data: AuthSession;
  }>;
}

export async function fetchDashboardMetrics() {
  return aperioConnectClient.getDashboardMetrics();
}

export async function fetchFindings(filters?: FindingsFilters) {
  return aperioConnectClient.listFindings(filters) as Promise<{
    data: Finding[];
    pageInfo: { total: number; nextCursor: string | null };
  }>;
}

export async function fetchFinding(id: string) {
  return aperioConnectClient.getFinding(id) as Promise<{ data: Finding }>;
}

export async function updateFindingStatus(
  id: string,
  payload: {
    status: "RESOLVED" | "MUTED";
    resolutionNote?: string;
  }
) {
  return aperioConnectClient.updateFindingStatus(id, payload);
}

export async function resolveFinding(id: string, resolutionNote?: string) {
  return updateFindingStatus(id, {
    status: "RESOLVED",
    resolutionNote:
      resolutionNote ?? "Resolved from the Aperio executive dashboard"
  });
}

export async function acceptFindingRisk(id: string, resolutionNote?: string) {
  return updateFindingStatus(id, {
    status: "MUTED",
    resolutionNote:
      resolutionNote ?? "Risk accepted from the Aperio finding detail page"
  });
}

export async function fetchConnectorCatalog() {
  return aperioConnectClient.listConnectorCatalog() as Promise<{
    data: ConnectorDefinition[];
  }>;
}

export async function fetchIntegrations() {
  return aperioConnectClient.listIntegrations() as Promise<{
    data: IntegrationConnection[];
  }>;
}

export async function fetchGoogleMailboxScanConfig(integrationId: string) {
  return aperioConnectClient.getGoogleMailboxScanConfig(
    integrationId
  ) as Promise<{ data: GoogleMailboxScanConfig }>;
}

export async function connectIntegration(payload: ConnectIntegrationPayload) {
  return aperioConnectClient.createIntegration(payload) as Promise<{
    data: IntegrationConnection;
  }>;
}

export async function updateGoogleMailboxScanConfig(
  integrationId: string,
  payload: {
    enabled: boolean;
    serviceAccountClientEmail?: string;
    privateKey?: string;
  }
) {
  return aperioConnectClient.updateGoogleMailboxScanConfig(
    integrationId,
    payload
  ) as Promise<{ data: GoogleMailboxScanConfig }>;
}

export async function fetchGoogleWorkspaceBigQueryConfig(integrationId: string) {
  return aperioConnectClient.getGoogleWorkspaceBigQueryConfig(
    integrationId
  ) as Promise<{ data: GoogleWorkspaceBigQueryConfig }>;
}

export async function updateGoogleWorkspaceBigQueryConfig(
  integrationId: string,
  payload: {
    enabled: boolean;
    projectId?: string;
    rawDatasetId?: string;
    datasetId?: string;
    location?: string;
    serviceAccountEmail?: string;
    workloadIdentityProvider?: string;
    accessMode?: "views" | "dataset";
  }
) {
  return aperioConnectClient.updateGoogleWorkspaceBigQueryConfig(
    integrationId,
    payload
  ) as Promise<{ data: GoogleWorkspaceBigQueryConfig }>;
}

export async function startGoogleWorkspaceOAuth(mode: IntegrationMode) {
  return aperioConnectClient.startGoogleWorkspaceOAuth(mode);
}

export async function fetchIntegrationOAuthClient(provider: "GOOGLE_WORKSPACE") {
  return aperioConnectClient.getIntegrationOAuthClient(provider);
}

export async function saveIntegrationOAuthClient(input: {
  provider: "GOOGLE_WORKSPACE";
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}) {
  return aperioConnectClient.setIntegrationOAuthClient(input);
}

export async function clearIntegrationOAuthClient(provider: "GOOGLE_WORKSPACE") {
  return aperioConnectClient.clearIntegrationOAuthClient(provider);
}

export type IntegrationOAuthClient =
  import("@aperio/connect/client").ConnectIntegrationOAuthClient;

export async function fetchSiemCatalog() {
  return aperioConnectClient.listSiemCatalog() as Promise<{
    data: SiemDestinationDefinition[];
  }>;
}

export async function fetchSiemDestinations() {
  return aperioConnectClient.listSiemDestinations() as Promise<{
    data: SiemDestination[];
  }>;
}

export async function createSiemDestination(payload: CreateSiemPayload) {
  return aperioConnectClient.createSiemDestination(payload) as Promise<{
    data: SiemDestination;
  }>;
}

export async function testSiemDestination(id: string) {
  return aperioConnectClient.testSiemDestination(id) as Promise<{
    data: SiemTestResult;
  }>;
}

export async function deleteSiemDestination(id: string) {
  await aperioConnectClient.deleteSiemDestination(id);
}

export async function fetchIntegrationChecks(integrationId: string) {
  return aperioConnectClient.getIntegrationChecks(integrationId) as Promise<{
    data: IntegrationCheckState;
  }>;
}

export async function updateIntegrationChecks(
  integrationId: string,
  disabledChecks: string[]
) {
  return aperioConnectClient.updateIntegrationChecks(
    integrationId,
    disabledChecks
  ) as Promise<{ data: IntegrationCheckState }>;
}

export type ConnectorBuiltInRule =
  import("@aperio/connect/client").ConnectConnectorBuiltInRule;
export type ConnectorCustomRule =
  import("@aperio/connect/client").ConnectConnectorCustomRule;
export type ConnectorRulesResponse =
  import("@aperio/connect/client").ConnectConnectorRulesResponse;
export type CustomRuleInput =
  import("@aperio/connect/client").ConnectCustomRuleInput;

export async function fetchConnectorRules(integrationId: string) {
  const out = await aperioConnectClient.listConnectorRules(integrationId);
  return out.data;
}

export async function createCustomRule(
  integrationId: string,
  input: CustomRuleInput
) {
  return aperioConnectClient.createCustomRule(integrationId, input);
}

export async function updateCustomRule(
  integrationId: string,
  ruleId: string,
  input: CustomRuleInput
) {
  return aperioConnectClient.updateCustomRule(integrationId, ruleId, input);
}

export async function deleteCustomRule(integrationId: string, ruleId: string) {
  return aperioConnectClient.deleteCustomRule(integrationId, ruleId);
}

export async function forceSyncIntegration(integrationId: string) {
  return aperioConnectClient.forceSyncIntegration(integrationId) as Promise<{
    data: IntegrationConnection;
    sync: {
      sampleCount: number;
      eventsIngested: number;
      findingsOpened: number;
      sources: string[];
    };
  }>;
}

export async function remediateFinding(
  findingId: string,
  payload: { action: string; targetIdentifier?: string; note?: string }
) {
  return aperioConnectClient.remediateFinding(findingId, payload) as Promise<{
    data: RemediationResult;
  }>;
}

export async function disconnectIntegration(id: string) {
  await aperioConnectClient.deleteIntegration(id);
}

export type TenantSettings = {
  id: string;
  name: string;
  slug: string;
  notificationEmail: string | null;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string | null;
  createdAt: string;
  updatedAt: string;
};

export type TenantMember = {
  id: string;
  email: string;
  displayName: string | null;
  isActive: boolean;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  isBreakGlass: boolean;
  role: TenantRole;
  authState: "ACTIVE" | "INVITED" | "PASSWORD_RESET_PENDING";
  pendingActionExpiresAt: string | null;
  createdAt: string;
};

export type AuditLogEntry = {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  actor: string;
  createdAt: string;
  metadata: Record<string, unknown> | null;
};

export type SecurityAssetType =
  | "APPLICATION"
  | "OAUTH_APP"
  | "SERVICE_ACCOUNT"
  | "DATA_RESOURCE"
  | "WORKSPACE"
  | "VAULT"
  | "REPOSITORY";

export type AssetCriticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AssetExposureLevel = "INTERNAL" | "TRUSTED_EXTERNAL" | "PUBLIC";
export type AssetOwnershipStatus =
  | "ASSIGNED"
  | "UNASSIGNED"
  | "REVIEW_REQUIRED";
export type RiskExceptionStatus = "ACTIVE" | "EXPIRED" | "REVOKED";

export type SecurityAsset = {
  id: string;
  type: SecurityAssetType;
  provider: Provider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: AssetCriticality;
  exposureLevel: AssetExposureLevel;
  ownershipStatus: AssetOwnershipStatus;
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  createdAt: string;
  updatedAt: string;
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
  owner: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  businessOwner: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  openFindingCount: number;
  activeExceptionCount: number;
};

export type RiskException = {
  id: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: RiskExceptionStatus;
  expiresAt: string | null;
  approvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  asset: {
    id: string;
    name: string;
    type: SecurityAssetType;
  } | null;
  finding: {
    id: string;
    title: string;
    severity: Finding["severity"];
    status: Finding["status"];
  } | null;
  createdBy: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
  approvedBy: {
    id: string;
    email: string;
    displayName: string | null;
  } | null;
};

export type SecurityIdentity = {
  id: string;
  entityId: string;
  kind: "USER" | "SERVICE_ACCOUNT" | "BOT";
  name: string;
  email: string | null;
  provider: Provider | null;
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
  role: string;
  privileged: boolean;
  mfaEnabled: boolean | null;
  status: "ACTIVE" | "SUSPENDED" | "DORMANT";
  isExternal: boolean;
  lastObservedAt: string | null;
  linkedAssetCount: number;
  riskScore: number;
};

export type SecurityGraphNode = {
  id: string;
  label: string;
  kind: string;
  riskScore: number;
  privileged: boolean;
  exposureLevel: string;
  criticality: string;
};

export type SecurityGraphEdge = {
  id: string;
  sourceId: string;
  targetId: string;
  relationshipType: string;
};

export type AttackPath = {
  id: string;
  title: string;
  score: number;
  findingTitle: string;
  entryPoint: string;
  target: string;
  owner: string;
  exposureLevel: AssetExposureLevel;
  criticality: AssetCriticality;
  reason: string;
  path: string[];
};

export type DomainWideDelegation = {
  integrationId: string;
  provider: "GOOGLE_WORKSPACE";
  displayName: string;
  workspaceDomain: string;
  serviceAccountClientEmail: string | null;
  scopes: string[];
  status: "ENABLED" | "NOT_CONFIGURED";
  integrationStatus: "CONNECTED" | "DISABLED" | "ERROR";
  mode: "READ_ONLY" | "REMEDIATION";
  openMailboxFindings: number;
  lastSyncAt: string | null;
  configuredAt: string;
};

export type SecurityOverview = {
  summary: {
    privilegedIdentities: number;
    adminIdentitiesWithoutMfa: number;
    riskyOauthApps: number;
    exposedDataAssets: number;
    unownedAssets: number;
    activeExceptions: number;
    topBlastRadiusScore: number;
  };
  identities: SecurityIdentity[];
  graph: {
    nodes: SecurityGraphNode[];
    edges: SecurityGraphEdge[];
  };
  oauthApps: SecurityAsset[];
  dataAssets: SecurityAsset[];
  attackPaths: AttackPath[];
  ownershipGaps: SecurityAsset[];
  exceptions: RiskException[];
  domainWideDelegations?: DomainWideDelegation[];
};

export type CreateSecurityAssetPayload = {
  integrationId?: string;
  ownerUserId?: string;
  businessOwnerUserId?: string;
  type: SecurityAssetType;
  provider?: Provider;
  name: string;
  summary?: string;
  externalId?: string;
  labels: string[];
  criticality: AssetCriticality;
  exposureLevel: AssetExposureLevel;
  ownershipStatus?: AssetOwnershipStatus;
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt?: string;
};

export type UpdateSecurityAssetPayload = Partial<CreateSecurityAssetPayload>;

export type CreateRiskExceptionPayload = {
  assetId?: string;
  findingId?: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  expiresAt?: string;
};

export type UpdateRiskExceptionPayload = Partial<{
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: RiskExceptionStatus;
  expiresAt: string;
}>;

export type TenantSettingsUpdate = Partial<{
  name: string;
  notificationEmail: string;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string;
}>;

export async function fetchTenantSettings() {
  return aperioConnectClient.getTenantSettings() as Promise<{
    data: TenantSettings;
  }>;
}

export async function updateTenantSettings(payload: TenantSettingsUpdate) {
  return aperioConnectClient.updateTenantSettings(payload) as Promise<{
    data: TenantSettings;
  }>;
}

export async function fetchTenantMembers() {
  return aperioConnectClient.listTenantMembers() as Promise<{
    data: TenantMember[];
  }>;
}

export type CreateMemberPayload = {
  email: string;
  displayName?: string;
  roleName: TenantRole;
};

export type InvitationResult = {
  delivery: "manual_link" | "email";
  url?: string;
  expiresAt: string;
};

export async function createTenantMember(payload: CreateMemberPayload) {
  return aperioConnectClient.createTenantMember(payload) as Promise<{
    data: TenantMember;
    invitation: InvitationResult;
  }>;
}

export async function createMemberResetLink(id: string) {
  return aperioConnectClient.createMemberResetLink(id) as Promise<{
    data: TenantMember;
    reset: InvitationResult;
  }>;
}

export async function updateMemberRole(id: string, roleName: TenantRole) {
  return aperioConnectClient.updateMemberRole(id, roleName) as Promise<{
    data: TenantMember;
  }>;
}

export async function fetchAuditLogs() {
  return aperioConnectClient.listAuditLogs() as Promise<{
    data: AuditLogEntry[];
  }>;
}

export async function fetchSecurityOverview() {
  return aperioConnectClient.getSecurityOverview() as Promise<{
    data: SecurityOverview;
  }>;
}

export async function fetchSecurityAssets() {
  return aperioConnectClient.listSecurityAssets() as Promise<{
    data: SecurityAsset[];
  }>;
}

export async function createSecurityAsset(payload: CreateSecurityAssetPayload) {
  return aperioConnectClient.createSecurityAsset(payload) as Promise<{
    data: SecurityAsset;
  }>;
}

export async function updateSecurityAsset(
  id: string,
  payload: UpdateSecurityAssetPayload
) {
  return aperioConnectClient.updateSecurityAsset(id, payload) as Promise<{
    data: SecurityAsset;
  }>;
}

export async function fetchRiskExceptions() {
  return aperioConnectClient.listRiskExceptions() as Promise<{
    data: RiskException[];
  }>;
}

export async function createRiskException(payload: CreateRiskExceptionPayload) {
  return aperioConnectClient.createRiskException(payload) as Promise<{
    data: RiskException;
  }>;
}

export async function updateRiskException(
  id: string,
  payload: UpdateRiskExceptionPayload
) {
  return aperioConnectClient.updateRiskException(id, payload) as Promise<{
    data: RiskException;
  }>;
}

export type ShadowItOauthApp = {
  id: string;
  provider: Provider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: AssetCriticality;
  containsSensitiveData: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  userCount: number;
  scopes: string[];
  integration: {
    id: string;
    provider: Provider;
    displayName: string;
  } | null;
};

export type ShadowItOauthAppGrant = {
  id: string;
  userEmail: string;
  userExternalId: string | null;
  userDisplayName: string | null;
  scopes: string[];
  anonymous: boolean;
  nativeApp: boolean;
  lastObservedAt: string;
};

export type ShadowItOauthAppDetail = {
  app: {
    id: string;
    name: string;
    externalId: string | null;
    provider: Provider | null;
  };
  grants: ShadowItOauthAppGrant[];
};

export async function fetchShadowItOauthApps() {
  return aperioConnectClient.listShadowItOauthApps() as Promise<{
    data: ShadowItOauthApp[];
  }>;
}

export async function fetchShadowItOauthAppGrants(assetId: string) {
  return aperioConnectClient.listShadowItOauthAppGrants(assetId) as Promise<{
    data: ShadowItOauthAppDetail;
  }>;
}

export type ExecutiveReportPeriod = "WEEK" | "MONTH" | "QUARTER" | "CUSTOM";
export type ExecutiveReportStatus = "GENERATING" | "READY" | "FAILED";
export type ExecutiveReportTemplate =
  | "EXECUTIVE_SUMMARY"
  | "GOOGLE_WORKSPACE_ASSESSMENT";

export type ExecutiveReportSummary = {
  id: string;
  template: ExecutiveReportTemplate;
  period: ExecutiveReportPeriod;
  periodStart: string;
  periodEnd: string;
  title: string;
  summary?: string;
  status: ExecutiveReportStatus;
  hasHtml: boolean;
  hasPdf: boolean;
  htmlUrl?: string;
  pdfUrl?: string;
  createdAt: string;
  updatedAt: string;
  generatedAt?: string;
  errorMessage?: string;
  kpiSnapshot: Record<string, unknown>;
};

export async function fetchExecutiveReports() {
  return aperioConnectClient.listExecutiveReports() as Promise<{
    data: ExecutiveReportSummary[];
  }>;
}

export async function fetchExecutiveReport(id: string) {
  return aperioConnectClient.getExecutiveReport(id) as Promise<{
    data: ExecutiveReportSummary;
  }>;
}

export async function createExecutiveReport(payload: {
  period: ExecutiveReportPeriod;
  title?: string;
  periodStart?: string;
  periodEnd?: string;
  template?: ExecutiveReportTemplate;
}) {
  return aperioConnectClient.createExecutiveReport(payload) as Promise<{
    data: ExecutiveReportSummary;
  }>;
}

export async function deleteExecutiveReport(id: string) {
  return aperioConnectClient.deleteExecutiveReport(id) as Promise<{
    data: { deleted: boolean };
  }>;
}

// Reports' HTML and PDF artifacts are streamed out of band as static files
// rather than over Connect-RPC; the server returns the canonical URL on the
// report payload so clients never construct API paths themselves.
export function resolveReportArtifactUrl(
  report: ExecutiveReportSummary,
  kind: "html" | "pdf"
): string | null {
  if (kind === "html") return report.htmlUrl ?? null;
  return report.pdfUrl ?? null;
}

export type ComplianceReportControl = {
  id: string;
  title: string;
  status: "PASS" | "PARTIAL" | "FAIL" | "NOT_APPLICABLE";
  evidenceCount: number;
  owner: string;
};

export type ComplianceReportGroup = {
  id: string;
  title: string;
  description: string;
  controls: ComplianceReportControl[];
};

export type ComplianceReportFramework = {
  id: string;
  name: string;
  version: string;
  description: string;
  groups: ComplianceReportGroup[];
};

export type ComplianceReportPayload = {
  generatedAt: string;
  organization: string;
  frameworks: ComplianceReportFramework[];
};

// exportComplianceReport posts the current dashboard snapshot to the Go
// renderer and returns the resulting PDF as a Blob. The fetch is
// same-origin via a Next.js rewrite, so the session cookie is
// included automatically without CORS gymnastics.
export async function exportComplianceReport(
  payload: ComplianceReportPayload
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch("/compliance/reports/render", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      text || `Compliance report failed (${response.status})`
    );
  }
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] ?? "aperio-compliance.pdf";
  const blob = await response.blob();
  return { blob, filename };
}
