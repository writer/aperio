import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  AperioService,
  type AuditLogEntry as ProtoAuditLogEntry,
  type AuthSession as ProtoAuthSession,
  type ConnectorDefinition as ProtoConnectorDefinition,
  type EmailDomainDkimSelector as ProtoEmailDomainDkimSelector,
  type EmailDomainHealth as ProtoEmailDomainHealth,
  type EmailDomainHealthDetail as ProtoEmailDomainHealthDetail,
  type EmailDomainHealthHistoryPoint as ProtoEmailDomainHealthHistoryPoint,
  type EmailDomainHealthIssue as ProtoEmailDomainHealthIssue,
  type Finding as ProtoFinding,
  type GoogleMailboxScanConfig as ProtoGoogleMailboxScanConfig,
  type GoogleWorkspaceBigQueryConfig as ProtoGoogleWorkspaceBigQueryConfig,
  type GoogleWorkspaceBigQueryValidation as ProtoGoogleWorkspaceBigQueryValidation,
  type IntegrationCheckState as ProtoIntegrationCheckState,
  type IntegrationConnection as ProtoIntegrationConnection,
  type IntegrationSourceSyncAction as ProtoIntegrationSourceSyncAction,
  type IntegrationSourceSyncState as ProtoIntegrationSourceSyncState,
  type IntegrationSyncStatus as ProtoIntegrationSyncStatus,
  type InvitationResult as ProtoInvitationResult,
  type MfaEnrollment as ProtoMfaEnrollment,
  type PasswordResetResult as ProtoPasswordResetResult,
  type RemediationResult as ProtoRemediationResult,
  type RiskException as ProtoRiskException,
  type SaasIncident as ProtoSaasIncident,
  type SaasIncidentDetail as ProtoSaasIncidentDetail,
  type SaasIncidentMetrics as ProtoSaasIncidentMetrics,
  type SaasIncidentTimelineEvent as ProtoSaasIncidentTimelineEvent,
  type SaasResponseAction as ProtoSaasResponseAction,
  type SecurityGraph as ProtoSecurityGraph,
  type SecurityGraphEdge as ProtoSecurityGraphEdge,
  type SecurityGraphNode as ProtoSecurityGraphNode,
  type SecurityIdentity as ProtoSecurityIdentity,
  type SecurityOverview as ProtoSecurityOverview,
  type SecurityAsset as ProtoSecurityAsset,
  type SecurityPrincipal as ProtoSecurityPrincipal,
  type SiemDestination as ProtoSiemDestination,
  type SiemDestinationDefinition as ProtoSiemDestinationDefinition,
  type ShadowItOauthApp as ProtoShadowItOauthApp,
  type ShadowItOauthAppGrant as ProtoShadowItOauthAppGrant,
  type TenantMember as ProtoTenantMember,
  type TenantSettings as ProtoTenantSettings,
  type WorkspaceMembership as ProtoWorkspaceMembership
} from "./gen/aperio/v1/api_pb";

const CONNECT_BASE_URL =
  process.env.NEXT_PUBLIC_CONNECT_API_BASE_URL?.replace(/\/$/, "") ??
  "http://localhost:4100";

export type ConnectDashboardMetrics = {
  totalRiskScore: number;
  openCriticalFindings: number;
  connectedApps: number;
  eventIngestionRate: number;
};

export type ConnectFinding = {
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
    provider:
      | "GITHUB"
      | "SLACK"
      | "GOOGLE_WORKSPACE"
      | "ONE_PASSWORD"
      | "OKTA"
      | "MICROSOFT_365"
      | "ATLASSIAN"
      | "SALESFORCE";
    displayName: string;
  };
};

export type ConnectFindingsFilters = {
  severity?: ConnectFinding["severity"];
  status?: ConnectFinding["status"] | "ALL";
  provider?: ConnectFinding["integration"]["provider"];
  integrationId?: string;
  limit?: number;
  cursor?: string;
};

export type ConnectSecurityPrincipal = {
  id: string;
  email: string;
  displayName: string | null;
};

export type ConnectSaasIncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED";

export type ConnectSaasResponseActionKind =
  | "REVOKE_OAUTH_GRANT"
  | "SUSPEND_USER"
  | "RESET_MFA"
  | "REVOKE_SESSION"
  | "REMOVE_EXTERNAL_SHARE"
  | "DISABLE_FORWARDING"
  | "REMOVE_ADMIN_ROLE"
  | "QUARANTINE_APP"
  | "OPEN_TICKET"
  | "NOTIFY_SECOPS";

export type ConnectSaasResponseActionStatus =
  | "PROPOSED"
  | "APPROVED"
  | "EXECUTING"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED";

export type ConnectCerebroEntityRef = {
  urn: string;
  type: string;
  label: string;
  provider?: string | null;
};

export type ConnectCerebroGraphSignal = {
  label: string;
  predicate?: string | null;
  confidence?: number | null;
  entityUrn?: string | null;
  evidence?: string | null;
};

export type ConnectCerebroGraphPath = {
  id: string;
  title: string;
  risk?: string | null;
  nodes: ConnectCerebroEntityRef[];
};

export type ConnectCerebroClaimSummary = {
  claimType: string;
  predicate: string;
  subjectUrn: string;
  objectUrn?: string | null;
  sourceEvent?: string | null;
};

export type ConnectCerebroMCPContext = {
  server?: string | null;
  resourceUri?: string | null;
  mimeType?: string | null;
  tools: string[];
};

export type ConnectCerebroIncidentContext = {
  source: string;
  mode: string;
  sourceRuntimeId?: string | null;
  findingContract?: string | null;
  claimCount?: number | null;
  lastClaimFanoutAt?: string | null;
  graphSignals: ConnectCerebroGraphSignal[];
  entities: ConnectCerebroEntityRef[];
  graphPaths: ConnectCerebroGraphPath[];
  claimSummaries: ConnectCerebroClaimSummary[];
  responseHints: string[];
  mcp: ConnectCerebroMCPContext | null;
};

export type ConnectSaasIncident = {
  id: string;
  title: string;
  summary: string;
  severity: ConnectFinding["severity"];
  status: ConnectSaasIncidentStatus;
  confidenceScore: number;
  ownerTeam: string | null;
  assignee: ConnectSecurityPrincipal | null;
  firstDetectedAt: string;
  lastActivityAt: string;
  slaDueAt: string | null;
  resolvedAt: string | null;
  cerebroContext: ConnectCerebroIncidentContext;
  createdAt: string;
  updatedAt: string;
  findingCount: number;
  openFindingCount: number;
  responseActionCount: number;
  completedResponseActionCount: number;
};

export type ConnectSaasIncidentMetrics = {
  open: number;
  investigating: number;
  contained: number;
  resolved: number;
  criticalOpen: number;
  responseActionsPending: number;
};

export type ConnectSaasIncidentTimelineEvent = {
  id: string;
  incidentId: string;
  findingId: string | null;
  responseActionId: string | null;
  kind:
    | "DETECTION"
    | "CEREBRO_CONTEXT"
    | "INVESTIGATION"
    | "RESPONSE_ACTION"
    | "STATUS_CHANGE"
    | "NOTE";
  title: string;
  description: string;
  actor: string | null;
  source: string;
  evidence: Record<string, unknown>;
  occurredAt: string;
  createdAt: string;
};

export type ConnectSaasResponseAction = {
  id: string;
  incidentId: string;
  findingId: string | null;
  action: ConnectSaasResponseActionKind;
  provider: ConnectProvider | null;
  targetType: string;
  targetIdentifier: string;
  status: ConnectSaasResponseActionStatus;
  approvalRequired: boolean;
  rationale: string;
  approvedBy: ConnectSecurityPrincipal | null;
  approvedAt: string | null;
  executedAt: string | null;
  errorMessage: string | null;
  result: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

export type ConnectSaasIncidentDetail = {
  incident: ConnectSaasIncident;
  findings: ConnectFinding[];
  timeline: ConnectSaasIncidentTimelineEvent[];
  responseActions: ConnectSaasResponseAction[];
};

export type ConnectSaasIncidentsFilters = {
  status?: ConnectSaasIncidentStatus | "ALL";
  severity?: ConnectFinding["severity"];
  assigneeUserId?: string;
  limit?: number;
  cursor?: string;
};

type ConnectProvider = ConnectFinding["integration"]["provider"];

type ConnectTenantRole = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export type ConnectAuthSession = {
  user: {
    id: string;
    email: string;
    displayName: string | null;
    mfaEnabled: boolean;
    role: ConnectTenantRole;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
  };
};

export type ConnectWorkspaceMembership = {
  id: string;
  name: string;
  slug: string;
  role: ConnectTenantRole;
  current: boolean;
};

export type ConnectPasswordResetResult = {
  accepted: boolean;
  delivery?: "manual_link" | "email";
  resetUrl?: string;
  expiresAt?: string;
  organizationName?: string;
};

export type ConnectMfaEnrollment = {
  secret: string;
  otpauthUrl: string;
};

export type ConnectIntegrationConnection = {
  id: string;
  provider: ConnectProvider;
  displayName: string;
  externalAccountId: string;
  status: "CONNECTED" | "DISABLED" | "ERROR";
  mode: "READ_ONLY" | "REMEDIATION";
  scopes: string[];
  disabledChecks: string[];
  googleMailboxScanEnabled: boolean;
  googleMailboxScanClientEmail: string | null;
  lastSyncAt: string | null;
  createdAt: string;
};

export type ConnectIntegrationPayload = {
  provider: ConnectProvider;
  displayName: string;
  externalAccountId: string;
  mode: "READ_ONLY" | "REMEDIATION";
  credentials: {
    accessToken: string;
    refreshToken?: string;
    webhookSecret?: string;
  };
};

export type ConnectIntegrationOAuthClient = {
  provider: "GOOGLE_WORKSPACE";
  clientId: string;
  redirectUri: string;
  defaultRedirectUri: string;
  configured: boolean;
  source: "tenant" | "env" | "";
  updatedAt: string | null;
};

export type ConnectConnectorDefinition = {
  provider: ConnectProvider;
  name: string;
  category: string;
  availability: "production_ready" | "preview";
  readinessNote?: string;
  description: string;
  readScopes: string[];
  remediationScopes: string[];
  remediationActions: {
    key: string;
    label: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM";
  }[];
  findingChecks: {
    key: string;
    title: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    defaultEnabled: boolean;
  }[];
  docsUrl: string;
  fields: {
    key: string;
    label: string;
    placeholder?: string;
    helper?: string;
    type: "text" | "password" | "url";
    required: boolean;
    secret: boolean;
  }[];
};

export type ConnectGoogleMailboxScanConfig = {
  enabled: boolean;
  serviceAccountClientEmail: string | null;
};

export type ConnectGoogleWorkspaceBigQueryConfig = {
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

export type ConnectGoogleWorkspaceBigQueryValidation = {
  integrationId: string;
  ok: boolean;
  message: string;
  projectId: string;
  datasetId: string;
  activityTable: string;
  tableFound: boolean;
  sampleRows: number;
  estimatedBytes: bigint;
  runtimeTokenPresent: boolean;
};

export type ConnectIntegrationCheckState = {
  integrationId: string;
  disabledChecks: string[];
  checks: {
    key: string;
    title: string;
    description: string;
    severityHint: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    defaultEnabled: boolean;
    enabled: boolean;
  }[];
};

export type ConnectCheckDisableInput = {
  reason: string;
  expiresAt: string;
};

export type ConnectConnectorBuiltInRule = {
  id: string;
  kind: "built_in";
  provider: string;
  title: string;
  description: string;
  severity: string;
  eventTypes: string[];
  enabled: boolean;
};

export type ConnectConnectorCustomRule = {
  id: string;
  kind: "custom";
  name: string;
  severity: string;
  eventType: string;
  subjectField: string;
  predicate: unknown;
  enabled: boolean;
  updatedAt: string;
};

export type ConnectConnectorRulesResponse = {
  integrationId: string;
  provider: string;
  builtIn: ConnectConnectorBuiltInRule[];
  custom: ConnectConnectorCustomRule[];
};

export type ConnectCustomRuleInput = {
  name: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  eventType: string;
  subjectField: string;
  predicate: unknown;
  enabled: boolean;
};

export type ConnectSyncSummary = {
  sampleCount: number;
  eventsIngested: number;
  findingsOpened: number;
  sources: string[];
};

export type ConnectIntegrationSourceKind =
  | "all"
  | "google_reports"
  | "google_bigquery"
  | "google_directory"
  | "google_oauth"
  | "ingestion_queue";

export type ConnectIntegrationSourceSyncState = {
  sourceKind: ConnectIntegrationSourceKind | string;
  streamName: string;
  displayName: string;
  status: "pending" | "healthy" | "queued" | "running" | "error" | string;
  cursorTime: string | null;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lagSeconds: bigint;
  rowsSeen: bigint;
  rowsEnqueued: bigint;
  queueQueued: bigint;
  queueRunning: bigint;
  queueFailed: bigint;
  queueDeadLetter: bigint;
  queueSucceeded: bigint;
  syncNowSupported: boolean;
  backfillSupported: boolean;
  queueSource: string;
};

export type ConnectIntegrationSyncStatus = {
  integrationId: string;
  provider: ConnectProvider;
  generatedAt: string;
  sources: ConnectIntegrationSourceSyncState[];
};

export type ConnectIntegrationSourceSyncAction = {
  integrationId: string;
  sourceKind: ConnectIntegrationSourceKind | string;
  streamName: string;
  queued: boolean;
  message: string;
  requestedAt: string;
};

export type ConnectSiemDestination = {
  id: string;
  kind: string;
  name: string;
  endpointUrl: string | null;
  filePath: string | null;
  index: string | null;
  streams: string[];
  status: "ACTIVE" | "PAUSED" | "ERROR";
  lastDeliveryAt: string | null;
  lastError: string | null;
  deliveriesOk: number;
  deliveriesFail: number;
  createdAt: string;
};

export type ConnectSiemDestinationDefinition = {
  kind: string;
  name: string;
  vendor: string;
  description: string;
  category: "Cloud SIEM" | "Hosted Search" | "Observability" | "Graph" | "Generic";
  docsUrl: string;
  defaultStreams: string[];
  fields: {
    key: "endpointUrl" | "token" | "filePath" | "index";
    label: string;
    placeholder?: string;
    helper?: string;
    type: "text" | "password" | "url";
    required: boolean;
    secret: boolean;
  }[];
};

export type ConnectCreateSiemPayload = {
  kind: string;
  name: string;
  endpointUrl?: string;
  filePath?: string;
  index?: string;
  token?: string;
  streams: string[];
};

export type ConnectSiemTestResult = {
  destinationId: string;
  ok: boolean;
  message: string;
};

export type ConnectShadowItOauthApp = {
  id: string;
  provider: ConnectProvider | "";
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  containsSensitiveData: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  userCount: number;
  scopes: string[];
  integration: {
    id: string;
    provider: ConnectProvider | "";
    displayName: string;
  } | null;
};

export type ConnectShadowItOauthAppGrant = {
  id: string;
  userEmail: string;
  userExternalId: string | null;
  userDisplayName: string | null;
  scopes: string[];
  anonymous: boolean;
  nativeApp: boolean;
  lastObservedAt: string;
};

export type ConnectShadowItOauthAppDetail = {
  app: {
    id: string;
    name: string;
    externalId: string | null;
    provider: ConnectProvider | "";
  };
  grants: ConnectShadowItOauthAppGrant[];
};

export type ConnectSecurityAsset = {
  id: string;
  type: string;
  provider: ConnectProvider | null;
  name: string;
  summary: string | null;
  externalId: string | null;
  labels: string[];
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  exposureLevel: "INTERNAL" | "TRUSTED_EXTERNAL" | "PUBLIC";
  ownershipStatus: "ASSIGNED" | "UNASSIGNED" | "REVIEW_REQUIRED";
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt: string | null;
  createdAt: string;
  updatedAt: string;
  integration: {
    id: string;
    provider: ConnectProvider;
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

export type ConnectSecurityAssetsFilters = {
  type?: string;
  ownershipStatus?: string;
  integrationId?: string;
};

export type ConnectRiskException = {
  id: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  expiresAt: string | null;
  approvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  asset: {
    id: string;
    name: string;
    type: string;
  } | null;
  finding: {
    id: string;
    title: string;
    severity: ConnectFinding["severity"];
    status: ConnectFinding["status"];
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

export type ConnectTenantSettings = {
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

export type ConnectTenantSettingsUpdate = Partial<{
  name: string;
  notificationEmail: string;
  dataRetentionDays: number;
  criticalRiskThreshold: number;
  defaultSlaHours: number;
  autoResolveLowSeverity: boolean;
  enforceSsoOnly: boolean;
  webhookAlertUrl: string;
}>;

export type ConnectTenantMember = {
  id: string;
  email: string;
  displayName: string | null;
  isActive: boolean;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  isBreakGlass: boolean;
  role: ConnectTenantRole;
  authState: "ACTIVE" | "INVITED" | "PASSWORD_RESET_PENDING";
  pendingActionExpiresAt: string | null;
  createdAt: string;
};

export type ConnectInvitationResult = {
  delivery: "manual_link" | "email";
  url?: string;
  expiresAt: string;
};

export type ConnectAuditLogEntry = {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  actor: string;
  createdAt: string;
  metadata: Record<string, unknown> | null;
};

export type ConnectSecurityIdentity = {
  id: string;
  entityId: string;
  kind: "USER" | "SERVICE_ACCOUNT" | "BOT";
  name: string;
  email: string | null;
  provider: ConnectProvider | null;
  integration: {
    id: string;
    provider: ConnectProvider;
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

export type ConnectSecurityOverview = {
  summary: {
    privilegedIdentities: number;
    adminIdentitiesWithoutMfa: number;
    riskyOauthApps: number;
    exposedDataAssets: number;
    unownedAssets: number;
    activeExceptions: number;
    topBlastRadiusScore: number;
  };
  identities: ConnectSecurityIdentity[];
  graph: {
    nodes: {
      id: string;
      label: string;
      kind: string;
      riskScore: number;
      privileged: boolean;
      exposureLevel: string;
      criticality: string;
    }[];
    edges: {
      id: string;
      sourceId: string;
      targetId: string;
      relationshipType: string;
    }[];
  };
  oauthApps: ConnectSecurityAsset[];
  dataAssets: ConnectSecurityAsset[];
  attackPaths: {
    id: string;
    title: string;
    score: number;
    findingTitle: string;
    entryPoint: string;
    target: string;
    owner: string;
    exposureLevel: string;
    criticality: string;
    reason: string;
    path: string[];
  }[];
  ownershipGaps: ConnectSecurityAsset[];
  exceptions: ConnectRiskException[];
  domainWideDelegations: {
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
  }[];
};

export type ConnectEmailDomainHealth = {
  domain: string;
  providerSources: string[];
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  score: number;
  spfStatus: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  dkimStatus: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  dmarcStatus: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  lastCheckedAt: string;
  issueCount: number;
  failingIssueCount: number;
};

export type ConnectEmailDomainHealthIssue = {
  id: string;
  protocol: "SPF" | "DKIM" | "DMARC" | "MX" | "GENERAL";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  code: string;
  title: string;
  detail: string;
  recommendation: string;
};

export type ConnectEmailDomainDkimSelector = {
  selector: string;
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  keyBits: number;
  record: string;
};

export type ConnectEmailDomainHealthHistoryPoint = {
  checkedAt: string;
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
  score: number;
  issueCount: number;
};

export type ConnectEmailDomainHealthDetail = {
  domain: ConnectEmailDomainHealth;
  spfRecords: string[];
  spfPolicy: string;
  spfLookupCount: number;
  dmarcRecords: string[];
  dmarcPolicy: string;
  dmarcPct: number;
  dmarcRua: string[];
  mxRecords: string[];
  dkimSelectors: ConnectEmailDomainDkimSelector[];
  relatedRecords: string[];
  issues: ConnectEmailDomainHealthIssue[];
  history: ConnectEmailDomainHealthHistoryPoint[];
};

export type ConnectCreateSecurityAssetPayload = {
  integrationId?: string;
  ownerUserId?: string;
  businessOwnerUserId?: string;
  type: string;
  provider?: ConnectProvider;
  name: string;
  summary?: string;
  externalId?: string;
  labels: string[];
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  exposureLevel: "INTERNAL" | "TRUSTED_EXTERNAL" | "PUBLIC";
  ownershipStatus?: "ASSIGNED" | "UNASSIGNED" | "REVIEW_REQUIRED";
  containsSensitiveData: boolean;
  isPrivileged: boolean;
  riskScore: number;
  lastObservedAt?: string;
};

export type ConnectUpdateSecurityAssetPayload =
  Partial<ConnectCreateSecurityAssetPayload>;

export type ConnectCreateRiskExceptionPayload = {
  assetId?: string;
  findingId?: string;
  title: string;
  rationale: string;
  compensatingControls: string[];
  expiresAt?: string;
};

export type ConnectUpdateRiskExceptionPayload = Partial<{
  title: string;
  rationale: string;
  compensatingControls: string[];
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  expiresAt: string;
}>;

export type ConnectRemediationResult = {
  findingId: string;
  action: string;
  success: boolean;
  message: string;
  providerRequestId: string;
  effects: string[];
};

const transport = createConnectTransport({
  baseUrl: CONNECT_BASE_URL,
  fetch(input, init) {
    // ConnectRPC calls use the same HttpOnly session cookie as the compatibility
    // API, and no-store avoids showing stale security posture after mutations.
    return fetch(input, {
      ...init,
      credentials: "include",
      cache: "no-store"
    });
  }
});

const client = createClient(AperioService, transport);

function parseEvidence(evidenceJson: string) {
  if (!evidenceJson) {
    return undefined;
  }
  const parsed = JSON.parse(evidenceJson) as unknown;
  // Evidence is an open-ended JSON object produced by provider-specific
  // detectors. Keep it typed as a record for UI rendering without coupling this
  // bridge to every detector schema.
  return parsed && typeof parsed === "object"
    ? (parsed as Record<string, unknown>)
    : undefined;
}

function safeParse(json: string): unknown {
  if (!json) {
    return {};
  }
  try {
    return JSON.parse(json) as unknown;
  } catch {
    // A malformed predicate cannot block the UI from listing the rule;
    // returning {} keeps the editor usable so the operator can repair it.
    return {};
  }
}

function parseMetadata(metadataJson: string): Record<string, unknown> | null {
  if (!metadataJson) {
    return null;
  }
  const parsed = JSON.parse(metadataJson) as unknown;
  return parsed && typeof parsed === "object"
    ? (parsed as Record<string, unknown>)
    : null;
}

function authSessionFromProto(session: ProtoAuthSession): ConnectAuthSession {
  return {
    user: {
      id: session.user?.id ?? "",
      email: session.user?.email ?? "",
      displayName: session.user?.displayName || null,
      mfaEnabled: session.user?.mfaEnabled ?? false,
      role: (session.user?.role ?? "VIEWER") as ConnectTenantRole
    },
    organization: {
      id: session.organization?.id ?? "",
      name: session.organization?.name ?? "",
      slug: session.organization?.slug ?? ""
    }
  };
}

function workspaceMembershipFromProto(
  workspace: ProtoWorkspaceMembership
): ConnectWorkspaceMembership {
  return {
    id: workspace.id,
    name: workspace.name,
    slug: workspace.slug,
    role: workspace.role as ConnectTenantRole,
    current: workspace.current
  };
}

function passwordResetResultFromProto(
  result: ProtoPasswordResetResult
): ConnectPasswordResetResult {
  return {
    accepted: result.accepted,
    delivery: result.delivery
      ? (result.delivery as ConnectPasswordResetResult["delivery"])
      : undefined,
    resetUrl: result.resetUrl || undefined,
    expiresAt: result.expiresAt || undefined,
    organizationName: result.organizationName || undefined
  };
}

function mfaEnrollmentFromProto(
  enrollment: ProtoMfaEnrollment
): ConnectMfaEnrollment {
  return {
    secret: enrollment.secret,
    otpauthUrl: enrollment.otpauthUrl
  };
}

function findingFromProto(finding: ProtoFinding): ConnectFinding {
  // Generated proto3 strings default to "", while the web API contract uses
  // null for absent optional fields. Normalize at the edge so components do not
  // need to know protobuf defaulting rules.
  return {
    id: finding.id,
    assetId: finding.assetId || null,
    title: finding.title,
    description: finding.description,
    severity: finding.severity as ConnectFinding["severity"],
    status: finding.status as ConnectFinding["status"],
    riskScore: finding.riskScore,
    remediationSteps: finding.remediationSteps,
    tags: finding.tags ?? [],
    evidence: parseEvidence(finding.evidenceJson),
    detectedAt: finding.detectedAt,
    resolvedAt: finding.resolvedAt || null,
    integration: {
      id: finding.integration?.id,
      provider: (finding.integration?.provider ??
        "") as ConnectFinding["integration"]["provider"],
      displayName: finding.integration?.displayName ?? ""
    }
  };
}

function recordFromJson(json: string): Record<string, unknown> {
  const parsed = safeParse(json);
  return recordFromUnknown(parsed) ?? {};
}

function recordFromUnknown(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringFromRecord(
  record: Record<string, unknown>,
  key: string
): string | null {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function numberFromRecord(
  record: Record<string, unknown>,
  key: string
): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function recordsFromUnknown(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          Boolean(item) && typeof item === "object" && !Array.isArray(item)
      )
    : [];
}

function stringsFromUnknown(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function cerebroEntityRefFromRecord(
  record: Record<string, unknown>
): ConnectCerebroEntityRef | null {
  const urn = stringFromRecord(record, "urn");
  const type = stringFromRecord(record, "type");
  const label = stringFromRecord(record, "label");
  if (!urn || !type || !label) return null;
  return {
    urn,
    type,
    label,
    provider: stringFromRecord(record, "provider")
  };
}

function cerebroGraphSignalsFromUnknown(
  value: unknown
): ConnectCerebroGraphSignal[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === "string" && item.trim()) {
      return [{ label: item }];
    }
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return [];
    }
    const record = item as Record<string, unknown>;
    const label = stringFromRecord(record, "label");
    if (!label) return [];
    return [
      {
        label,
        predicate: stringFromRecord(record, "predicate"),
        confidence: numberFromRecord(record, "confidence"),
        entityUrn: stringFromRecord(record, "entityUrn"),
        evidence: stringFromRecord(record, "evidence")
      }
    ];
  });
}

function cerebroGraphPathsFromUnknown(
  value: unknown
): ConnectCerebroGraphPath[] {
  return recordsFromUnknown(value).flatMap((record) => {
    const id = stringFromRecord(record, "id");
    const title = stringFromRecord(record, "title");
    if (!id || !title) return [];
    return [
      {
        id,
        title,
        risk: stringFromRecord(record, "risk"),
        nodes: recordsFromUnknown(record.nodes)
          .map(cerebroEntityRefFromRecord)
          .filter((node): node is ConnectCerebroEntityRef => Boolean(node))
      }
    ];
  });
}

function cerebroClaimSummariesFromUnknown(
  value: unknown
): ConnectCerebroClaimSummary[] {
  return recordsFromUnknown(value).flatMap((record) => {
    const claimType = stringFromRecord(record, "claimType");
    const predicate = stringFromRecord(record, "predicate");
    const subjectUrn = stringFromRecord(record, "subjectUrn");
    if (!claimType || !predicate || !subjectUrn) return [];
    return [
      {
        claimType,
        predicate,
        subjectUrn,
        objectUrn: stringFromRecord(record, "objectUrn"),
        sourceEvent: stringFromRecord(record, "sourceEvent")
      }
    ];
  });
}

function cerebroMCPContextFromUnknown(
  value: unknown
): ConnectCerebroMCPContext | null {
  const record = recordFromUnknown(value);
  if (!record) return null;
  const server = stringFromRecord(record, "server");
  const resourceUri = stringFromRecord(record, "resourceUri");
  const mimeType = stringFromRecord(record, "mimeType");
  const tools = stringsFromUnknown(record.tools);
  if (!server && !resourceUri && !mimeType && tools.length === 0) return null;
  return {
    server,
    resourceUri,
    mimeType,
    tools
  };
}

function cerebroContextFromJson(json: string): ConnectCerebroIncidentContext {
  const record = recordFromJson(json);
  return {
    source: stringFromRecord(record, "source") ?? "cerebro",
    mode: stringFromRecord(record, "mode") ?? "context-only",
    sourceRuntimeId: stringFromRecord(record, "sourceRuntimeId"),
    findingContract: stringFromRecord(record, "findingContract"),
    claimCount: numberFromRecord(record, "claimCount"),
    lastClaimFanoutAt: stringFromRecord(record, "lastClaimFanoutAt"),
    graphSignals: cerebroGraphSignalsFromUnknown(record.graphSignals),
    entities: recordsFromUnknown(record.entities)
      .map(cerebroEntityRefFromRecord)
      .filter((entity): entity is ConnectCerebroEntityRef => Boolean(entity)),
    graphPaths: cerebroGraphPathsFromUnknown(record.graphPaths),
    claimSummaries: cerebroClaimSummariesFromUnknown(record.claimSummaries),
    responseHints: stringsFromUnknown(record.responseHints),
    mcp: cerebroMCPContextFromUnknown(record.mcp)
  };
}

function securityPrincipalFromProto(
  principal?: ProtoSecurityPrincipal | null
): ConnectSecurityPrincipal | null {
  if (!principal || !principal.id) {
    return null;
  }
  return {
    id: principal.id,
    email: principal.email,
    displayName: principal.displayName || null
  };
}

function saasIncidentFromProto(
  incident: ProtoSaasIncident
): ConnectSaasIncident {
  return {
    id: incident.id,
    title: incident.title,
    summary: incident.summary,
    severity: incident.severity as ConnectSaasIncident["severity"],
    status: incident.status as ConnectSaasIncidentStatus,
    confidenceScore: incident.confidenceScore,
    ownerTeam: incident.ownerTeam || null,
    assignee: securityPrincipalFromProto(incident.assignee),
    firstDetectedAt: incident.firstDetectedAt,
    lastActivityAt: incident.lastActivityAt,
    slaDueAt: incident.slaDueAt || null,
    resolvedAt: incident.resolvedAt || null,
    cerebroContext: cerebroContextFromJson(incident.cerebroContextJson),
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
    findingCount: incident.findingCount,
    openFindingCount: incident.openFindingCount,
    responseActionCount: incident.responseActionCount,
    completedResponseActionCount: incident.completedResponseActionCount
  };
}

function saasIncidentMetricsFromProto(
  metrics?: ProtoSaasIncidentMetrics
): ConnectSaasIncidentMetrics {
  return {
    open: metrics?.open ?? 0,
    investigating: metrics?.investigating ?? 0,
    contained: metrics?.contained ?? 0,
    resolved: metrics?.resolved ?? 0,
    criticalOpen: metrics?.criticalOpen ?? 0,
    responseActionsPending: metrics?.responseActionsPending ?? 0
  };
}

function saasIncidentTimelineEventFromProto(
  event: ProtoSaasIncidentTimelineEvent
): ConnectSaasIncidentTimelineEvent {
  return {
    id: event.id,
    incidentId: event.incidentId,
    findingId: event.findingId || null,
    responseActionId: event.responseActionId || null,
    kind: event.kind as ConnectSaasIncidentTimelineEvent["kind"],
    title: event.title,
    description: event.description,
    actor: event.actor || null,
    source: event.source,
    evidence: recordFromJson(event.evidenceJson),
    occurredAt: event.occurredAt,
    createdAt: event.createdAt
  };
}

function saasResponseActionFromProto(
  action: ProtoSaasResponseAction
): ConnectSaasResponseAction {
  return {
    id: action.id,
    incidentId: action.incidentId,
    findingId: action.findingId || null,
    action: action.action as ConnectSaasResponseActionKind,
    provider: action.provider ? (action.provider as ConnectProvider) : null,
    targetType: action.targetType,
    targetIdentifier: action.targetIdentifier,
    status: action.status as ConnectSaasResponseActionStatus,
    approvalRequired: action.approvalRequired,
    rationale: action.rationale,
    approvedBy: securityPrincipalFromProto(action.approvedBy),
    approvedAt: action.approvedAt || null,
    executedAt: action.executedAt || null,
    errorMessage: action.errorMessage || null,
    result: recordFromJson(action.resultJson),
    createdAt: action.createdAt,
    updatedAt: action.updatedAt
  };
}

function saasIncidentDetailFromProto(
  detail: ProtoSaasIncidentDetail
): ConnectSaasIncidentDetail {
  if (!detail.incident) {
    throw new Error("Incident not found");
  }
  return {
    incident: saasIncidentFromProto(detail.incident),
    findings: detail.findings.map(findingFromProto),
    timeline: detail.timeline.map(saasIncidentTimelineEventFromProto),
    responseActions: detail.responseActions.map(saasResponseActionFromProto)
  };
}

function integrationOAuthClientFromProto(
  proto: { provider: string; clientId: string; redirectUri: string; configured: boolean; defaultRedirectUri: string; updatedAt: string; source: string } | undefined,
  fallbackProvider: "GOOGLE_WORKSPACE"
): ConnectIntegrationOAuthClient {
  if (!proto) {
    return {
      provider: fallbackProvider,
      clientId: "",
      redirectUri: "",
      defaultRedirectUri: "",
      configured: false,
      source: "",
      updatedAt: null
    };
  }
  const source =
    proto.source === "tenant" || proto.source === "env" ? proto.source : "";
  return {
    provider: (proto.provider || fallbackProvider) as "GOOGLE_WORKSPACE",
    clientId: proto.clientId,
    redirectUri: proto.redirectUri,
    defaultRedirectUri: proto.defaultRedirectUri,
    configured: proto.configured,
    source,
    updatedAt: proto.updatedAt || null
  };
}

function integrationFromProto(
  integration: ProtoIntegrationConnection
): ConnectIntegrationConnection {
  return {
    id: integration.id,
    provider: integration.provider as ConnectProvider,
    displayName: integration.displayName,
    externalAccountId: integration.externalAccountId,
    status: integration.status as ConnectIntegrationConnection["status"],
    mode: integration.mode as ConnectIntegrationConnection["mode"],
    scopes: integration.scopes,
    disabledChecks: integration.disabledChecks,
    googleMailboxScanEnabled: integration.googleMailboxScanEnabled,
    googleMailboxScanClientEmail:
      integration.googleMailboxScanClientEmail || null,
    lastSyncAt: integration.lastSyncAt || null,
    createdAt: integration.createdAt
  };
}

function connectorDefinitionFromProto(
  definition: ProtoConnectorDefinition
): ConnectConnectorDefinition {
  // Catalog definitions are authored in Go and rendered directly by React; casts
  // here preserve the narrower UI unions while the proto contract stays stringly.
  return {
    provider: definition.provider as ConnectProvider,
    name: definition.name,
    category: definition.category,
    availability: definition.availability as ConnectConnectorDefinition["availability"],
    readinessNote: definition.readinessNote || undefined,
    description: definition.description,
    readScopes: definition.readScopes,
    remediationScopes: definition.remediationScopes,
    remediationActions: definition.remediationActions.map((action) => ({
      key: action.key,
      label: action.label,
      description: action.description,
      severityHint: action.severityHint as "CRITICAL" | "HIGH" | "MEDIUM"
    })),
    findingChecks: definition.findingChecks.map((check) => ({
      key: check.key,
      title: check.title,
      description: check.description,
      severityHint: check.severityHint as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      defaultEnabled: check.defaultEnabled
    })),
    docsUrl: definition.docsUrl,
    fields: definition.fields.map((field) => ({
      key: field.key,
      label: field.label,
      placeholder: field.placeholder || undefined,
      helper: field.helper || undefined,
      type: field.type as "text" | "password" | "url",
      required: field.required,
      secret: field.secret
    }))
  };
}

function googleMailboxScanConfigFromProto(
  config: ProtoGoogleMailboxScanConfig
): ConnectGoogleMailboxScanConfig {
  return {
    enabled: config.enabled,
    serviceAccountClientEmail: config.serviceAccountClientEmail || null
  };
}

function googleWorkspaceBigQueryConfigFromProto(
  config: ProtoGoogleWorkspaceBigQueryConfig
): ConnectGoogleWorkspaceBigQueryConfig {
  const accessMode =
    config.accessMode === "views" || config.accessMode === "dataset"
      ? config.accessMode
      : "";
  return {
    enabled: config.enabled,
    projectId: config.projectId,
    rawDatasetId: config.rawDatasetId,
    datasetId: config.datasetId,
    location: config.location,
    serviceAccountEmail: config.serviceAccountEmail,
    workloadIdentityProvider: config.workloadIdentityProvider,
    accessMode,
    updatedAt: config.updatedAt || null
  };
}

function googleWorkspaceBigQueryValidationFromProto(
  validation: ProtoGoogleWorkspaceBigQueryValidation
): ConnectGoogleWorkspaceBigQueryValidation {
  return {
    integrationId: validation.integrationId,
    ok: validation.ok,
    message: validation.message,
    projectId: validation.projectId,
    datasetId: validation.datasetId,
    activityTable: validation.activityTable,
    tableFound: validation.tableFound,
    sampleRows: validation.sampleRows,
    estimatedBytes: validation.estimatedBytes,
    runtimeTokenPresent: validation.runtimeTokenPresent
  };
}

function integrationSourceSyncStateFromProto(
  state: ProtoIntegrationSourceSyncState
): ConnectIntegrationSourceSyncState {
  return {
    sourceKind: state.sourceKind,
    streamName: state.streamName,
    displayName: state.displayName,
    status: state.status,
    cursorTime: state.cursorTime || null,
    lastAttemptAt: state.lastAttemptAt || null,
    lastSuccessAt: state.lastSuccessAt || null,
    lastError: state.lastError || null,
    lagSeconds: state.lagSeconds,
    rowsSeen: state.rowsSeen,
    rowsEnqueued: state.rowsEnqueued,
    queueQueued: state.queueQueued,
    queueRunning: state.queueRunning,
    queueFailed: state.queueFailed,
    queueDeadLetter: state.queueDeadLetter,
    queueSucceeded: state.queueSucceeded,
    syncNowSupported: state.syncNowSupported,
    backfillSupported: state.backfillSupported,
    queueSource: state.queueSource
  };
}

function integrationSyncStatusFromProto(
  status: ProtoIntegrationSyncStatus
): ConnectIntegrationSyncStatus {
  return {
    integrationId: status.integrationId,
    provider: status.provider as ConnectProvider,
    generatedAt: status.generatedAt,
    sources: status.sources.map(integrationSourceSyncStateFromProto)
  };
}

function integrationSourceSyncActionFromProto(
  action: ProtoIntegrationSourceSyncAction
): ConnectIntegrationSourceSyncAction {
  return {
    integrationId: action.integrationId,
    sourceKind: action.sourceKind,
    streamName: action.streamName,
    queued: action.queued,
    message: action.message,
    requestedAt: action.requestedAt
  };
}

function integrationCheckStateFromProto(
  state: ProtoIntegrationCheckState
): ConnectIntegrationCheckState {
  return {
    integrationId: state.integrationId,
    disabledChecks: state.disabledChecks,
    checks: state.checks.map((check) => ({
      key: check.key,
      title: check.title,
      description: check.description,
      severityHint: check.severityHint as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      defaultEnabled: check.defaultEnabled,
      enabled: check.enabled
    }))
  };
}

function siemDestinationFromProto(
  destination: ProtoSiemDestination
): ConnectSiemDestination {
  return {
    id: destination.id,
    kind: destination.kind,
    name: destination.name,
    endpointUrl: destination.endpointUrl || null,
    filePath: destination.filePath || null,
    index: destination.index || null,
    streams: destination.streams,
    status: destination.status as ConnectSiemDestination["status"],
    lastDeliveryAt: destination.lastDeliveryAt || null,
    lastError: destination.lastError || null,
    deliveriesOk: destination.deliveriesOk,
    deliveriesFail: destination.deliveriesFail,
    createdAt: destination.createdAt
  };
}

function siemDefinitionFromProto(
  definition: ProtoSiemDestinationDefinition
): ConnectSiemDestinationDefinition {
  return {
    kind: definition.kind,
    name: definition.name,
    vendor: definition.vendor,
    description: definition.description,
    category: definition.category as ConnectSiemDestinationDefinition["category"],
    docsUrl: definition.docsUrl,
    defaultStreams: definition.defaultStreams,
    fields: definition.fields.map((field) => ({
      key: field.key as "endpointUrl" | "token" | "filePath" | "index",
      label: field.label,
      placeholder: field.placeholder || undefined,
      helper: field.helper || undefined,
      type: field.type as "text" | "password" | "url",
      required: field.required,
      secret: field.secret
    }))
  };
}

function remediationResultFromProto(
  result: ProtoRemediationResult
): ConnectRemediationResult {
  return {
    findingId: result.findingId,
    action: result.action,
    success: result.success,
    message: result.message,
    providerRequestId: result.providerRequestId,
    effects: result.effects
  };
}

function shadowItOauthAppFromProto(
  app: ProtoShadowItOauthApp
): ConnectShadowItOauthApp {
  return {
    id: app.id,
    provider: app.provider as ConnectProvider | "",
    name: app.name,
    summary: app.summary || null,
    externalId: app.externalId || null,
    labels: app.labels,
    criticality: app.criticality as ConnectShadowItOauthApp["criticality"],
    containsSensitiveData: app.containsSensitiveData,
    riskScore: app.riskScore,
    lastObservedAt: app.lastObservedAt || null,
    userCount: app.userCount,
    scopes: app.scopes,
    integration: app.integration
      ? {
          id: app.integration.id,
          provider: app.integration.provider as ConnectProvider | "",
          displayName: app.integration.displayName
        }
      : null
  };
}

function shadowItGrantFromProto(
  grant: ProtoShadowItOauthAppGrant
): ConnectShadowItOauthAppGrant {
  return {
    id: grant.id,
    userEmail: grant.userEmail,
    userExternalId: grant.userExternalId || null,
    userDisplayName: grant.userDisplayName || null,
    scopes: grant.scopes,
    anonymous: grant.anonymous,
    nativeApp: grant.nativeApp,
    lastObservedAt: grant.lastObservedAt
  };
}

function securityAssetFromProto(asset: ProtoSecurityAsset): ConnectSecurityAsset {
  // Asset ownership and integration refs are optional nested messages. Collapse
  // missing messages and empty proto strings into nulls for stable React checks.
  return {
    id: asset.id,
    type: asset.type,
    provider: asset.provider ? (asset.provider as ConnectProvider) : null,
    name: asset.name,
    summary: asset.summary || null,
    externalId: asset.externalId || null,
    labels: asset.labels,
    criticality: asset.criticality as ConnectSecurityAsset["criticality"],
    exposureLevel: asset.exposureLevel as ConnectSecurityAsset["exposureLevel"],
    ownershipStatus:
      asset.ownershipStatus as ConnectSecurityAsset["ownershipStatus"],
    containsSensitiveData: asset.containsSensitiveData,
    isPrivileged: asset.isPrivileged,
    riskScore: asset.riskScore,
    lastObservedAt: asset.lastObservedAt || null,
    createdAt: asset.createdAt,
    updatedAt: asset.updatedAt,
    integration: asset.integration
      ? {
          id: asset.integration.id,
          provider: asset.integration.provider as ConnectProvider,
          displayName: asset.integration.displayName
        }
      : null,
    owner: asset.owner
      ? {
          id: asset.owner.id,
          email: asset.owner.email,
          displayName: asset.owner.displayName || null
        }
      : null,
    businessOwner: asset.businessOwner
      ? {
          id: asset.businessOwner.id,
          email: asset.businessOwner.email,
          displayName: asset.businessOwner.displayName || null
        }
      : null,
    openFindingCount: asset.openFindingCount,
    activeExceptionCount: asset.activeExceptionCount
  };
}

function riskExceptionFromProto(
  exception: ProtoRiskException
): ConnectRiskException {
  return {
    id: exception.id,
    title: exception.title,
    rationale: exception.rationale,
    compensatingControls: exception.compensatingControls,
    status: exception.status as ConnectRiskException["status"],
    expiresAt: exception.expiresAt || null,
    approvedAt: exception.approvedAt || null,
    createdAt: exception.createdAt,
    updatedAt: exception.updatedAt,
    asset: exception.asset
      ? {
          id: exception.asset.id,
          name: exception.asset.name,
          type: exception.asset.type
        }
      : null,
    finding: exception.finding
      ? {
          id: exception.finding.id,
          title: exception.finding.title,
          severity: exception.finding.severity as ConnectFinding["severity"],
          status: exception.finding.status as ConnectFinding["status"]
        }
      : null,
    createdBy: exception.createdBy
      ? {
          id: exception.createdBy.id,
          email: exception.createdBy.email,
          displayName: exception.createdBy.displayName || null
        }
      : null,
    approvedBy: exception.approvedBy
      ? {
          id: exception.approvedBy.id,
          email: exception.approvedBy.email,
          displayName: exception.approvedBy.displayName || null
        }
      : null
  };
}

function tenantSettingsFromProto(
  settings: ProtoTenantSettings
): ConnectTenantSettings {
  return {
    id: settings.id,
    name: settings.name,
    slug: settings.slug,
    notificationEmail: settings.notificationEmail || null,
    dataRetentionDays: settings.dataRetentionDays,
    criticalRiskThreshold: settings.criticalRiskThreshold,
    defaultSlaHours: settings.defaultSlaHours,
    autoResolveLowSeverity: settings.autoResolveLowSeverity,
    enforceSsoOnly: settings.enforceSsoOnly,
    webhookAlertUrl: settings.webhookAlertUrl || null,
    createdAt: settings.createdAt,
    updatedAt: settings.updatedAt
  };
}

function tenantMemberFromProto(member: ProtoTenantMember): ConnectTenantMember {
  return {
    id: member.id,
    email: member.email,
    displayName: member.displayName || null,
    isActive: member.isActive,
    mfaEnabled: member.mfaEnabled,
    lastLoginAt: member.lastLoginAt || null,
    isBreakGlass: member.isBreakGlass,
    role: member.role as ConnectTenantRole,
    authState: member.authState as ConnectTenantMember["authState"],
    pendingActionExpiresAt: member.pendingActionExpiresAt || null,
    createdAt: member.createdAt
  };
}

function invitationResultFromProto(
  invitation: ProtoInvitationResult
): ConnectInvitationResult {
  return {
    delivery: invitation.delivery as ConnectInvitationResult["delivery"],
    url: invitation.url || undefined,
    expiresAt: invitation.expiresAt
  };
}

function auditLogFromProto(log: ProtoAuditLogEntry): ConnectAuditLogEntry {
  return {
    id: log.id,
    action: log.action,
    targetType: log.targetType,
    targetId: log.targetId,
    actor: log.actor,
    createdAt: log.createdAt,
    metadata: parseMetadata(log.metadataJson)
  };
}

function securityIdentityFromProto(
  identity: ProtoSecurityIdentity
): ConnectSecurityIdentity {
  return {
    id: identity.id,
    entityId: identity.entityId,
    kind: identity.kind as ConnectSecurityIdentity["kind"],
    name: identity.name,
    email: identity.email || null,
    provider: identity.provider ? (identity.provider as ConnectProvider) : null,
    integration: identity.integration
      ? {
          id: identity.integration.id,
          provider: identity.integration.provider as ConnectProvider,
          displayName: identity.integration.displayName
        }
      : null,
    role: identity.role,
    privileged: identity.privileged,
    mfaEnabled: identity.mfaEnabledState ?? (identity.mfaEnabled ? true : null),
    status: identity.status as ConnectSecurityIdentity["status"],
    isExternal: identity.isExternal,
    lastObservedAt: identity.lastObservedAt || null,
    linkedAssetCount: identity.linkedAssetCount,
    riskScore: identity.riskScore
  };
}

function securityGraphNodeFromProto(node: ProtoSecurityGraphNode) {
  return {
    id: node.id,
    label: node.label,
    kind: node.kind,
    riskScore: node.riskScore,
    privileged: node.privileged,
    exposureLevel: node.exposureLevel,
    criticality: node.criticality
  };
}

function securityGraphEdgeFromProto(edge: ProtoSecurityGraphEdge) {
  return {
    id: edge.id,
    sourceId: edge.sourceId,
    targetId: edge.targetId,
    relationshipType: edge.relationshipType
  };
}

function securityGraphFromProto(graph?: ProtoSecurityGraph | null) {
  return {
    nodes: graph?.nodes.map(securityGraphNodeFromProto) ?? [],
    edges: graph?.edges.map(securityGraphEdgeFromProto) ?? []
  };
}

function securityOverviewFromProto(
  overview: ProtoSecurityOverview
): ConnectSecurityOverview {
  return {
    summary: {
      privilegedIdentities: overview.summary?.privilegedIdentities ?? 0,
      adminIdentitiesWithoutMfa:
        overview.summary?.adminIdentitiesWithoutMfa ?? 0,
      riskyOauthApps: overview.summary?.riskyOauthApps ?? 0,
      exposedDataAssets: overview.summary?.exposedDataAssets ?? 0,
      unownedAssets: overview.summary?.unownedAssets ?? 0,
      activeExceptions: overview.summary?.activeExceptions ?? 0,
      topBlastRadiusScore: overview.summary?.topBlastRadiusScore ?? 0
    },
    identities: overview.identities.map(securityIdentityFromProto),
    graph: securityGraphFromProto(overview.graph),
    oauthApps: overview.oauthApps.map(securityAssetFromProto),
    dataAssets: overview.dataAssets.map(securityAssetFromProto),
    attackPaths: overview.attackPaths.map((path) => ({
      id: path.id,
      title: path.title,
      score: path.score,
      findingTitle: path.findingTitle,
      entryPoint: path.entryPoint,
      target: path.target,
      owner: path.owner,
      exposureLevel: path.exposureLevel,
      criticality: path.criticality,
      reason: path.reason,
      path: path.path
    })),
    ownershipGaps: overview.ownershipGaps.map(securityAssetFromProto),
    exceptions: overview.exceptions.map(riskExceptionFromProto),
    domainWideDelegations: overview.domainWideDelegations.map((delegation) => ({
      integrationId: delegation.integrationId,
      provider: delegation.provider as "GOOGLE_WORKSPACE",
      displayName: delegation.displayName,
      workspaceDomain: delegation.workspaceDomain,
      serviceAccountClientEmail:
        delegation.serviceAccountClientEmail || null,
      scopes: delegation.scopes,
      status: delegation.status as "ENABLED" | "NOT_CONFIGURED",
      integrationStatus: delegation.integrationStatus as
        | "CONNECTED"
        | "DISABLED"
        | "ERROR",
      mode: delegation.mode as "READ_ONLY" | "REMEDIATION",
      openMailboxFindings: delegation.openMailboxFindings,
      lastSyncAt: delegation.lastSyncAt || null,
      configuredAt: delegation.configuredAt
    }))
  };
}

function emailDomainHealthFromProto(
  domain?: ProtoEmailDomainHealth | null
): ConnectEmailDomainHealth {
  return {
    domain: domain?.domain ?? "",
    providerSources: domain?.providerSources ?? [],
    status: (domain?.status ?? "UNKNOWN") as ConnectEmailDomainHealth["status"],
    score: domain?.score ?? 0,
    spfStatus: (domain?.spfStatus ?? "UNKNOWN") as ConnectEmailDomainHealth["spfStatus"],
    dkimStatus: (domain?.dkimStatus ?? "UNKNOWN") as ConnectEmailDomainHealth["dkimStatus"],
    dmarcStatus: (domain?.dmarcStatus ?? "UNKNOWN") as ConnectEmailDomainHealth["dmarcStatus"],
    lastCheckedAt: domain?.lastCheckedAt ?? "",
    issueCount: domain?.issueCount ?? 0,
    failingIssueCount: domain?.failingIssueCount ?? 0
  };
}

function emailDomainIssueFromProto(
  issue: ProtoEmailDomainHealthIssue
): ConnectEmailDomainHealthIssue {
  return {
    id: issue.id,
    protocol: issue.protocol as ConnectEmailDomainHealthIssue["protocol"],
    severity: issue.severity as ConnectEmailDomainHealthIssue["severity"],
    code: issue.code,
    title: issue.title,
    detail: issue.detail,
    recommendation: issue.recommendation
  };
}

function emailDomainDkimSelectorFromProto(
  selector: ProtoEmailDomainDkimSelector
): ConnectEmailDomainDkimSelector {
  return {
    selector: selector.selector,
    status: selector.status as ConnectEmailDomainDkimSelector["status"],
    keyBits: selector.keyBits,
    record: selector.record
  };
}

function emailDomainHistoryFromProto(
  point: ProtoEmailDomainHealthHistoryPoint
): ConnectEmailDomainHealthHistoryPoint {
  return {
    checkedAt: point.checkedAt,
    status: point.status as ConnectEmailDomainHealthHistoryPoint["status"],
    score: point.score,
    issueCount: point.issueCount
  };
}

function emailDomainHealthDetailFromProto(
  detail: ProtoEmailDomainHealthDetail
): ConnectEmailDomainHealthDetail {
  return {
    domain: emailDomainHealthFromProto(detail.domain),
    spfRecords: detail.spfRecords,
    spfPolicy: detail.spfPolicy,
    spfLookupCount: detail.spfLookupCount,
    dmarcRecords: detail.dmarcRecords,
    dmarcPolicy: detail.dmarcPolicy,
    dmarcPct: detail.dmarcPct,
    dmarcRua: detail.dmarcRua,
    mxRecords: detail.mxRecords,
    dkimSelectors: detail.dkimSelectors.map(emailDomainDkimSelectorFromProto),
    relatedRecords: detail.relatedRecords,
    issues: detail.issues.map(emailDomainIssueFromProto),
    history: detail.history.map(emailDomainHistoryFromProto)
  };
}

export const aperioConnectClient = {
  async signup(payload: {
    organizationName: string;
    organizationSlug: string;
    notificationEmail?: string;
    ownerEmail: string;
    ownerDisplayName?: string;
    password: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.signup({
      organizationName: payload.organizationName,
      organizationSlug: payload.organizationSlug,
      notificationEmail: payload.notificationEmail ?? "",
      ownerEmail: payload.ownerEmail,
      ownerDisplayName: payload.ownerDisplayName ?? "",
      password: payload.password
    });
    if (!response.data) {
      throw new Error("Signup failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async login(payload: {
    organizationSlug: string;
    email: string;
    password: string;
    totpCode?: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.login({
      organizationSlug: payload.organizationSlug,
      email: payload.email,
      password: payload.password,
      totpCode: payload.totpCode ?? ""
    });
    if (!response.data) {
      throw new Error("Login failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async getCurrentSession(): Promise<{ data: ConnectAuthSession }> {
    const response = await client.getCurrentSession({});
    if (!response.data) {
      throw new Error("Session unavailable");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async logoutCurrentSession(): Promise<{ data: { ok: boolean } }> {
    const response = await client.logoutCurrentSession({});
    return { data: { ok: response.data?.ok ?? true } };
  },
  async listWorkspaces(): Promise<{ data: ConnectWorkspaceMembership[] }> {
    const response = await client.listWorkspaces({});
    return { data: response.data.map(workspaceMembershipFromProto) };
  },
  async switchWorkspace(payload: {
    organizationSlug: string;
    password: string;
    totpCode?: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.switchWorkspace({
      organizationSlug: payload.organizationSlug,
      password: payload.password,
      totpCode: payload.totpCode ?? ""
    });
    if (!response.data) {
      throw new Error("Workspace switch failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async requestPasswordReset(payload: {
    organizationSlug: string;
    email: string;
  }): Promise<{ data: ConnectPasswordResetResult }> {
    const response = await client.requestPasswordReset({
      organizationSlug: payload.organizationSlug,
      email: payload.email
    });
    if (!response.data) {
      throw new Error("Password reset request failed");
    }
    return { data: passwordResetResultFromProto(response.data) };
  },
  async resetPassword(payload: {
    token: string;
    password: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.resetPassword({
      token: payload.token,
      password: payload.password
    });
    if (!response.data) {
      throw new Error("Password reset failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async acceptInvite(payload: {
    token: string;
    displayName?: string;
    password: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.acceptInvite({
      token: payload.token,
      displayName: payload.displayName ?? "",
      password: payload.password
    });
    if (!response.data) {
      throw new Error("Invite accept failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async beginMfaEnrollment(): Promise<{ data: ConnectMfaEnrollment }> {
    const response = await client.beginMfaEnrollment({});
    if (!response.data) {
      throw new Error("MFA setup failed");
    }
    return { data: mfaEnrollmentFromProto(response.data) };
  },
  async enableMfa(code: string): Promise<{ data: ConnectAuthSession }> {
    const response = await client.enableMfa({ code });
    if (!response.data) {
      throw new Error("MFA enable failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  async disableMfa(payload: {
    password: string;
    code?: string;
  }): Promise<{ data: ConnectAuthSession }> {
    const response = await client.disableMfa({
      password: payload.password,
      code: payload.code ?? ""
    });
    if (!response.data) {
      throw new Error("MFA disable failed");
    }
    return { data: authSessionFromProto(response.data) };
  },
  checkHealth() {
    return client.checkHealth({});
  },
  async getDashboardMetrics(): Promise<{ data: ConnectDashboardMetrics }> {
    const response = await client.getDashboardMetrics({});
    return {
      data: response.data ?? {
        totalRiskScore: 0,
        openCriticalFindings: 0,
        connectedApps: 0,
        eventIngestionRate: 0
      }
    };
  },
  async listFindings(filters?: ConnectFindingsFilters): Promise<{
    data: ConnectFinding[];
    pageInfo: { total: number; nextCursor: string | null };
  }> {
    // Default to OPEN findings to match the security triage view; callers that
    // need full history must explicitly pass status: "ALL".
    const response = await client.listFindings({
      severity: filters?.severity ?? "",
      status: filters?.status === "ALL" ? "ALL" : filters?.status ?? "OPEN",
      provider: filters?.provider ?? "",
      integrationId: filters?.integrationId ?? "",
      limit: filters?.limit ?? 50,
      cursor: filters?.cursor ?? ""
    });
    return {
      data: response.data.map(findingFromProto),
      pageInfo: {
        total: response.pageInfo?.total ?? 0,
        nextCursor: response.pageInfo?.nextCursor || null
      }
    };
  },
  async getFinding(id: string): Promise<{ data: ConnectFinding }> {
    const response = await client.getFinding({ id });
    if (!response.data) {
      throw new Error("Finding not found");
    }
    return { data: findingFromProto(response.data) };
  },
  async updateFindingStatus(
    id: string,
    payload: { status: "RESOLVED" | "MUTED"; resolutionNote?: string }
  ): Promise<{ data: { id: string; status: "RESOLVED" | "MUTED" } }> {
    const response = await client.updateFindingStatus({
      id,
      status: payload.status,
      resolutionNote: payload.resolutionNote ?? ""
    });
    if (!response.data) {
      throw new Error("Finding update failed");
    }
    return {
      data: {
        id: response.data.id,
        status: response.data.status as "RESOLVED" | "MUTED"
      }
    };
  },
  async remediateFinding(
    findingId: string,
    payload: { action: string; targetIdentifier?: string; note?: string }
  ): Promise<{ data: ConnectRemediationResult }> {
    const response = await client.remediateFinding({
      findingId,
      action: payload.action,
      targetIdentifier: payload.targetIdentifier ?? "",
      note: payload.note ?? ""
    });
    if (!response.data) {
      throw new Error("Remediation failed");
    }
    return { data: remediationResultFromProto(response.data) };
  },
  async listSaasIncidents(filters?: ConnectSaasIncidentsFilters): Promise<{
    data: ConnectSaasIncident[];
    pageInfo: { total: number; nextCursor: string | null };
    metrics: ConnectSaasIncidentMetrics;
  }> {
    const response = await client.listSaasIncidents({
      status: filters?.status === "ALL" ? "ALL" : filters?.status ?? "ALL",
      severity: filters?.severity ?? "",
      assigneeUserId: filters?.assigneeUserId ?? "",
      limit: filters?.limit ?? 50,
      cursor: filters?.cursor ?? ""
    });
    return {
      data: response.data.map(saasIncidentFromProto),
      pageInfo: {
        total: response.pageInfo?.total ?? 0,
        nextCursor: response.pageInfo?.nextCursor || null
      },
      metrics: saasIncidentMetricsFromProto(response.metrics)
    };
  },
  async getSaasIncident(id: string): Promise<{ data: ConnectSaasIncidentDetail }> {
    const response = await client.getSaasIncident({ id });
    if (!response.data) {
      throw new Error("Incident not found");
    }
    return { data: saasIncidentDetailFromProto(response.data) };
  },
  async createSaasIncident(payload: {
    title: string;
    summary?: string;
    severity: ConnectFinding["severity"];
    findingIds?: string[];
    ownerTeam?: string;
    assigneeUserId?: string;
  }): Promise<{ data: ConnectSaasIncidentDetail }> {
    const response = await client.createSaasIncident({
      title: payload.title,
      summary: payload.summary ?? "",
      severity: payload.severity,
      findingIds: payload.findingIds ?? [],
      ownerTeam: payload.ownerTeam ?? "",
      assigneeUserId: payload.assigneeUserId ?? ""
    });
    if (!response.data) {
      throw new Error("Incident create failed");
    }
    return { data: saasIncidentDetailFromProto(response.data) };
  },
  async updateSaasIncidentStatus(
    id: string,
    payload: { status: ConnectSaasIncidentStatus; note?: string }
  ): Promise<{ data: ConnectSaasIncident }> {
    const response = await client.updateSaasIncidentStatus({
      id,
      status: payload.status,
      note: payload.note ?? ""
    });
    if (!response.data) {
      throw new Error("Incident status update failed");
    }
    return { data: saasIncidentFromProto(response.data) };
  },
  async proposeSaasResponseAction(payload: {
    incidentId: string;
    findingId?: string;
    action: ConnectSaasResponseActionKind;
    provider?: ConnectProvider;
    targetType: string;
    targetIdentifier: string;
    rationale: string;
    approvalRequired?: boolean;
  }): Promise<{ data: ConnectSaasResponseAction }> {
    const response = await client.proposeSaasResponseAction({
      incidentId: payload.incidentId,
      findingId: payload.findingId ?? "",
      action: payload.action,
      provider: payload.provider ?? "",
      targetType: payload.targetType,
      targetIdentifier: payload.targetIdentifier,
      rationale: payload.rationale,
      approvalRequired: payload.approvalRequired ?? true
    });
    if (!response.data) {
      throw new Error("Response action proposal failed");
    }
    return { data: saasResponseActionFromProto(response.data) };
  },
  async executeSaasResponseAction(
    id: string,
    note?: string
  ): Promise<{ data: ConnectSaasResponseAction }> {
    const response = await client.executeSaasResponseAction({
      id,
      note: note ?? ""
    });
    if (!response.data) {
      throw new Error("Response action execution failed");
    }
    return { data: saasResponseActionFromProto(response.data) };
  },
  async listConnectorCatalog(): Promise<{
    data: ConnectConnectorDefinition[];
  }> {
    const response = await client.listConnectorCatalog({});
    return { data: response.data.map(connectorDefinitionFromProto) };
  },
  async listIntegrations(): Promise<{ data: ConnectIntegrationConnection[] }> {
    const response = await client.listIntegrations({});
    return { data: response.data.map(integrationFromProto) };
  },
  async createIntegration(
    payload: ConnectIntegrationPayload
  ): Promise<{ data: ConnectIntegrationConnection }> {
    // Empty strings are used for absent proto fields because optional scalar
    // presence is not relied on by the Go compatibility layer.
    const response = await client.createIntegration({
      provider: payload.provider,
      displayName: payload.displayName,
      externalAccountId: payload.externalAccountId,
      mode: payload.mode,
      credentials: {
        accessToken: payload.credentials.accessToken,
        refreshToken: payload.credentials.refreshToken ?? "",
        webhookSecret: payload.credentials.webhookSecret ?? ""
      }
    });
    if (!response.data) {
      throw new Error("Integration create failed");
    }
    return { data: integrationFromProto(response.data) };
  },
  async deleteIntegration(id: string): Promise<void> {
    await client.deleteIntegration({ id });
  },
  async getIntegrationChecks(
    integrationId: string
  ): Promise<{ data: ConnectIntegrationCheckState }> {
    const response = await client.getIntegrationChecks({ integrationId });
    if (!response.data) {
      throw new Error("Integration checks unavailable");
    }
    return { data: integrationCheckStateFromProto(response.data) };
  },
  async updateIntegrationChecks(
    integrationId: string,
    disabledChecks: string[],
    disableInput?: ConnectCheckDisableInput
  ): Promise<{ data: ConnectIntegrationCheckState }> {
    const response = await client.updateIntegrationChecks({
      integrationId,
      disabledChecks,
      disableReason: disableInput?.reason ?? "",
      disableExpiresAt: disableInput?.expiresAt ?? ""
    });
    if (!response.data) {
      throw new Error("Integration checks update failed");
    }
    return { data: integrationCheckStateFromProto(response.data) };
  },
  async listConnectorRules(
    integrationId: string
  ): Promise<{ data: ConnectConnectorRulesResponse }> {
    const response = await client.listConnectorRules({ integrationId });
    return {
      data: {
        integrationId: response.integrationId,
        provider: response.provider,
        builtIn: response.builtIn.map((rule) => ({
          id: rule.id,
          kind: "built_in",
          provider: rule.provider,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          eventTypes: [...rule.eventTypes],
          enabled: rule.enabled
        })),
        custom: response.custom.map((rule) => ({
          id: rule.id,
          kind: "custom",
          name: rule.name,
          severity: rule.severity,
          eventType: rule.eventType,
          subjectField: rule.subjectField,
          predicate: rule.predicateJson ? safeParse(rule.predicateJson) : {},
          enabled: rule.enabled,
          updatedAt: rule.updatedAt
        }))
      }
    };
  },
  async createCustomRule(
    integrationId: string,
    input: ConnectCustomRuleInput
  ): Promise<{ data: { id: string } }> {
    const response = await client.createCustomRule({
      integrationId,
      name: input.name,
      severity: input.severity,
      eventType: input.eventType,
      subjectField: input.subjectField,
      predicateJson: JSON.stringify(input.predicate ?? {}),
      enabled: input.enabled
    });
    return { data: { id: response.id } };
  },
  async updateCustomRule(
    integrationId: string,
    ruleId: string,
    input: ConnectCustomRuleInput
  ): Promise<{ data: { id: string } }> {
    const response = await client.updateCustomRule({
      integrationId,
      ruleId,
      name: input.name,
      severity: input.severity,
      eventType: input.eventType,
      subjectField: input.subjectField,
      predicateJson: JSON.stringify(input.predicate ?? {}),
      enabled: input.enabled
    });
    return { data: { id: response.id } };
  },
  async deleteCustomRule(
    integrationId: string,
    ruleId: string
  ): Promise<{ data: { id: string } }> {
    const response = await client.deleteCustomRule({ integrationId, ruleId });
    return { data: { id: response.id } };
  },
  async getGoogleMailboxScanConfig(
    integrationId: string
  ): Promise<{ data: ConnectGoogleMailboxScanConfig }> {
    const response = await client.getGoogleMailboxScanConfig({
      integrationId
    });
    if (!response.data) {
      throw new Error("Google mailbox scan config unavailable");
    }
    return { data: googleMailboxScanConfigFromProto(response.data) };
  },
  async updateGoogleMailboxScanConfig(
    integrationId: string,
    payload: {
      enabled: boolean;
      serviceAccountClientEmail?: string;
      privateKey?: string;
    }
  ): Promise<{ data: ConnectGoogleMailboxScanConfig }> {
    const response = await client.updateGoogleMailboxScanConfig({
      integrationId,
      enabled: payload.enabled,
      serviceAccountClientEmail: payload.serviceAccountClientEmail ?? "",
      privateKey: payload.privateKey ?? ""
    });
    if (!response.data) {
      throw new Error("Google mailbox scan config update failed");
    }
    return { data: googleMailboxScanConfigFromProto(response.data) };
  },
  async getGoogleWorkspaceBigQueryConfig(
    integrationId: string
  ): Promise<{ data: ConnectGoogleWorkspaceBigQueryConfig }> {
    const response = await client.getGoogleWorkspaceBigQueryConfig({
      integrationId
    });
    if (!response.data) {
      throw new Error("Google Workspace BigQuery config unavailable");
    }
    return { data: googleWorkspaceBigQueryConfigFromProto(response.data) };
  },
  async updateGoogleWorkspaceBigQueryConfig(
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
  ): Promise<{ data: ConnectGoogleWorkspaceBigQueryConfig }> {
    const response = await client.updateGoogleWorkspaceBigQueryConfig({
      integrationId,
      enabled: payload.enabled,
      projectId: payload.projectId ?? "",
      rawDatasetId: payload.rawDatasetId ?? "",
      datasetId: payload.datasetId ?? "",
      location: payload.location ?? "",
      serviceAccountEmail: payload.serviceAccountEmail ?? "",
      workloadIdentityProvider: payload.workloadIdentityProvider ?? "",
      accessMode: payload.accessMode ?? ""
    });
    if (!response.data) {
      throw new Error("Google Workspace BigQuery config update failed");
    }
    return { data: googleWorkspaceBigQueryConfigFromProto(response.data) };
  },
  async validateGoogleWorkspaceBigQueryConfig(
    integrationId: string
  ): Promise<{ data: ConnectGoogleWorkspaceBigQueryValidation }> {
    const response = await client.validateGoogleWorkspaceBigQueryConfig({
      integrationId
    });
    if (!response.data) {
      throw new Error("Google Workspace BigQuery validation unavailable");
    }
    return { data: googleWorkspaceBigQueryValidationFromProto(response.data) };
  },
  async startGoogleWorkspaceOAuth(
    mode: "READ_ONLY" | "REMEDIATION"
  ): Promise<{ data: { url: string } }> {
    // Google Workspace is intentionally OAuth-only in the UI; the callback fills
    // in tenant identity and encrypted tokens server-side.
    const response = await client.startGoogleWorkspaceOAuth({ mode });
    return { data: { url: response.data?.url ?? "" } };
  },
  async getIntegrationOAuthClient(
    provider: "GOOGLE_WORKSPACE"
  ): Promise<{ data: ConnectIntegrationOAuthClient }> {
    const response = await client.getIntegrationOAuthClient({ provider });
    return { data: integrationOAuthClientFromProto(response.data, provider) };
  },
  async setIntegrationOAuthClient(input: {
    provider: "GOOGLE_WORKSPACE";
    clientId: string;
    clientSecret: string;
    redirectUri: string;
  }): Promise<{ data: ConnectIntegrationOAuthClient }> {
    const response = await client.setIntegrationOAuthClient(input);
    return { data: integrationOAuthClientFromProto(response.data, input.provider) };
  },
  async clearIntegrationOAuthClient(
    provider: "GOOGLE_WORKSPACE"
  ): Promise<{ data: ConnectIntegrationOAuthClient }> {
    const response = await client.clearIntegrationOAuthClient({ provider });
    return { data: integrationOAuthClientFromProto(response.data, provider) };
  },
  async forceSyncIntegration(integrationId: string): Promise<{
    data: ConnectIntegrationConnection;
    sync: ConnectSyncSummary;
  }> {
    const response = await client.forceSyncIntegration({ integrationId });
    if (!response.data) {
      throw new Error("Integration sync failed");
    }
    return {
      data: integrationFromProto(response.data),
      sync: {
        sampleCount: response.sync?.sampleCount ?? 0,
        eventsIngested: response.sync?.eventsIngested ?? 0,
        findingsOpened: response.sync?.findingsOpened ?? 0,
        sources: response.sync?.sources ?? []
      }
    };
  },
  async getIntegrationSyncStatus(
    integrationId: string
  ): Promise<{ data: ConnectIntegrationSyncStatus }> {
    const response = await client.getIntegrationSyncStatus({ integrationId });
    if (!response.data) {
      throw new Error("Integration sync status unavailable");
    }
    return { data: integrationSyncStatusFromProto(response.data) };
  },
  async runIntegrationSourceSync(input: {
    integrationId: string;
    sourceKind?: ConnectIntegrationSourceKind | string;
    streamName?: string;
  }): Promise<{ data: ConnectIntegrationSourceSyncAction }> {
    const response = await client.runIntegrationSourceSync({
      integrationId: input.integrationId,
      sourceKind: input.sourceKind ?? "all",
      streamName: input.streamName ?? ""
    });
    if (!response.data) {
      throw new Error("Source sync failed");
    }
    return { data: integrationSourceSyncActionFromProto(response.data) };
  },
  async backfillIntegrationSource(input: {
    integrationId: string;
    sourceKind: ConnectIntegrationSourceKind | string;
    streamName: string;
    fromTime: string;
  }): Promise<{ data: ConnectIntegrationSourceSyncAction }> {
    const response = await client.backfillIntegrationSource(input);
    if (!response.data) {
      throw new Error("Source backfill failed");
    }
    return { data: integrationSourceSyncActionFromProto(response.data) };
  },
  async listSiemCatalog(): Promise<{
    data: ConnectSiemDestinationDefinition[];
  }> {
    const response = await client.listSiemCatalog({});
    return { data: response.data.map(siemDefinitionFromProto) };
  },
  async listSiemDestinations(): Promise<{ data: ConnectSiemDestination[] }> {
    const response = await client.listSiemDestinations({});
    return { data: response.data.map(siemDestinationFromProto) };
  },
  async createSiemDestination(
    payload: ConnectCreateSiemPayload
  ): Promise<{ data: ConnectSiemDestination }> {
    const response = await client.createSiemDestination({
      kind: payload.kind,
      name: payload.name,
      endpointUrl: payload.endpointUrl ?? "",
      filePath: payload.filePath ?? "",
      index: payload.index ?? "",
      token: payload.token ?? "",
      streams: payload.streams
    });
    if (!response.data) {
      throw new Error("SIEM destination create failed");
    }
    return { data: siemDestinationFromProto(response.data) };
  },
  async deleteSiemDestination(id: string): Promise<void> {
    await client.deleteSiemDestination({ id });
  },
  async testSiemDestination(
    id: string
  ): Promise<{ data: ConnectSiemTestResult }> {
    const response = await client.testSiemDestination({ id });
    if (!response.data) {
      throw new Error("SIEM destination test failed");
    }
    return {
      data: {
        destinationId: response.data.destinationId,
        ok: response.data.ok,
        message: response.data.message
      }
    };
  },
  async listShadowItOauthApps(): Promise<{ data: ConnectShadowItOauthApp[] }> {
    const response = await client.listShadowItOauthApps({});
    return { data: response.data.map(shadowItOauthAppFromProto) };
  },
  async listShadowItOauthAppGrants(
    assetId: string
  ): Promise<{ data: ConnectShadowItOauthAppDetail }> {
    const response = await client.listShadowItOauthAppGrants({ assetId });
    if (!response.data?.app) {
      throw new Error("OAuth app not found");
    }
    return {
      data: {
        app: {
          id: response.data.app.id,
          name: response.data.app.name,
          externalId: response.data.app.externalId || null,
          provider: response.data.app.provider as ConnectProvider | ""
        },
        grants: response.data.grants.map(shadowItGrantFromProto)
      }
    };
  },
  async getTenantSettings(): Promise<{ data: ConnectTenantSettings }> {
    const response = await client.getTenantSettings({});
    if (!response.data) {
      throw new Error("Tenant settings unavailable");
    }
    return { data: tenantSettingsFromProto(response.data) };
  },
  async updateTenantSettings(
    payload: ConnectTenantSettingsUpdate
  ): Promise<{ data: ConnectTenantSettings }> {
    const response = await client.updateTenantSettings({
      name: payload.name,
      notificationEmail: payload.notificationEmail,
      dataRetentionDays: payload.dataRetentionDays,
      criticalRiskThreshold: payload.criticalRiskThreshold,
      defaultSlaHours: payload.defaultSlaHours,
      autoResolveLowSeverity: payload.autoResolveLowSeverity,
      enforceSsoOnly: payload.enforceSsoOnly,
      webhookAlertUrl: payload.webhookAlertUrl
    });
    if (!response.data) {
      throw new Error("Tenant settings update failed");
    }
    return { data: tenantSettingsFromProto(response.data) };
  },
  async listTenantMembers(): Promise<{ data: ConnectTenantMember[] }> {
    const response = await client.listTenantMembers({});
    return { data: response.data.map(tenantMemberFromProto) };
  },
  async createTenantMember(payload: {
    email: string;
    displayName?: string;
    roleName: ConnectTenantRole;
  }): Promise<{
    data: ConnectTenantMember;
    invitation: ConnectInvitationResult;
  }> {
    const response = await client.createTenantMember({
      email: payload.email,
      displayName: payload.displayName ?? "",
      roleName: payload.roleName
    });
    if (!response.data || !response.invitation) {
      throw new Error("Tenant member create failed");
    }
    return {
      data: tenantMemberFromProto(response.data),
      invitation: invitationResultFromProto(response.invitation)
    };
  },
  async createMemberResetLink(id: string): Promise<{
    data: ConnectTenantMember;
    reset: ConnectInvitationResult;
  }> {
    const response = await client.createMemberResetLink({ id });
    if (!response.data || !response.reset) {
      throw new Error("Member reset link create failed");
    }
    return {
      data: tenantMemberFromProto(response.data),
      reset: invitationResultFromProto(response.reset)
    };
  },
  async updateMemberRole(
    id: string,
    roleName: ConnectTenantRole
  ): Promise<{ data: ConnectTenantMember }> {
    const response = await client.updateMemberRole({ id, roleName });
    if (!response.data) {
      throw new Error("Member role update failed");
    }
    return { data: tenantMemberFromProto(response.data) };
  },
  async listAuditLogs(): Promise<{ data: ConnectAuditLogEntry[] }> {
    const response = await client.listAuditLogs({});
    return { data: response.data.map(auditLogFromProto) };
  },
  async getSecurityOverview(): Promise<{ data: ConnectSecurityOverview }> {
    const response = await client.getSecurityOverview({});
    if (!response.data) {
      throw new Error("Security overview unavailable");
    }
    return { data: securityOverviewFromProto(response.data) };
  },
  async listEmailDomainHealth(options?: {
    refreshIfStale?: boolean;
  }): Promise<{ data: ConnectEmailDomainHealth[] }> {
    const response = await client.listEmailDomainHealth({
      refreshIfStale: options?.refreshIfStale ?? false
    });
    return { data: response.data.map(emailDomainHealthFromProto) };
  },
  async getEmailDomainHealth(
    domain: string
  ): Promise<{ data: ConnectEmailDomainHealthDetail }> {
    const response = await client.getEmailDomainHealth({ domain });
    if (!response.data) {
      throw new Error("Email domain health unavailable");
    }
    return { data: emailDomainHealthDetailFromProto(response.data) };
  },
  async refreshEmailDomainHealth(
    domain?: string
  ): Promise<{ data: ConnectEmailDomainHealth[] }> {
    const response = await client.refreshEmailDomainHealth({
      domain: domain ?? ""
    });
    return { data: response.data.map(emailDomainHealthFromProto) };
  },
  async listSecurityAssets(
    filters?: ConnectSecurityAssetsFilters
  ): Promise<{ data: ConnectSecurityAsset[] }> {
    const response = await client.listSecurityAssets({
      type: filters?.type ?? "",
      ownershipStatus: filters?.ownershipStatus ?? "",
      integrationId: filters?.integrationId ?? ""
    });
    return { data: response.data.map(securityAssetFromProto) };
  },
  async createSecurityAsset(
    payload: ConnectCreateSecurityAssetPayload
  ): Promise<{ data: ConnectSecurityAsset }> {
    const response = await client.createSecurityAsset({
      integrationId: payload.integrationId ?? "",
      ownerUserId: payload.ownerUserId ?? "",
      businessOwnerUserId: payload.businessOwnerUserId ?? "",
      type: payload.type,
      provider: payload.provider ?? "",
      name: payload.name,
      summary: payload.summary ?? "",
      externalId: payload.externalId ?? "",
      labels: payload.labels,
      criticality: payload.criticality,
      exposureLevel: payload.exposureLevel,
      ownershipStatus: payload.ownershipStatus ?? "",
      containsSensitiveData: payload.containsSensitiveData,
      isPrivileged: payload.isPrivileged,
      riskScore: payload.riskScore,
      lastObservedAt: payload.lastObservedAt ?? ""
    });
    if (!response.data) {
      throw new Error("Security asset create failed");
    }
    return { data: securityAssetFromProto(response.data) };
  },
  async updateSecurityAsset(
    id: string,
    payload: ConnectUpdateSecurityAssetPayload
  ): Promise<{ data: ConnectSecurityAsset }> {
    const response = await client.updateSecurityAsset({
      id,
      integrationId: payload.integrationId,
      ownerUserId: payload.ownerUserId,
      businessOwnerUserId: payload.businessOwnerUserId,
      type: payload.type,
      provider: payload.provider,
      name: payload.name,
      summary: payload.summary,
      externalId: payload.externalId,
      labels: payload.labels ?? [],
      labelsPresent: payload.labels !== undefined,
      criticality: payload.criticality,
      exposureLevel: payload.exposureLevel,
      ownershipStatus: payload.ownershipStatus,
      containsSensitiveData: payload.containsSensitiveData,
      isPrivileged: payload.isPrivileged,
      riskScore: payload.riskScore,
      lastObservedAt: payload.lastObservedAt
    });
    if (!response.data) {
      throw new Error("Security asset update failed");
    }
    return { data: securityAssetFromProto(response.data) };
  },
  async listRiskExceptions(): Promise<{ data: ConnectRiskException[] }> {
    const response = await client.listRiskExceptions({});
    return { data: response.data.map(riskExceptionFromProto) };
  },
  async createRiskException(
    payload: ConnectCreateRiskExceptionPayload
  ): Promise<{ data: ConnectRiskException }> {
    const response = await client.createRiskException({
      assetId: payload.assetId ?? "",
      findingId: payload.findingId ?? "",
      title: payload.title,
      rationale: payload.rationale,
      compensatingControls: payload.compensatingControls,
      expiresAt: payload.expiresAt ?? ""
    });
    if (!response.data) {
      throw new Error("Risk exception create failed");
    }
    return { data: riskExceptionFromProto(response.data) };
  },
  async updateRiskException(
    id: string,
    payload: ConnectUpdateRiskExceptionPayload
  ): Promise<{ data: ConnectRiskException }> {
    const response = await client.updateRiskException({
      id,
      title: payload.title,
      rationale: payload.rationale,
      compensatingControls: payload.compensatingControls ?? [],
      compensatingControlsPresent:
        payload.compensatingControls !== undefined,
      status: payload.status,
      expiresAt: payload.expiresAt
    });
    if (!response.data) {
      throw new Error("Risk exception update failed");
    }
    return { data: riskExceptionFromProto(response.data) };
  },
  async listExecutiveReports(): Promise<{
    data: ConnectExecutiveReport[];
  }> {
    const response = await client.listExecutiveReports({});
    return { data: response.data.map(executiveReportFromProto) };
  },
  async getExecutiveReport(
    id: string
  ): Promise<{ data: ConnectExecutiveReport }> {
    const response = await client.getExecutiveReport({ id });
    if (!response.data) {
      throw new Error("Executive report not found");
    }
    return { data: executiveReportFromProto(response.data) };
  },
  async createExecutiveReport(payload: {
    period: ExecutiveReportPeriod;
    title?: string;
    periodStart?: string;
    periodEnd?: string;
    template?: ExecutiveReportTemplate;
  }): Promise<{ data: ConnectExecutiveReport }> {
    const response = await client.createExecutiveReport({
      period: payload.period,
      title: payload.title ?? "",
      periodStart: payload.periodStart ?? "",
      periodEnd: payload.periodEnd ?? "",
      template: payload.template ?? "EXECUTIVE_SUMMARY"
    });
    if (!response.data) {
      throw new Error("Executive report create failed");
    }
    return { data: executiveReportFromProto(response.data) };
  },
  async deleteExecutiveReport(
    id: string
  ): Promise<{ data: { deleted: boolean } }> {
    const response = await client.deleteExecutiveReport({ id });
    return { data: { deleted: response.deleted } };
  }
};

export type ExecutiveReportPeriod = "WEEK" | "MONTH" | "QUARTER" | "CUSTOM";
export type ExecutiveReportStatus = "GENERATING" | "READY" | "FAILED";
export type ExecutiveReportTemplate =
  | "EXECUTIVE_SUMMARY"
  | "GOOGLE_WORKSPACE_ASSESSMENT";

export type ConnectExecutiveReport = {
  id: string;
  template: ExecutiveReportTemplate;
  period: ExecutiveReportPeriod;
  periodStart: string;
  periodEnd: string;
  title: string;
  summary?: string;
  status: ExecutiveReportStatus;
  kpiSnapshot: Record<string, unknown>;
  hasHtml: boolean;
  hasPdf: boolean;
  htmlUrl?: string;
  pdfUrl?: string;
  createdAt: string;
  updatedAt: string;
  generatedAt?: string;
  errorMessage?: string;
  requestedByUser?: string | null;
};

function parsePeriodValue(value: string): ExecutiveReportPeriod {
  if (value === "WEEK" || value === "MONTH" || value === "QUARTER" || value === "CUSTOM") {
    return value;
  }
  return "MONTH";
}

function parseStatusValue(value: string): ExecutiveReportStatus {
  if (value === "READY" || value === "FAILED") return value;
  return "GENERATING";
}

function parseTemplateValue(value: string): ExecutiveReportTemplate {
  if (value === "GOOGLE_WORKSPACE_ASSESSMENT") return value;
  return "EXECUTIVE_SUMMARY";
}

function executiveReportFromProto(
  proto: import("./gen/aperio/v1/api_pb").ExecutiveReport
): ConnectExecutiveReport {
  let kpiSnapshot: Record<string, unknown> = {};
  if (proto.kpiSnapshotJson) {
    try {
      const parsed = JSON.parse(proto.kpiSnapshotJson);
      if (parsed && typeof parsed === "object") {
        kpiSnapshot = parsed as Record<string, unknown>;
      }
    } catch {
      kpiSnapshot = {};
    }
  }
  return {
    id: proto.id,
    template: parseTemplateValue(proto.template),
    period: parsePeriodValue(proto.period),
    periodStart: proto.periodStart,
    periodEnd: proto.periodEnd,
    title: proto.title,
    summary: proto.summary || undefined,
    status: parseStatusValue(proto.status),
    kpiSnapshot,
    hasHtml: proto.hasHtml,
    hasPdf: proto.hasPdf,
    htmlUrl: proto.htmlUrl || undefined,
    pdfUrl: proto.pdfUrl || undefined,
    createdAt: proto.createdAt,
    updatedAt: proto.updatedAt,
    generatedAt: proto.generatedAt || undefined,
    errorMessage: proto.errorMessage || undefined,
    requestedByUser: proto.requestedByUserId || null
  };
}
