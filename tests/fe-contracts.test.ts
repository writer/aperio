import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function exportedTypeBlock(source: string, typeName: string) {
  const start = source.indexOf(`export type ${typeName} = {`);
  assert.notEqual(start, -1, `expected exported type ${typeName}`);
  return balancedBlock(source, source.indexOf("{", start), typeName);
}

function tsFunctionBlock(source: string, functionName: string) {
  const start = source.indexOf(`function ${functionName}(`);
  assert.notEqual(start, -1, `expected function ${functionName}`);
  return balancedBlock(source, source.indexOf("{", start), functionName);
}

function goFunctionBlock(source: string, functionName: string) {
  const start = source.indexOf(`func ${functionName}(`);
  assert.notEqual(start, -1, `expected Go function ${functionName}`);
  return balancedBlock(source, source.indexOf("{", start), functionName);
}

function balancedBlock(source: string, openBrace: number, label: string) {
  let depth = 0;
  for (let index = openBrace; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) {
      return source.slice(openBrace, index + 1);
    }
  }
  throw new Error(`unterminated block for ${label}`);
}

function lowerCamel(value: string) {
  return value.charAt(0).toLowerCase() + value.slice(1);
}

function serviceRpcNames(proto: string) {
  const serviceStart = proto.indexOf("service AperioService {");
  assert.notEqual(serviceStart, -1, "expected AperioService service block");
  const service = balancedBlock(proto, proto.indexOf("{", serviceStart), "AperioService");
  return [...service.matchAll(/^\s*rpc\s+(\w+)\(/gm)].map((match) => match[1]);
}

test("frontend-consumed AperioService RPC inventory is implemented and wrapped", () => {
  const proto = readRepoFile("proto/aperio/v1/api.proto");
  const client = readRepoFile("packages/connect/src/client.ts");
  const appSources = [
    readRepoFile("internal/bootstrap/app.go"),
    readRepoFile("internal/bootstrap/typed_compat.go"),
    readRepoFile("internal/bootstrap/oauth_clients.go")
  ].join("\n");

  const rpcs = serviceRpcNames(proto);
  assert.ok(rpcs.length > 40, "expected complete AperioService RPC inventory");

  for (const rpc of rpcs) {
    assert.match(
      appSources,
      new RegExp(`func \\(a \\*App\\) ${rpc}\\(`),
      `${rpc} must be implemented on the Go API`
    );

    const wrapperName = lowerCamel(rpc);
    if (rpc === "CallApi") {
      assert.doesNotMatch(
        client,
        /\bcallApi\s*\(/,
        "CallApi must not be exposed through the browser wrapper"
      );
      continue;
    }
    assert.match(
      client,
      new RegExp(`\\b(?:async\\s+)?${wrapperName}\\s*\\(`),
      `${rpc} must be wrapped by packages/connect/src/client.ts`
    );
  }
});

test("React-facing API exports cover typed product RPCs without exposing CallApi", () => {
  const webApi = readRepoFile("apps/web/lib/api.ts");
  const expectedExports: Record<string, string> = {
    Signup: "signup",
    Login: "login",
    GetCurrentSession: "fetchCurrentSession",
    LogoutCurrentSession: "logoutCurrentSession",
    ListWorkspaces: "fetchWorkspaces",
    SwitchWorkspace: "switchWorkspace",
    RequestPasswordReset: "requestPasswordReset",
    ResetPassword: "resetPassword",
    AcceptInvite: "acceptInvite",
    BeginMfaEnrollment: "beginMfaEnrollment",
    EnableMfa: "enableMfa",
    DisableMfa: "disableMfa",
    GetDashboardMetrics: "fetchDashboardMetrics",
    ListFindings: "fetchFindings",
    GetFinding: "fetchFinding",
    UpdateFindingStatus: "updateFindingStatus",
    RemediateFinding: "remediateFinding",
    ListConnectorCatalog: "fetchConnectorCatalog",
    ListIntegrations: "fetchIntegrations",
    CreateIntegration: "connectIntegration",
    DeleteIntegration: "disconnectIntegration",
    GetIntegrationChecks: "fetchIntegrationChecks",
    UpdateIntegrationChecks: "updateIntegrationChecks",
    GetGoogleMailboxScanConfig: "fetchGoogleMailboxScanConfig",
    UpdateGoogleMailboxScanConfig: "updateGoogleMailboxScanConfig",
    GetGoogleWorkspaceBigQueryConfig: "fetchGoogleWorkspaceBigQueryConfig",
    UpdateGoogleWorkspaceBigQueryConfig: "updateGoogleWorkspaceBigQueryConfig",
    ValidateGoogleWorkspaceBigQueryConfig: "validateGoogleWorkspaceBigQueryConfig",
    StartGoogleWorkspaceOAuth: "startGoogleWorkspaceOAuth",
    ForceSyncIntegration: "forceSyncIntegration",
    ListSiemCatalog: "fetchSiemCatalog",
    ListSiemDestinations: "fetchSiemDestinations",
    CreateSiemDestination: "createSiemDestination",
    DeleteSiemDestination: "deleteSiemDestination",
    TestSiemDestination: "testSiemDestination",
    ListShadowItOauthApps: "fetchShadowItOauthApps",
    ListShadowItOauthAppGrants: "fetchShadowItOauthAppGrants",
    GetTenantSettings: "fetchTenantSettings",
    UpdateTenantSettings: "updateTenantSettings",
    ListTenantMembers: "fetchTenantMembers",
    CreateTenantMember: "createTenantMember",
    CreateMemberResetLink: "createMemberResetLink",
    UpdateMemberRole: "updateMemberRole",
    ListAuditLogs: "fetchAuditLogs",
    GetSecurityOverview: "fetchSecurityOverview",
    ListEmailDomainHealth: "fetchEmailDomainHealth",
    GetEmailDomainHealth: "fetchEmailDomainHealthDetail",
    RefreshEmailDomainHealth: "refreshEmailDomainHealth",
    ListSecurityAssets: "fetchSecurityAssets",
    CreateSecurityAsset: "createSecurityAsset",
    UpdateSecurityAsset: "updateSecurityAsset",
    ListRiskExceptions: "fetchRiskExceptions",
    CreateRiskException: "createRiskException",
    UpdateRiskException: "updateRiskException"
  };

  for (const [rpc, exportName] of Object.entries(expectedExports)) {
    assert.match(
      webApi,
      new RegExp(`export\\s+async\\s+function\\s+${exportName}\\b`),
      `${rpc} should be surfaced through apps/web/lib/api.ts as ${exportName}`
    );
  }
  assert.doesNotMatch(webApi, /\bcallApi\b|\/api\/v1\//);
});

test("Connect transport stays configured for credentialed no-store browser fetches", () => {
  const connectClient = readRepoFile("packages/connect/src/client.ts");
  const nextConfig = readRepoFile("apps/web/next.config.mjs");

  assert.match(connectClient, /NEXT_PUBLIC_CONNECT_API_BASE_URL/);
  assert.match(connectClient, /"http:\/\/localhost:4100"/);
  assert.match(connectClient, /baseUrl:\s*CONNECT_BASE_URL/);
  assert.match(connectClient, /credentials:\s*"include"/);
  assert.match(connectClient, /cache:\s*"no-store"/);

  assert.match(nextConfig, /NEXT_PUBLIC_CONNECT_API_BASE_URL/);
  assert.match(nextConfig, /connectApiBaseUrl/);
  assert.match(nextConfig, /connect-src 'self'.*\$\{connectApiBaseUrl\}/);
});

test("workspace switcher retries after a transient workspace load failure", () => {
  const switcher = readRepoFile("apps/web/components/layout/workspace-switcher.tsx");

  assert.match(
    switcher,
    /if \(!open \|\| workspaces !== null \|\| errorMessage\) return;/,
    "the failed open should stop retrying while the error is visible"
  );
  assert.match(
    switcher,
    /if \(next && errorMessage\) \{\s*setWorkspaces\(null\);\s*setErrorMessage\(null\);/s,
    "reopening after an error should clear the failed snapshot and retry"
  );
  assert.doesNotMatch(
    switcher,
    /catch[\s\S]*?setWorkspaces\(\[\]\);/,
    "transient failures must not be cached as a successful empty workspace list"
  );
});

test("security identity MFA remains a nullable tri-state contract", () => {
  const proto = readRepoFile("proto/aperio/v1/api.proto");
  const generated = readRepoFile("packages/connect/src/gen/aperio/v1/api_pb.ts");
  const connectClient = readRepoFile("packages/connect/src/client.ts");
  const webApi = readRepoFile("apps/web/lib/api.ts");
  const privilegedIdentitiesPage = readRepoFile(
    "apps/web/components/security/privileged-identities-page.tsx"
  );

  assert.match(proto, /bool\s+mfa_enabled\s*=\s*10;/);
  assert.match(proto, /optional\s+bool\s+mfa_enabled_state\s*=\s*16;/);
  assert.match(generated, /mfaEnabled:\s*boolean;/);
  assert.match(generated, /mfaEnabledState\?:\s*boolean;/);
  assert.match(
    exportedTypeBlock(connectClient, "ConnectSecurityIdentity"),
    /mfaEnabled:\s*boolean\s*\|\s*null;/
  );
  assert.match(
    tsFunctionBlock(connectClient, "securityIdentityFromProto"),
    /mfaEnabled:\s*identity\.mfaEnabledState\s*\?\?\s*\(identity\.mfaEnabled\s*\?\s*true\s*:\s*null\)/
  );
  assert.match(
    exportedTypeBlock(webApi, "SecurityIdentity"),
    /mfaEnabled:\s*boolean\s*\|\s*null;/
  );
  assert.match(privilegedIdentitiesPage, /i\.mfaEnabled\s*==\s*null/);
  assert.match(privilegedIdentitiesPage, /i\.mfaEnabled\s*===\s*false/);
});

test("typed auth sessions do not copy compatibility bearer tokens", () => {
  const typedCompat = readRepoFile("internal/bootstrap/typed_compat.go");
  assert.doesNotMatch(
    goFunctionBlock(typedCompat, "authSessionFromMap"),
    /Token:\s*stringFromAny/,
    "typed auth responses should rely on Set-Cookie and omit bearer tokens"
  );
});
