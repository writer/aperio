import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function sourceFilesUnder(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const entries = readdirSync(absoluteDir);
  return entries.flatMap((entry) => {
    const absolutePath = path.join(absoluteDir, entry);
    const relativePath = path.join(relativeDir, entry);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      if (entry === "gen" || entry === ".next") return [];
      return sourceFilesUnder(relativePath);
    }
    return /\.(?:ts|tsx)$/.test(entry) ? [relativePath] : [];
  });
}

function exportedTypeBlock(source: string, typeName: string) {
  const start = source.indexOf(`export type ${typeName} = {`);
  assert.notEqual(start, -1, `expected exported type ${typeName}`);
  const openBrace = source.indexOf("{", start);
  let depth = 0;
  for (let index = openBrace; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) {
      return source.slice(openBrace, index + 1);
    }
  }
  throw new Error(`unterminated exported type ${typeName}`);
}

function functionBlock(source: string, functionName: string) {
  const start = source.indexOf(`function ${functionName}(`);
  assert.notEqual(start, -1, `expected function ${functionName}`);
  const openBrace = source.indexOf("{", start);
  let depth = 0;
  for (let index = openBrace; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) {
      return source.slice(openBrace, index + 1);
    }
  }
  throw new Error(`unterminated function ${functionName}`);
}

test("browser auth client has no localStorage bearer-token shims", () => {
  const api = readRepoFile("apps/web/lib/api.ts");

  assert.doesNotMatch(api, /aperio\.auth\.token/);
  assert.doesNotMatch(
    api,
    /\b(?:authTokenFromStorage|getAuthToken|setAuthToken|clearAuthToken)\b/
  );
  assert.doesNotMatch(api, /\blocalStorage\b/);

  for (const relativePath of [
    "apps/web/components/auth/login-page.tsx",
    "apps/web/components/auth/signup-page.tsx",
    "apps/web/components/auth/reset-password-page.tsx",
    "apps/web/components/auth/accept-invite-page.tsx",
    "apps/web/components/auth/auth-shell.tsx",
    "apps/web/components/layout/top-nav.tsx"
  ]) {
    const source = readRepoFile(relativePath);
    assert.doesNotMatch(source, /\bsetAuthToken\b|\bclearAuthToken\b/);
    assert.doesNotMatch(source, /response\.data\.token/);
  }
});

test("browser localStorage use is limited to the non-auth theme preference", () => {
  const allowedLocalStorageSources = new Set([
    "apps/web/app/layout.tsx",
    "apps/web/components/layout/theme-provider.tsx"
  ]);
  const browserSources = [
    ...sourceFilesUnder("apps/web"),
    ...sourceFilesUnder("packages/connect/src")
  ].filter(
    (relativePath) => !relativePath.includes(`${path.sep}gen${path.sep}`)
  );

  for (const relativePath of browserSources) {
    const source = readRepoFile(relativePath);
    if (!/\blocalStorage\b/.test(source)) {
      continue;
    }
    assert.ok(
      allowedLocalStorageSources.has(relativePath),
      `${relativePath} must not introduce browser localStorage outside the theme preference`
    );
    assert.match(source, /aperio\.theme/);
    assert.doesNotMatch(
      source,
      /localStorage\.(?:getItem|setItem|removeItem)\([^)]*(?:auth|token|session)/i,
      `${relativePath} must not persist auth/session/token values in localStorage`
    );
  }
});

test("frontend auth session types do not expose bearer tokens", () => {
  const webApi = readRepoFile("apps/web/lib/api.ts");
  const connectClient = readRepoFile("packages/connect/src/client.ts");

  assert.doesNotMatch(exportedTypeBlock(webApi, "AuthSession"), /\btoken\s*:/);
  assert.doesNotMatch(
    exportedTypeBlock(connectClient, "ConnectAuthSession"),
    /\btoken\s*:/
  );
  assert.doesNotMatch(
    functionBlock(connectClient, "authSessionFromProto"),
    /session\.token/
  );
  assert.match(
    functionBlock(connectClient, "authSessionFromProto"),
    /session\.authContext/,
    "frontend auth sessions should consume server-provided Cerebro auth context"
  );
  assert.match(exportedTypeBlock(webApi, "AuthContext"), /\bauthMode\s*:/);
  assert.match(exportedTypeBlock(webApi, "AuthContext"), /\ballowedTenants\s*:/);
  assert.match(exportedTypeBlock(webApi, "AuthContext"), /\bgroups\s*:/);
  assert.match(
    exportedTypeBlock(webApi, "AuthContext"),
    /\bcerebroMcpResource\s*:/
  );
  assert.match(
    exportedTypeBlock(webApi, "AuthContext"),
    /\bcerebroMcpResourceMetadataPath\s*:/
  );
  assert.match(
    exportedTypeBlock(webApi, "AuthContext"),
    /\bcerebroOauthAuthorizationServerMetadataPath\s*:/
  );
});

test("frontend auth surfaces share Cerebro auth vocabulary", () => {
  const authModel = readRepoFile("apps/web/lib/cerebro-auth.ts");
  const accountMenu = readRepoFile(
    "apps/web/components/layout/account-menu.tsx"
  );
  const authLayout = readRepoFile("apps/web/components/auth/auth-layout.tsx");
  const loginPage = readRepoFile("apps/web/components/auth/login-page.tsx");
  const workspaceSwitcher = readRepoFile(
    "apps/web/components/layout/workspace-switcher.tsx"
  );

  assert.match(authModel, /CEREBRO_API_RESOURCE\s*=\s*"cerebro-api"/);
  assert.match(authModel, /CEREBRO_MCP_RESOURCE\s*=\s*"cerebro-mcp"/);
  assert.match(
    authModel,
    /CEREBRO_MCP_RESOURCE_METADATA_PATH\s*=\s*\n\s*"\/\.well-known\/oauth-protected-resource\/api\/v1\/mcp"/
  );
  assert.match(
    authModel,
    /CEREBRO_OAUTH_AUTHORIZATION_SERVER_METADATA_PATH\s*=\s*\n\s*"\/\.well-known\/oauth-authorization-server"/
  );
  assert.match(
    authModel,
    /CEREBRO_HUMAN_AUTH_MODE\s*=\s*"human_workspace_session"/
  );
  assert.match(
    authModel,
    /CEREBRO_SESSION_TRANSPORT\s*=\s*"http_only_cookie"/
  );
  assert.match(accountMenu, /formatCerebroScope/);
  assert.match(accountMenu, /formatCerebroTransport/);
  assert.match(accountMenu, /CEREBRO_API_RESOURCE/);
  assert.match(
    authModel,
    /formatCerebroTransport\(CEREBRO_SESSION_TRANSPORT\)/
  );
  assert.match(accountMenu, /CEREBRO_MCP_RESOURCE_METADATA_PATH/);
  assert.match(accountMenu, /CEREBRO_OAUTH_AUTHORIZATION_SERVER_METADATA_PATH/);
  assert.match(accountMenu, /cerebroMcpGrantTypes/);
  assert.match(authLayout, /CEREBRO_AUTH_INSIGHTS/);
  assert.match(authLayout, /CEREBRO_MCP_RESOURCE/);
  assert.match(loginPage, /CEREBRO_HUMAN_AUTH_MODE/);
  assert.match(workspaceSwitcher, /CEREBRO_API_RESOURCE/);
});

test("frontend requests rely on cookies instead of Authorization bearer headers", () => {
  const connectClient = readRepoFile("packages/connect/src/client.ts");
  assert.match(connectClient, /credentials:\s*"include"/);

  const browserSources = [
    ...sourceFilesUnder("apps/web"),
    ...sourceFilesUnder("packages/connect/src")
  ].filter(
    (relativePath) => !relativePath.includes(`${path.sep}gen${path.sep}`)
  );

  for (const relativePath of browserSources) {
    const source = readRepoFile(relativePath);
    assert.doesNotMatch(
      source,
      /\bAuthorization\b|Bearer\s+\+|Bearer\s+["'`]/,
      `${relativePath} must not construct browser bearer auth`
    );
  }
});

test("frontend sources do not expose the CallApi compatibility bridge", () => {
  const browserSources = [
    ...sourceFilesUnder("apps/web"),
    ...sourceFilesUnder("packages/connect/src")
  ].filter(
    (relativePath) => !relativePath.includes(`${path.sep}gen${path.sep}`)
  );

  for (const relativePath of browserSources) {
    const source = readRepoFile(relativePath).replaceAll(
      "/.well-known/oauth-protected-resource/api/v1/mcp",
      ""
    );
    assert.doesNotMatch(
      source,
      /\bcallApi\b|\/api\/v1\//,
      `${relativePath} must use typed Connect helpers instead of the legacy compatibility bridge`
    );
  }
});
