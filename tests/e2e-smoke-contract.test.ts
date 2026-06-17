import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL, fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

async function loadSmokeHarness() {
  return import(pathToFileURL(path.join(repoRoot, "scripts/smoke-e2e.mjs")).href);
}

test("local E2E smoke command is registered as the authoritative harness", () => {
  const packageJson = JSON.parse(readRepoFile("package.json")) as {
    scripts: Record<string, string>;
  };
  const makefile = readRepoFile("Makefile");

  assert.equal(packageJson.scripts["smoke:e2e"], "node scripts/smoke-e2e.mjs");
  assert.match(makefile, /^\.PHONY: .*smoke-e2e/m);
  assert.match(makefile, /^smoke-e2e: require-env ## Run the local Go API \+ TypeScript FE E2E smoke harness/m);
  assert.match(makefile, /\$\(LOAD_ENV\) ENV_FILE="\$\(ENV_FILE\)" npm run smoke:e2e/);
});

test("CI e2e-smoke writes local .env before launching the smoke harness", () => {
  const ci = readRepoFile(".github/workflows/ci.yml");
  const jobStart = ci.indexOf("  e2e-smoke:");
  assert.notEqual(jobStart, -1, "CI workflow must define the e2e-smoke job");
  const job = ci.slice(jobStart);

  const checkoutMatch = /- uses: actions\/checkout@[^\s]+/.exec(job);
  const checkoutIndex = checkoutMatch?.index ?? -1;
  const writeEnvStepIndex = job.indexOf("- name: Write local smoke env file");
  const writeEnvCommandIndex = job.indexOf("cat > .env <<EOF");
  const runSmokeStepIndex = job.indexOf("- name: Run Go API and web E2E smoke");
  const smokeCommandIndex = job.indexOf("run: npm run smoke:e2e");

  assert.ok(checkoutIndex >= 0, "fresh GitHub Actions checkout must happen in the e2e-smoke job");
  assert.ok(writeEnvStepIndex >= 0, "e2e-smoke job must write a local .env file");
  assert.ok(writeEnvCommandIndex >= 0, "e2e-smoke job must create .env with a heredoc");
  assert.ok(runSmokeStepIndex >= 0, "e2e-smoke job must have an explicit smoke run step");
  assert.ok(smokeCommandIndex >= 0, "e2e-smoke job must run npm run smoke:e2e");
  assert.ok(checkoutIndex < writeEnvStepIndex, ".env must be written after the fresh checkout");
  assert.ok(writeEnvCommandIndex < smokeCommandIndex, ".env must be written before npm run smoke:e2e");
  assert.ok(writeEnvStepIndex < runSmokeStepIndex, ".env step must precede the smoke run step");

  for (const variable of [
    "DATABASE_URL",
    "APERIO_NATS_URL",
    "APERIO_ENCRYPTION_KEY",
    "APERIO_AUTH_SECRET",
    "APERIO_WEB_ORIGIN",
    "NEXT_PUBLIC_CONNECT_API_BASE_URL",
    "NEXT_TELEMETRY_DISABLED"
  ]) {
    assert.match(job, new RegExp(`${variable}="\\$\\{${variable}\\}"`));
  }
});

test("smoke harness exports the canonical localhost route matrix and report sections", async () => {
  const smoke = await loadSmokeHarness();

  assert.equal(smoke.WEB_ORIGIN, "http://localhost:3000");
  assert.equal(smoke.API_ORIGIN, "http://127.0.0.1:4100");
  assert.deepEqual(smoke.EXPECTED_PORTS, {
    postgres: 5433,
    nats: 4222,
    natsMonitor: 8222,
    api: 4100,
    web: 3000
  });

  const routes = smoke.CANONICAL_ROUTES.map((route: { path: string }) => route.path);
  assert.deepEqual(routes, [
    "/",
    "/incidents",
    "/incidents/inc_demo_vendor_drive_response",
    "/findings",
    "/findings/fnd_demo_public_repo",
    "/connectors",
    "/siem-connectors",
    "/apps",
    "/apps/int_demo_github",
    "/shadow-it",
    "/shadow-it/oauth-apps",
    "/security",
    "/security/privileged-identities",
    "/settings",
    "/settings/organization"
  ]);
  assert.ok(
    smoke.CANONICAL_ROUTES.every(
      (route: { url: string; expectedText: string }) =>
        route.url.startsWith("http://localhost:3000/") || route.url === "http://localhost:3000"
    ),
    "browser route validation must use localhost:3000"
  );
  assert.equal(
    smoke.CANONICAL_ROUTES.some((route: { url: string }) => route.url.includes("127.0.0.1:3000")),
    false
  );
  assert.equal(
    smoke.isOAuthWellKnownMetadataRequest(
      "http://localhost:3000/.well-known/oauth-protected-resource/api/v1/mcp"
    ),
    true
  );
  assert.equal(
    smoke.isDirectProductApiV1BrowserRequest(
      "http://localhost:3000/.well-known/oauth-protected-resource/api/v1/mcp",
      "Fetch"
    ),
    false
  );
  assert.equal(
    smoke.isDirectProductApiV1BrowserRequest(
      "http://localhost:3000/api/v1/admin/reports/report-a/html",
      "Fetch"
    ),
    true
  );
  assert.equal(
    smoke.isDirectProductApiV1BrowserRequest(
      "http://localhost:3000/api/v1/admin/reports/report-a/html",
      "Document"
    ),
    false
  );

  const report = smoke.createInitialReport();
  for (const section of smoke.REQUIRED_REPORT_SECTIONS) {
    assert.ok(section in report, `report should include ${section}`);
  }
  assert.deepEqual(smoke.REQUIRED_REPORT_SECTIONS, [
    "serviceStatus",
    "health",
    "browser",
    "routes",
    "safeMutations",
    "workerSmokes",
    "redaction",
    "cleanup"
  ]);
});

test("worker smoke commands are bounded Go default smokes", async () => {
  const smoke = await loadSmokeHarness();

  assert.deepEqual(
    smoke.WORKER_SMOKE_COMMANDS.map((entry: { command: string; args: string[] }) => ({
      command: entry.command,
      args: entry.args
    })),
    [
      {
        command: "npm",
        args: ["run", "worker:ingestion", "--", "-once", "-limit", "1"]
      },
      {
        command: "npm",
        args: ["run", "worker:siem", "--", "-once", "-limit", "1"]
      }
    ]
  );
});

test("smoke harness exercises the SIEM connector browser CRUD flow", async () => {
  const smoke = await loadSmokeHarness();
  const report = smoke.createInitialReport();
  const harness = readRepoFile("scripts/smoke-e2e.mjs");

  assert.equal(report.browser.siemConnectors, null);
  assert.equal(
    report.safeMutations[0].surface,
    "/siem-connectors CRUD/test-ping/delete"
  );
  assert.match(harness, /async function runSiemConnectorCrudFlow/);
  assert.match(harness, /ListSiemDestinations/);
  assert.match(harness, /DeleteSiemDestination/);
  assert.match(harness, /worker:siem/);
  assert.doesNotMatch(harness, /worker:siem:go/);
});

test("browser launch startup failures clean up Chrome and temp profile", () => {
  const harness = readRepoFile("scripts/smoke-e2e.mjs");
  assert.match(harness, /async function launchBrowser\(report\)[\s\S]*try \{/);
  assert.match(harness, /catch \(error\)[\s\S]*await stopChildProcess\(browser, report\)/);
  assert.match(harness, /catch \(error\)[\s\S]*await fsp\.rm\(userDataDir, \{ recursive: true, force: true \}\)/);
});

test("smoke evidence redaction masks cookies, bearer tokens, passwords, and DSNs", async () => {
  const smoke = await loadSmokeHarness();
  const raw = [
    "Cookie: aperio_session=s3cr3t-cookie; other=value",
    "Authorization: Bearer secret-token",
    "password=DemoPass1234",
    "postgres://aperio:aperio@127.0.0.1:5433/aperio?sslmode=disable"
  ].join("\n");
  const redacted = smoke.redactEvidence(raw);

  assert.doesNotMatch(redacted, /s3cr3t-cookie/);
  assert.doesNotMatch(redacted, /secret-token/);
  assert.doesNotMatch(redacted, /DemoPass1234/);
  assert.doesNotMatch(redacted, /aperio:aperio@/);
  assert.match(redacted, /\[REDACTED_COOKIE\]/);
  assert.match(redacted, /\[REDACTED_BEARER\]/);
  assert.match(redacted, /password=\[REDACTED\]/);
  assert.match(redacted, /postgres:\/\/\[REDACTED_DSN\]@127\.0\.0\.1:5433/);
});

test("seed data includes E2E-critical shadow IT grants and local SIEM destination", () => {
  const seed = readRepoFile("scripts/seed.ts");

  assert.match(seed, /shadow-it/);
  assert.match(seed, /oauthAppGrant\.upsert/);
  assert.match(seed, /grant_demo_vendor_analytics_morgan/);
  assert.match(seed, /grant_demo_ci_deploy_breakglass/);
  assert.match(seed, /siemDestination\.upsert/);
  assert.match(seed, /siem_demo_json_file/);
  assert.match(seed, /JSON_FILE/);
  assert.match(seed, /saasIncident\.upsert/);
  assert.match(seed, /inc_demo_vendor_drive_response/);
  assert.match(seed, /saasResponseAction\.upsert/);
});
