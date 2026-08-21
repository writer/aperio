import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type IngestionRuleState =
  | "typescript-reference"
  | "go-parity"
  | "go-default"
  | "removable";

type IngestionRuleMatrix = {
  version: number;
  finalCutoverPlan?: {
    status: string;
    defaultsFlippedInThisFeature: boolean;
    fixture: string;
    localHarness?: string;
    goDefaultRequires?: string[];
  };
  unsupportedWorkPolicy?: {
    state: string;
    action: string;
    reason: string;
    tests: string[];
  };
  source: string;
  rules: Array<{
    ruleId: string;
    provider: string;
    state: IngestionRuleState;
    typescriptEventAliases: string[];
    typescriptPayloadPredicates: string[];
    goClaimedEventTypes: string[];
    fixtures: string[];
    tests: string[];
    cutoverBlockers: string[];
    goDefaultBlocked: boolean;
  }>;
};

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(readRepoFile(relativePath)) as T;
}

function sorted(values: Iterable<string>) {
  return [...values].sort((a, b) => a.localeCompare(b));
}

function goClaimAllowlistPairs(source: string) {
  const pairs = new Set<string>();
  const block = source.match(
    /var supportedIngestionEventTypes = map\[string\]\[\]string\{([\s\S]*?)\n\}/
  )?.[1];
  assert.ok(block, "Go worker must expose the final supported ingestion matrix");
  for (const match of block.matchAll(/"([^"]+)":\s*\{([\s\S]*?)\n\t\},/g)) {
    const provider = match[1];
    for (const eventType of match[2].matchAll(/"([^"]+)"/g)) {
      pairs.add(`${provider}:${eventType[1]}`);
    }
  }
  return sorted(pairs);
}

function filesUnder(relativeDir: string, predicate: (relativePath: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return readdirSync(absoluteDir).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry);
    const absolutePath = path.join(repoRoot, relativePath);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      return filesUnder(relativePath, predicate);
    }
    return predicate(relativePath) ? [relativePath] : [];
  });
}

const expectedRuleIds = [
  "atlassian.anonymous_access_enabled",
  "atlassian.org_admin_granted",
  "atlassian.public_space_created",
  "github.branch_protection_disabled",
  "github.deploy_key_added",
  "github.oauth_app_installed",
  "github.public_repository_created",
  "google_workspace.admin_external_recovery_email",
  "google_workspace.admin_mfa_not_enforced",
  "google_workspace.admin_role_granted",
  "google_workspace.email_forwarding_enabled",
  "google_workspace.external_sharing_enabled",
  "google_workspace.forwarding_delegate_send_as_combo",
  "google_workspace.legacy_mail_auth_used",
  "google_workspace.mailbox_delegation_granted",
  "google_workspace.risky_oauth_grant",
  "google_workspace.super_admin_granted",
  "ms365.conditional_access_disabled",
  "ms365.global_admin_granted",
  "ms365.guest_user_invited",
  "okta.admin_role_assigned",
  "okta.mfa_factor_reset",
  "okta.password_policy_weakened",
  "okta.suspicious_signin",
  "salesforce.admin_profile_assigned",
  "salesforce.connected_app_policy_weakened",
  "salesforce.report_exported",
  "slack.app_installed",
  "slack.external_shared_channel_created",
  "slack.mfa_disabled",
  "slack.workspace_invite_link_enabled"
];

test("ingestion rule matrix is fully unblocked for Go default", () => {
  const matrix = readJson<IngestionRuleMatrix>(
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json"
  );
  const matrixRuleIds = sorted(matrix.rules.map((rule) => rule.ruleId));

  assert.equal(matrix.finalCutoverPlan?.status, "ingestion-go-default-enforced");
  assert.equal(matrix.finalCutoverPlan?.defaultsFlippedInThisFeature, true);
  assert.match(matrix.source, /^internal\/ingestionworker\/worker\.go:/);
  assert.deepEqual(matrixRuleIds, expectedRuleIds, "matrix must enumerate every Go-owned detector rule");

  const seenProviders = new Set<string>();
  for (const rule of matrix.rules) {
    seenProviders.add(rule.provider);
    assert.equal(rule.state, "go-default", `${rule.ruleId} must be Go-default after cutover`);
    assert.equal(rule.goDefaultBlocked, false, `${rule.ruleId} must not block Go default`);
    assert.deepEqual(rule.cutoverBlockers, [], `${rule.ruleId} must not carry stale blockers`);
    assert.ok(rule.goClaimedEventTypes.length > 0, `${rule.ruleId} must have Go-claimed event types`);
    assert.ok(
      rule.fixtures.every((fixture) => fixture.startsWith("tests/fixtures/worker-parity/")),
      `${rule.ruleId} must use deterministic worker-parity fixtures`
    );
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_test.go"));
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_db_test.go"));
  }
  assert.deepEqual(sorted(seenProviders), [
    "ATLASSIAN",
    "GITHUB",
    "GOOGLE_WORKSPACE",
    "MICROSOFT_365",
    "OKTA",
    "SALESFORCE",
    "SLACK"
  ]);
});

test("Go ingestion supported-work allowlist matches only matrix-backed parity slices", () => {
  const matrix = readJson<IngestionRuleMatrix>(
    "tests/fixtures/worker-parity/ingestion-rule-matrix.json"
  );
  const goSource = readRepoFile("internal/ingestionworker/worker.go");

  const matrixClaimPairs = sorted(
    matrix.rules.flatMap((rule) =>
      rule.goClaimedEventTypes.map((eventType) => `${rule.provider}:${eventType}`)
    )
  );
  assert.deepEqual(goClaimAllowlistPairs(goSource), matrixClaimPairs);
  assert.equal(matrix.unsupportedWorkPolicy?.state, "final-no-fallback");
  assert.equal(matrix.unsupportedWorkPolicy?.action, "dead_letter_without_side_effects");
  assert.match(matrix.unsupportedWorkPolicy?.reason ?? "", /deleted TypeScript fallback/);
  assert.match(goSource, /errUnsupportedIngestionWork/);
  assert.match(goSource, /deadLetterUnsupported/);
  assert.doesNotMatch(goSource, /provider = '[^']+'\s+AND event_type IN/);

  for (const rule of matrix.rules) {
    assert.equal(rule.state, "go-default", `${rule.ruleId} claimed slices must be Go-default`);
    assert.ok(
      rule.fixtures.every((fixture) => fixture.startsWith("tests/fixtures/worker-parity/")),
      `${rule.ruleId} must use shared worker-parity fixtures`
    );
    assert.ok(rule.tests.some((testPath) => testPath.startsWith("tests/") && testPath.endsWith(".test.ts")));
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_test.go"));
    assert.ok(rule.tests.includes("internal/ingestionworker/worker_db_test.go"));
  }
});

test("unsuffixed ingestion commands run Go and the TypeScript runtime is absent", () => {
  const packageJson = readJson<{ scripts: Record<string, string> }>("package.json");
  const makefile = readRepoFile("Makefile");
  const ingestionCommand = packageJson.scripts["worker:ingestion"];

  assert.match(ingestionCommand, /node scripts\/dev-config\.mjs go-database-url/);
  assert.match(ingestionCommand, /node scripts\/dev-env\.mjs go run \.\/cmd\/ingestion-worker/);
  assert.doesNotMatch(ingestionCommand, /\btsx\b|workers\/ingestion-worker\.ts/);
  assert.equal(packageJson.scripts["worker:ingestion:go"], "npm run worker:ingestion --");

  assert.match(makefile, /worker-ingestion: require-env ## Run the Go ingestion worker/);
  assert.match(makefile, /worker-ingestion: require-env[\s\S]*go run \.\/cmd\/ingestion-worker \$\(GO_WORKER_ARGS\)/);
  assert.match(makefile, /worker-ingestion-go: worker-ingestion ## Alias for the Go ingestion worker/);
  assert.doesNotMatch(makefile, /npx tsx workers\/ingestion-worker\.ts/);

  assert.equal(existsSync(path.join(repoRoot, "workers", "ingestion-worker.ts")), false);
});

test("tests and executable scripts no longer import the deleted ingestion runtime", () => {
  const deletedRuntimeImport = /^\s*import(?:\s+type)?[\s\S]*?from\s+["']\.\.\/workers\/ingestion-worker["'];?/m;
  const deletedRuntimeExecution = /\btsx\s+workers\/ingestion-worker\.ts\b/;
  const executableSurfaces = [
    ...filesUnder("tests", (file) => file.endsWith(".test.ts") && file !== "tests/ingestion-parity-matrix.test.ts"),
    ...filesUnder("scripts", (file) => /\.(?:mjs|ts)$/.test(file))
  ];

  const offenders = executableSurfaces.filter((file) => deletedRuntimeImport.test(readRepoFile(file)));
  assert.deepEqual(offenders, [], "deleted TypeScript ingestion runtime must not remain a test or script oracle");
  assert.equal(deletedRuntimeExecution.test(readRepoFile("package.json")), false);
  assert.equal(deletedRuntimeExecution.test(readRepoFile("Makefile")), false);
});
