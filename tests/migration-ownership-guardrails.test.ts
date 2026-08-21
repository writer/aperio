import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const matrixPath = "tests/fixtures/migration-ownership/migration-matrix.json";

const allowedStates = new Set([
  "go-default",
  "removed",
  "allowed-typescript",
  "validation-tooling"
]);

type MatrixEntry = {
  id: string;
  state: string;
  covers: string[];
  owner: string;
  rationale: string;
  evidence: string[];
  blockedBy?: string;
};

type MigrationMatrix = {
  version: number;
  entries: MatrixEntry[];
};

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(readRepoFile(relativePath)) as T;
}

function loadMatrix() {
  return readJson<MigrationMatrix>(matrixPath);
}

function packageScripts() {
  return readJson<{ scripts: Record<string, string> }>("package.json").scripts;
}

function filesUnder(relativeDir: string, predicate: (relativePath: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!existsSync(absoluteDir)) {
    return [];
  }
  const entries = readdirSync(absoluteDir);
  return entries.flatMap((entry) => {
    const absolutePath = path.join(absoluteDir, entry);
    const relativePath = path.join(relativeDir, entry);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) {
      return filesUnder(relativePath, predicate);
    }
    return predicate(relativePath) ? [relativePath] : [];
  });
}

function makeTargets() {
  const makefile = readRepoFile("Makefile");
  const targets = new Set<string>();
  for (const match of makefile.matchAll(/^\.PHONY:\s+(.+)$/gm)) {
    for (const target of match[1].trim().split(/\s+/)) {
      targets.add(target);
    }
  }
  return [...targets].sort();
}

function makeTargetDependencies(makefile: string, target: string) {
  const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = makefile.match(new RegExp(`^${escapedTarget}:\\s*([^#\\n]*)`, "m"));
  assert.ok(match, `expected Makefile target ${target}`);
  return match[1].trim().split(/\s+/).filter(Boolean);
}

function makeTargetBlock(makefile: string, target: string) {
  const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = makefile.match(new RegExp(`^${escapedTarget}:.*(?:\\n\\t.*)*`, "m"));
  assert.ok(match, `expected Makefile target ${target}`);
  return match[0];
}

function compatRoutes() {
  const source = readRepoFile("internal/bootstrap/compat_api.go");
  const block = source.match(/var compatRouteTemplates = map\[string\]struct\{\}\{([\s\S]*?)\n\}/);
  assert.ok(block, "expected compatRouteTemplates map");
  return [...block[1].matchAll(/"([^"]+)":\s*\{\}/g)].map((match) => match[1]).sort();
}

function inventoryItems() {
  const packageItems = Object.keys(packageScripts()).map((script) => `package-script:${script}`);
  const makeItems = makeTargets().map((target) => `make-target:${target}`);
  const repoFiles = [
    ".env.example",
    "docker-compose.yml",
    ...filesUnder(".github/workflows", (file) => /\.ya?ml$/.test(file)),
    ...filesUnder("scripts", (file) => /\.(?:mjs|ts)$/.test(file)),
    ...filesUnder("cmd", (file) => file.endsWith(".go")),
    ...filesUnder("workers", (file) => file.endsWith(".ts")),
    ...filesUnder("apps/mcp", (file) => file.endsWith(".ts")),
    ...filesUnder("internal/bootstrap", (file) => file.endsWith(".go")),
    ...filesUnder("internal/detection", (file) => /\.(?:go|ya?ml|json|md)$/.test(file)),
    ...filesUnder("internal/ingestionworker", (file) => file.endsWith(".go")),
    ...filesUnder("internal/mcpbroker", (file) => file.endsWith(".go")),
    ...filesUnder("internal/siemdispatcher", (file) => file.endsWith(".go")),
    ...filesUnder("proto", (file) => file.endsWith(".proto")),
    ...filesUnder(
      "packages/connect/src",
      (file) => file.endsWith(".ts") && !file.includes(`${path.sep}gen${path.sep}`)
    ),
    ...filesUnder("packages/shared/src", (file) => file.endsWith(".ts"))
  ].map((file) => `repo-file:${file}`);
  const routeItems = compatRoutes().map((route) => `compat-route:${route}`);
  const validatorItems = [
    "validator:typecheck",
    "validator:api-tests",
    "validator:db-validate",
    "validator:web-build",
    "validator:go-tests",
    "validator:db-backed-go-tests",
    "validator:proto-check",
    "validator:prod-audit",
    "validator:leak-check",
    "validator:frontend-legacy-api-auth-guardrail",
    "validator:worker-command-guardrail",
    "validator:migration-ownership-guardrail",
    "validator:worker-smoke",
    "validator:e2e-smoke",
    "validator:secret-safe-merge-evidence"
  ];

  return [...packageItems, ...makeItems, ...repoFiles, ...routeItems, ...validatorItems].sort();
}

function patternToRegExp(pattern: string) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}

function entryCovers(entry: MatrixEntry, item: string) {
  return entry.covers.some((pattern) => pattern === item || patternToRegExp(pattern).test(item));
}

function entriesFor(matrix: MigrationMatrix, item: string) {
  return matrix.entries.filter((entry) => entryCovers(entry, item));
}

function stateFor(matrix: MigrationMatrix, item: string) {
  const matches = entriesFor(matrix, item);
  assert.equal(matches.length, 1, `${item} should map to exactly one matrix entry`);
  return matches[0].state;
}

function evidenceIncludes(entry: MatrixEntry, expected: string) {
  return entry.evidence.some((evidence) => evidence.includes(expected));
}

const deletedRuntimePaths = [
  "workers/ingestion-worker.ts",
  "workers/siem-dispatcher.ts",
  "apps/mcp/src/server.ts"
];

const deletedRuntimePathPattern = new RegExp(
  deletedRuntimePaths.map((entrypoint) => entrypoint.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")
);

const typescriptRuntimeExecutionPattern = new RegExp(
  String.raw`\b(?:npx\s+)?(?:tsx|ts-node|node)\b[^\n]*(?:${deletedRuntimePaths
    .map((entrypoint) => entrypoint.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|")})`
);

const deletedRuntimeImportPattern =
  /from\s+["']\.\.\/(?:workers\/(?:ingestion-worker|siem-dispatcher)|apps\/mcp\/src\/server)(?:\.ts)?["']/;

const hiddenSelectorPattern =
  /\b(?:APERIO|A2A|MCP|WORKER|SIEM|INGESTION)[A-Z0-9_]*(?:TS|TYPESCRIPT|NODE|RUNTIME|FALLBACK|LEGACY)[A-Z0-9_]*\b[^\n]*(?:tsx|ts-node|typescript|workers\/|apps\/mcp\/src\/server\.ts)/i;

const transitionalStatePattern =
  /\b(?:typescript-reference|go-parity|removable|out-of-scope-this-mission)\b/;

const transitionalDocPattern =
  /\b(?:Go worker transition|explicit Go transition|TypeScript parity\/reference|worker:ingestion:go|worker:siem:go)\b/i;

type AuditSurface = {
  vector: string;
  path: string;
  content: string;
};

function findRuntimeOwnershipViolations(surface: AuditSurface) {
  const violations: string[] = [];
  if (
    surface.vector === "runtime-file" &&
    deletedRuntimePaths.includes(surface.path.replace(/\\/g, "/"))
  ) {
    violations.push("deleted TypeScript runtime file reintroduced");
  }
  if (deletedRuntimePathPattern.test(surface.content)) {
    violations.push("deleted TypeScript runtime path referenced");
  }
  if (typescriptRuntimeExecutionPattern.test(surface.content)) {
    violations.push("TypeScript backend/worker/MCP runtime execution command");
  }
  if (deletedRuntimeImportPattern.test(surface.content)) {
    violations.push("deleted TypeScript runtime imported as a hidden oracle");
  }
  if (hiddenSelectorPattern.test(surface.content)) {
    violations.push("hidden selector can choose a TypeScript runtime");
  }
  if (surface.vector === "ownership-matrix" && transitionalStatePattern.test(surface.content)) {
    violations.push("transitional ownership matrix state");
  }
  if (surface.vector === "user-facing-docs" && transitionalDocPattern.test(surface.content)) {
    violations.push("transition-era user-facing command documentation");
  }
  return violations.map((message) => `${surface.vector}:${surface.path}: ${message}`);
}

function markdownFiles() {
  return [
    "README.md",
    ...filesUnder("droid-wiki", (file) => file.endsWith(".md"))
  ];
}

test("migration ownership matrix covers every generated surface exactly once", () => {
  const matrix = loadMatrix();
  assert.equal(matrix.version, 1);
  assert.ok(matrix.entries.length > 0, "expected matrix entries");

  for (const entry of matrix.entries) {
    assert.ok(entry.id, "matrix entry id is required");
    assert.ok(allowedStates.has(entry.state), `${entry.id} has invalid state ${entry.state}`);
    assert.ok(entry.owner, `${entry.id} owner is required`);
    assert.ok(entry.rationale, `${entry.id} rationale is required`);
    assert.ok(entry.covers.length > 0, `${entry.id} must cover at least one surface`);
    assert.ok(entry.evidence.length > 0, `${entry.id} must include evidence`);
    assert.equal(
      Object.prototype.hasOwnProperty.call(entry, "rollback"),
      false,
      `${entry.id} must not retain transition-era rollback metadata`
    );
    assert.doesNotMatch(
      JSON.stringify(entry),
      transitionalStatePattern,
      `${entry.id} must not use transition-era ownership states`
    );
  }

  const uncovered: string[] = [];
  const duplicated: string[] = [];
  for (const item of inventoryItems()) {
    const matches = entriesFor(matrix, item);
    if (matches.length === 0) {
      uncovered.push(item);
    } else if (matches.length > 1) {
      duplicated.push(`${item} -> ${matches.map((entry) => entry.id).join(", ")}`);
    }
  }
  assert.deepEqual(uncovered, [], "every migration-relevant surface needs a matrix state");
  assert.deepEqual(duplicated, [], "every migration-relevant surface needs exactly one matrix state");
});

test("ingestion and SIEM defaults are Go-owned", () => {
  const matrix = loadMatrix();
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");

  assert.match(scripts["worker:ingestion"], /go run \.\/cmd\/ingestion-worker/);
  assert.match(scripts["worker:siem"], /go run \.\/cmd\/siem-dispatcher/);
  assert.doesNotMatch(scripts["worker:ingestion"], /\btsx\b|workers\/ingestion-worker\.ts/);
  assert.doesNotMatch(scripts["worker:siem"], /\btsx\b|workers\/siem-dispatcher\.ts/);

  assert.match(makefile, /go run \.\/cmd\/ingestion-worker/);
  assert.match(makefile, /go run \.\/cmd\/siem-dispatcher/);
  assert.doesNotMatch(makefile, /npx tsx workers\/ingestion-worker\.ts/);
  assert.doesNotMatch(makefile, /npx tsx workers\/siem-dispatcher\.ts/);
  assert.equal(scripts["worker:ingestion:go"], "npm run worker:ingestion --");
  assert.equal(scripts["worker:siem:go"], "npm run worker:siem --");
  assert.match(scripts["smoke:workers:go"], /worker:ingestion -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /worker:siem -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /smoke:siem:adapters/);

  for (const item of [
    "package-script:worker:ingestion",
    "make-target:worker-ingestion",
    "make-target:worker-ingestion-go",
    "repo-file:cmd/ingestion-worker/main.go",
    "repo-file:internal/ingestionworker/worker.go"
  ]) {
    assert.equal(stateFor(matrix, item), "go-default", `${item} must be Go default`);
  }

  assert.equal(
    stateFor(matrix, "package-script:worker:ingestion:go"),
    "go-default",
    "suffixed ingestion npm command must be a strict alias to the Go default"
  );
  assert.equal(
    stateFor(matrix, "repo-file:workers/ingestion-worker.ts"),
    "removed",
    "deleted ingestion runtime must be represented as removed"
  );

  for (const item of [
    "package-script:worker:siem",
    "package-script:worker:siem:go",
    "make-target:worker-siem",
    "make-target:worker-siem-go",
    "repo-file:cmd/siem-dispatcher/main.go",
    "repo-file:internal/siemdispatcher/dispatcher.go"
  ]) {
    assert.equal(stateFor(matrix, item), "go-default", `${item} must be Go default`);
  }

  assert.equal(
    stateFor(matrix, "repo-file:workers/siem-dispatcher.ts"),
    "removed",
    "deleted SIEM runtime must be represented as removed"
  );
  assert.equal(stateFor(matrix, "package-script:smoke:workers:go"), "go-default");
  assert.equal(stateFor(matrix, "make-target:smoke-workers-go"), "go-default");
});

test("MCP default is Go-owned and TypeScript runtime is removed", () => {
  const matrix = loadMatrix();
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");

  assert.match(scripts["mcp:broker"], /go run \.\/cmd\/mcp-broker/);
  assert.match(scripts["mcp:broker"], /DATABASE_URL="?\$\(node scripts\/dev-config\.mjs go-database-url\)"?/);
  assert.doesNotMatch(scripts["mcp:broker"], /\btsx\b|\bts-node\b|apps\/mcp\/src\/server\.ts/);

  const makeMCP = makeTargetBlock(makefile, "mcp");
  assert.match(makeMCP, /go run \.\/cmd\/mcp-broker/);
  assert.doesNotMatch(makeMCP, /\bnpx\s+tsx\b|\btsx\b|apps\/mcp\/src\/server\.ts/);
  assert.equal(
    existsSync(path.join(repoRoot, "apps/mcp/src/server.ts")),
    false,
    "TypeScript MCP backend runtime must be deleted"
  );

  for (const item of [
    "package-script:mcp:broker",
    "make-target:mcp",
    "repo-file:cmd/mcp-broker/main.go",
    "repo-file:internal/mcpbroker/server.go",
    "repo-file:internal/mcpbroker/tools.go"
  ]) {
    assert.equal(stateFor(matrix, item), "go-default", `${item} must be Go default`);
  }
  assert.equal(
    stateFor(matrix, "repo-file:apps/mcp/src/server.ts"),
    "removed",
    "deleted MCP runtime must be represented as removed"
  );
});

test("API and dev-stack backend commands are Go-owned", () => {
  const matrix = loadMatrix();
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");
  const devScript = readRepoFile("scripts/dev.mjs");

  assert.match(scripts["dev:connect"], /^go run \.\/cmd\/aperio$/);
  assert.equal(stateFor(matrix, "package-script:dev:connect"), "go-default");
  assert.equal(stateFor(matrix, "package-script:dev"), "go-default");
  assert.equal(stateFor(matrix, "package-script:dev:app"), "go-default");
  assert.match(devScript, /start\("connect", "go", \["run", "\.\/cmd\/aperio"\](?:, \{[^}]*\})?\)/);
  assert.doesNotMatch(devScript, /\btsx\b[^\n]*(?:server|api)|typescript.*backend/i);

  const makeDev = makeTargetBlock(makefile, "dev");
  const makeAPI = makeTargetBlock(makefile, "api");
  const makeRunAPI = makeTargetBlock(makefile, "_run-api");
  assert.match(makeDev, /_run-api/);
  assert.match(makeAPI, /_run-api/);
  assert.match(makeRunAPI, /go run \.\/cmd\/aperio/);
  for (const item of ["make-target:dev", "make-target:api", "make-target:_run-api"]) {
    assert.equal(stateFor(matrix, item), "go-default", `${item} must be Go-owned`);
  }
});

test("user-facing command docs and Make help are final Go-default", () => {
  const readme = readRepoFile("README.md");
  const makefile = readRepoFile("Makefile");

  assert.match(readme, /npm run worker:ingestion\s+# Go ingestion worker/);
  assert.match(readme, /npm run worker:siem\s+# Go SIEM dispatcher/);
  assert.match(readme, /npm run mcp:broker\s+# Go stdio MCP broker/);
  assert.match(readme, /Remaining TypeScript is limited to the Next\.js frontend, generated clients\/contracts, tests, Prisma, and local tooling\./);

  for (const doc of markdownFiles()) {
    const content = readRepoFile(doc);
    assert.deepEqual(
      findRuntimeOwnershipViolations({
        vector: "user-facing-docs",
        path: doc,
        content
      }),
      [],
      `${doc} must not document deleted TypeScript backend/worker/MCP runtimes`
    );
  }

  for (const target of ["worker-ingestion", "worker-siem", "mcp"]) {
    const block = makeTargetBlock(makefile, target);
    assert.match(block, /## Run the Go /, `${target} help must describe the Go default`);
    assert.doesNotMatch(block, /TypeScript|reference|fallback|transition/i);
  }
});

test("guardrail negative coverage protects every TypeScript runtime reintroduction vector", () => {
  const negativeCases: AuditSurface[] = [
    {
      vector: "runtime-file",
      path: "workers/ingestion-worker.ts",
      content: "export async function run() {}"
    },
    {
      vector: "package-script",
      path: "package.json:scripts.worker:ingestion",
      content: '"worker:ingestion": "tsx workers/ingestion-worker.ts"'
    },
    {
      vector: "make-target",
      path: "Makefile:worker-siem",
      content: "worker-siem:\n\tnpx tsx workers/siem-dispatcher.ts"
    },
    {
      vector: "ci-workflow",
      path: ".github/workflows/ci.yml",
      content: "run: npx tsx workers/siem-dispatcher.ts --once"
    },
    {
      vector: "ownership-matrix",
      path: matrixPath,
      content: '{"state":"typescript-reference","covers":["package-script:worker:siem"]}'
    },
    {
      vector: "user-facing-docs",
      path: "README.md",
      content: "Run worker:ingestion:go during the Go worker transition."
    },
    {
      vector: "wrapper-script",
      path: "scripts/dev.mjs",
      content: 'spawn("tsx", ["apps/mcp/src/server.ts"])'
    },
    {
      vector: "hidden-selector",
      path: "scripts/dev-env.mjs",
      content: 'if (process.env.APERIO_WORKER_RUNTIME === "typescript") command = "tsx workers/ingestion-worker.ts";'
    },
    {
      vector: "test-oracle-import",
      path: "tests/worker-oracle.test.ts",
      content: ['import { run } from "..', 'workers/ingestion-worker";'].join("/")
    },
    {
      vector: "executable-artifact",
      path: "dist/worker.js",
      content: 'require("tsx"); require("./workers/siem-dispatcher.ts");'
    }
  ];

  for (const negative of negativeCases) {
    assert.notDeepEqual(
      findRuntimeOwnershipViolations(negative),
      [],
      `${negative.vector} negative case must be rejected`
    );
  }

  const realSurfaces: AuditSurface[] = [
    {
      vector: "package-script",
      path: "package.json",
      content: JSON.stringify(packageScripts(), null, 2)
    },
    { vector: "make-target", path: "Makefile", content: readRepoFile("Makefile") },
    ...filesUnder(".github/workflows", (file) => /\.ya?ml$/.test(file)).map((file) => ({
      vector: "ci-workflow",
      path: file,
      content: readRepoFile(file)
    })),
    ...filesUnder("scripts", (file) => /\.(?:mjs|ts)$/.test(file)).map((file) => ({
      vector: "wrapper-script",
      path: file,
      content: readRepoFile(file)
    }))
  ];

  const violations = realSurfaces.flatMap(findRuntimeOwnershipViolations);
  assert.deepEqual(violations, [], "real command, CI, and wrapper surfaces must be free of TS runtime selectors");
});

test("remaining TypeScript inventory is categorized as frontend generated tests or tooling", () => {
  const tsFiles = [
    ...filesUnder("apps", (file) => /\.(?:ts|tsx|mts|cts)$/.test(file)),
    ...filesUnder("packages", (file) => /\.(?:ts|tsx|mts|cts)$/.test(file)),
    ...filesUnder("scripts", (file) => /\.(?:ts|tsx|mts|cts)$/.test(file)),
    ...filesUnder("tests", (file) => /\.(?:ts|tsx|mts|cts)$/.test(file)),
    ...filesUnder("workers", (file) => /\.(?:ts|tsx|mts|cts)$/.test(file))
  ].sort();

  const classified = new Map<string, string>();
  for (const file of tsFiles) {
    if (file.startsWith("apps/web/")) {
      classified.set(file, "frontend");
    } else if (file.startsWith("packages/connect/src/gen/")) {
      classified.set(file, "generated client/contract");
    } else if (file === "packages/connect/src/client.ts") {
      classified.set(file, "frontend Connect client");
    } else if (file.startsWith("packages/shared/src/")) {
      classified.set(file, "shared frontend/test contract");
    } else if (file.startsWith("packages/security/src/")) {
      classified.set(file, "local security tooling/test helper");
    } else if (file === "packages/db/src/client.ts") {
      classified.set(file, "Prisma/local tooling");
    } else if (file.startsWith("tests/")) {
      classified.set(file, "tests");
    } else if (file.startsWith("scripts/")) {
      classified.set(file, "local validation tooling");
    } else if (file === "workers/event-bus.ts" || file === "workers/telemetry.ts") {
      classified.set(file, "validation helper");
    }
  }

  const unclassified = tsFiles.filter((file) => !classified.has(file));
  assert.deepEqual(unclassified, [], "every TypeScript file must have an allowed final category");
  for (const forbidden of deletedRuntimePaths) {
    assert.equal(tsFiles.includes(forbidden), false, `${forbidden} must remain absent`);
  }
  assert.equal(
    stateFor(loadMatrix(), "repo-file:packages/shared/src/security.ts"),
    "allowed-typescript",
    "shared TypeScript contracts must be explicitly classified as allowed TypeScript"
  );
});

test("executable artifact audit finds no backend TypeScript remnants", () => {
  const packageJson = readJson<{ scripts: Record<string, string>; bin?: Record<string, string> | string }>(
    "package.json"
  );
  const executableSurfaces: AuditSurface[] = [
    {
      vector: "package-script",
      path: "package.json:scripts",
      content: JSON.stringify(packageJson.scripts, null, 2)
    },
    {
      vector: "package-bin",
      path: "package.json:bin",
      content: JSON.stringify(packageJson.bin ?? {}, null, 2)
    },
    { vector: "make-target", path: "Makefile", content: readRepoFile("Makefile") },
    ...filesUnder(".github/workflows", (file) => /\.ya?ml$/.test(file)).map((file) => ({
      vector: "ci-workflow",
      path: file,
      content: readRepoFile(file)
    })),
    ...filesUnder("scripts", (file) => /\.(?:mjs|ts|sh)$/.test(file)).map((file) => ({
      vector: "wrapper-script",
      path: file,
      content: readRepoFile(file)
    }))
  ];

  assert.deepEqual(
    executableSurfaces.flatMap(findRuntimeOwnershipViolations),
    [],
    "executable scripts, bins, wrappers, CI commands, and Make/package commands must not execute deleted TypeScript runtimes"
  );
  assert.deepEqual(
    filesUnder("workers", (file) => file.endsWith(".ts")).sort(),
    ["workers/event-bus.ts", "workers/telemetry.ts"],
    "workers/ may contain only explicitly allowed TypeScript validation helpers"
  );
  assert.equal(existsSync(path.join(repoRoot, "apps/mcp/src/server.ts")), false);
});

test("frontend legacy API and browser auth guardrails are registered as merge gates", () => {
  const matrix = loadMatrix();
  const guardrail = entriesFor(matrix, "validator:frontend-legacy-api-auth-guardrail")[0];
  assert.equal(guardrail.state, "validation-tooling");
  assert.ok(evidenceIncludes(guardrail, "tests/auth-client-cleanup.test.ts"));

  const source = readRepoFile("tests/auth-client-cleanup.test.ts");
  assert.match(source, /localStorage/);
  assert.match(source, /aperio\\\.theme/);
  assert.match(source, /Authorization/);
  assert.match(source, /Bearer/);
  assert.match(source, /callApi/);
  assert.match(source, /\\\/api\\\/v1\\\//);
});

test("shared parity fixtures gate every Go worker runtime surface", () => {
  const matrix = loadMatrix();
  const goWorkerEntries = matrix.entries.filter(
    (entry) =>
      entry.state === "go-default" &&
      entry.covers.some((item) => /internal\/(?:ingestionworker|siemdispatcher)/.test(item))
  );
  assert.ok(goWorkerEntries.length > 0, "expected Go worker runtime entries");

  for (const entry of goWorkerEntries) {
    assert.ok(
      entry.evidence.some((evidence) => evidence.startsWith("fixture:tests/fixtures/worker-parity/")),
      `${entry.id} must cite a shared worker parity fixture`
    );
  }

  const requiredFixtures = [
    {
      path: "tests/fixtures/worker-parity/github-public-repository.json",
      tsTest: "tests/github-rules.test.ts",
      goTest: "internal/ingestionworker/worker_test.go",
      requiredKeys: ["positive", "negative", "disabledCheck"]
    },
    {
      path: "tests/fixtures/worker-parity/slack-mfa-disabled.json",
      tsTest: "tests/slack-rules.test.ts",
      goTest: "internal/ingestionworker/worker_test.go",
      requiredKeys: ["positive", "alias", "negative", "disabledCheck"]
    },
    {
      path: "tests/fixtures/worker-parity/siem-finding-delivery.json",
      tsTest: "tests/siem-dispatcher.test.ts",
      goTest: "internal/siemdispatcher/dispatcher_test.go",
      requiredKeys: ["payload", "expectedDeliveryKey", "reopenedSourceEventId"]
    }
  ];

  for (const fixture of requiredFixtures) {
    assert.ok(existsSync(path.join(repoRoot, fixture.path)), `${fixture.path} should exist`);
    const parsed = readJson<Record<string, unknown>>(fixture.path);
    for (const key of fixture.requiredKeys) {
      assert.ok(key in parsed, `${fixture.path} should include ${key}`);
    }
    assert.match(readRepoFile(fixture.tsTest), new RegExp(path.basename(fixture.path)));
    assert.match(readRepoFile(fixture.goTest), new RegExp(path.basename(fixture.path)));
  }
});

test("aggregate verifier commands cover the VAL-GATE-010 local gates", () => {
  const scripts = packageScripts();
  const makefile = readRepoFile("Makefile");
  const npmVerify = scripts.verify;
  const makeVerify = makeTargetBlock(makefile, "verify");
  const makeVerifyDependencies = makeTargetDependencies(makefile, "verify");

  assert.ok(npmVerify, "npm run verify must be defined");
  assert.doesNotMatch(npmVerify, /\bmake\s+verify\b/, "npm verify must not recurse into make verify");
  assert.doesNotMatch(makeVerify, /\bnpm run verify\b/, "make verify must not recurse into npm run verify");

  const npmRequiredGates: Array<[string, RegExp]> = [
    ["TypeScript typecheck", /\bnpm run typecheck\b/],
    ["API tests", /\bnpm run test:api\b/],
    ["Prisma validate", /\bnpm run db:validate\b/],
    ["Go tests", /\bnpm run (?:test:go|verify:go)\b/],
    ["DB-backed Go tests", /\bmake test-go-db\b/],
    ["lint", /\bmake lint\b/],
    ["proto/generated-client drift", /\bnpm run (?:proto:check|verify:go)\b/],
    ["web build", /\b(?:npm run build:web|make build-web)\b/],
    ["migration guardrails", /\b(?:npm run guardrails:migration|make guardrails-migration)\b/],
    ["bounded Go worker smoke", /\b(?:npm run smoke:workers:go|make smoke-workers-go)\b/],
    ["E2E smoke", /\b(?:npm run smoke:e2e|make smoke-e2e)\b/],
    ["production audit", /\bnpm run audit:prod\b/],
    ["leak check", /\bnpm run leak:check\b/]
  ];
  for (const [gate, pattern] of npmRequiredGates) {
    assert.match(npmVerify, pattern, `npm run verify must cover ${gate}`);
  }

  const requiredMakeTargets = [
    "typecheck",
    "test-api",
    "db-validate",
    "test-go",
    "test-go-db",
    "lint",
    "generate-check",
    "build-web",
    "guardrails-migration",
    "smoke-workers-go",
    "smoke-e2e",
    "audit",
    "leak-check"
  ];
  for (const target of requiredMakeTargets) {
    assert.ok(makeVerifyDependencies.includes(target), `make verify must include ${target}`);
  }
});

test("validator and CI gates include contracts, audit, worker smoke, and secret hygiene", () => {
  const matrix = loadMatrix();
  const scripts = packageScripts();
  const ci = readRepoFile(".github/workflows/ci.yml");
  const contracts = readRepoFile(".github/workflows/contracts.yml");
  const leakCheck = readRepoFile(".github/workflows/leak-check.yml");
  const droidReview = readRepoFile(".github/workflows/droid-review.yml");

  assert.match(scripts["guardrails:migration"], /migration-ownership-guardrails\.test\.ts/);
  assert.match(scripts["guardrails:migration"], /auth-client-cleanup\.test\.ts/);
  assert.match(scripts["guardrails:migration"], /worker-command-guardrails\.test\.ts/);
  assert.match(scripts["guardrails:migration"], /e2e-smoke-contract\.test\.ts/);
  assert.match(scripts["guardrails:migration"], /droid-review-preflight\.test\.ts/);
  assert.match(scripts["smoke:workers:go"], /worker:ingestion -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /worker:siem -- -once -limit 1/);
  assert.match(scripts["smoke:workers:go"], /smoke:siem:adapters/);

  for (const item of [
    "validator:typecheck",
    "validator:api-tests",
    "validator:db-validate",
    "validator:web-build",
    "validator:go-tests",
    "validator:db-backed-go-tests",
    "validator:proto-check",
    "validator:prod-audit",
    "validator:leak-check",
    "validator:migration-ownership-guardrail",
    "validator:worker-smoke",
    "validator:e2e-smoke",
    "validator:secret-safe-merge-evidence"
  ]) {
    assert.equal(entriesFor(matrix, item).length, 1, `${item} should be represented in matrix gates`);
  }
  const e2eEntry = entriesFor(matrix, "validator:e2e-smoke")[0];
  assert.equal(e2eEntry.state, "validation-tooling");
  assert.equal(e2eEntry.blockedBy, undefined);
  assert.ok(evidenceIncludes(e2eEntry, "tests/e2e-smoke-contract.test.ts"));
  assert.ok(evidenceIncludes(e2eEntry, "npm run smoke:e2e"));

  assert.match(ci, /npm run guardrails:migration/);
  assert.match(ci, /npm run smoke:workers:go/);
  assert.match(ci, /npm run typecheck/);
  assert.match(ci, /npm run test:api/);
  assert.match(ci, /npm run db:validate/);
  assert.match(ci, /npm run build:web/);
  assert.match(ci, /npm run audit:prod/);
  assert.match(ci, /npm run leak:check/);
  assert.match(ci, /npm run smoke:e2e/);
  assert.match(ci, /make lint/);
  assert.match(ci, /needs: \[verify-shard, go-connect, e2e-smoke\]/);
  assert.match(ci, /go test \.\/\.\.\./);
  assert.match(contracts, /buf\/cmd\/buf@v1\.59\.0 lint/);
  assert.match(contracts, /buf\/cmd\/buf@v1\.59\.0 breaking/);
  assert.match(contracts, /git diff --exit-code -- gen packages\/connect\/src\/gen/);
  assert.match(leakCheck, /npm run leak:check/);
  assert.match(droidReview, /github_token:\s*\$\{\{\s*github\.token\s*\}\}/);

  execFileSync("git", ["check-ignore", "-q", ".env"], { cwd: repoRoot });
  const envStatus = execFileSync("git", ["status", "--porcelain", "--", ".env"], {
    cwd: repoRoot,
    encoding: "utf8"
  }).trim();
  assert.equal(envStatus, "", ".env must remain ignored and uncommitted");
});
