import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL, fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

async function loadPreflight() {
  return import(pathToFileURL(path.join(repoRoot, "scripts/droid-review-preflight.mjs")).href) as Promise<{
    buildPreflightReport: (input: {
      base?: string;
      head?: string;
      changedFiles: string[];
    }) => {
      result: {
        run_droid_review: string;
        review_model: string;
        review_reason: string;
        risk_categories: Array<{ id: string; label: string; file_count: number; files: string[] }>;
        probe_plan: string[];
      };
      markdown: string;
    };
  }>;
}

function semverAtLeast(version: string, minimum: string): boolean {
  const parse = (value: string) => {
    const match = value.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
    if (!match) return null;
    return [Number(match[1]), Number(match[2]), Number(match[3])] as const;
  };
  const left = parse(version);
  const right = parse(minimum);
  if (!left || !right) return false;
  if (left[0] !== right[0]) return left[0] > right[0];
  if (left[1] !== right[1]) return left[1] > right[1];
  return left[2] >= right[2];
}

test("Droid preflight treats Go SIEM and MCP runtime paths as high-risk review surfaces", async () => {
  const preflight = await loadPreflight();
  const changedFiles = [
    "cmd/siem-dispatcher/main.go",
    "internal/siemdispatcher/dispatcher.go",
    "cmd/mcp-broker/main.go",
    "internal/mcpbroker/server.go"
  ];
  const { result, markdown } = preflight.buildPreflightReport({
    base: "origin/main",
    head: "HEAD",
    changedFiles
  });

  assert.equal(result.run_droid_review, "true");
  assert.equal(result.review_model, "claude-sonnet-4-6");
  assert.match(result.review_reason, /Agents\/remediation\/MCP\/SIEM/);

  const category = result.risk_categories.find((entry) => entry.id === "agents_remediation_mcp_siem");
  assert.ok(category, "Go SIEM/MCP runtime changes must enter the high-risk category");
  assert.equal(category.label, "Agents/remediation/MCP/SIEM");
  assert.equal(category.file_count, changedFiles.length);
  assert.deepEqual(category.files, changedFiles);
  assert.ok(
    result.probe_plan.some((entry) => entry.includes("SIEM dispatch") && entry.includes("MCP exposure")),
    "high-risk SIEM/MCP changes should receive the SIEM/MCP probe plan"
  );
  assert.match(markdown, /Agents\/remediation\/MCP\/SIEM: 4 file\(s\)/);
});

test("Droid preflight preserves legacy Agents/remediation/MCP/SIEM high-risk patterns", async () => {
  const preflight = await loadPreflight();
  const changedFiles = [
    "apps/api/src/routes/agents.ts",
    "apps/api/src/remediation/slack.ts",
    "apps/mcp/package.json",
    "workers/siem-dispatcher.ts",
    "packages/shared/src/siem-destination.ts"
  ];
  const { result } = preflight.buildPreflightReport({
    base: "origin/main",
    head: "HEAD",
    changedFiles
  });

  assert.equal(result.review_model, "claude-sonnet-4-6");
  assert.deepEqual(
    result.risk_categories.find((entry) => entry.id === "agents_remediation_mcp_siem")?.files,
    changedFiles
  );
});

test("Dependency lock keeps esbuild at or above the patched baseline", () => {
  const lock = JSON.parse(readRepoFile("package-lock.json")) as {
    packages?: Record<string, { version?: string }>;
  };
  const version = lock.packages?.["node_modules/esbuild"]?.version ?? "";
  assert.notEqual(version, "", "package-lock must contain node_modules/esbuild version");
  assert.ok(
    semverAtLeast(version, "0.28.1"),
    `esbuild version ${version} is below required patched baseline 0.28.1`
  );
});

test("Droid Create issue comments on PRs update the PR branch", () => {
  const workflow = readRepoFile(".github/workflows/droid-create.yml");
  const issueCommentHandler =
    workflow.match(/elif event_name == "issue_comment":[\s\S]*?elif event_name == "issues":/)?.[0] ?? "";

  assert.match(issueCommentHandler, /source_pr = api_get\(issue\["pull_request"\]\["url"\]\)/);
  assert.match(issueCommentHandler, /\n\s+pr = source_pr\n/);
  assert.match(issueCommentHandler, /\n\s+is_pr = True\n/);
  assert.doesNotMatch(
    workflow,
    /github\.event_name == 'issue_comment' && needs\.droid-context\.outputs\.default_branch/,
    "PR-linked issue_comment triggers must not force checkout to the default branch"
  );

  const checkoutRefAssignments = workflow.match(/CHECKOUT_REF: .*/g) ?? [];
  assert.deepEqual(checkoutRefAssignments, [
    "CHECKOUT_REF: ${{ needs.droid-context.outputs.checkout_ref }}",
    "CHECKOUT_REF: ${{ needs.droid-context.outputs.checkout_ref }}"
  ]);
});

test("Droid Create event filters reject untrusted comment and issue authors before runner allocation", () => {
  const workflow = readRepoFile(".github/workflows/droid-create.yml");
  const contextJob = workflow.match(/  droid-context:[\s\S]*?    runs-on: ubuntu-latest/)?.[0] ?? "";
  const trustedActors = /\["OWNER","MEMBER","COLLABORATOR"\]/.source;

  assert.match(
    contextJob,
    new RegExp(
      [
        "github\\.event_name == 'pull_request_review_comment' &&",
        "\\s+github\\.event\\.pull_request\\.head\\.repo\\.full_name == github\\.repository &&",
        `\\s+contains\\(fromJSON\\('${trustedActors}'\\), github\\.event\\.comment\\.author_association\\) && \\(`
      ].join("\\n")
    )
  );
  assert.match(
    contextJob,
    new RegExp(
      [
        "github\\.event_name == 'pull_request_review' &&",
        "\\s+github\\.event\\.pull_request\\.head\\.repo\\.full_name == github\\.repository &&",
        `\\s+contains\\(fromJSON\\('${trustedActors}'\\), github\\.event\\.review\\.author_association\\) && \\(`
      ].join("\\n")
    )
  );
  assert.match(
    contextJob,
    new RegExp(
      [
        "github\\.event_name == 'issue_comment' &&",
        "\\s+github\\.event\\.issue\\.pull_request != null &&",
        `\\s+contains\\(fromJSON\\('${trustedActors}'\\), github\\.event\\.comment\\.author_association\\) && \\(`
      ].join("\\n")
    )
  );
  assert.match(
    contextJob,
    new RegExp(
      `contains\\(fromJSON\\('${trustedActors}'\\), github\\.event\\.issue\\.author_association\\) &&\\n\\s+\\(github\\.event\\.action == 'opened' \\|\\|`
    )
  );
});

test("Droid Create uses the resolved target concurrency key", () => {
  const workflow = readRepoFile(".github/workflows/droid-create.yml");
  const contextJob = workflow.match(/  droid-context:[\s\S]*?    runs-on: ubuntu-latest/)?.[0] ?? "";

  assert.match(
    contextJob,
    /concurrency:\n\s+group: \$\{\{ github\.workflow \}\}-\$\{\{ needs\.resolve-concurrency\.outputs\.key \}\}\n\s+cancel-in-progress: false/
  );
});
