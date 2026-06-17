import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { pathToFileURL, fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
