import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const moduleUrl = new URL("../scripts/review-preflight.mjs", import.meta.url);

test("review preflight is locally owned and classifies release-sensitive changes", async () => {
  const module = (await import(moduleUrl.href)) as {
    runPreflight: (input: { base: string; head: string }) => {
      requiredChecks: string[];
      categories: string[];
      violations: string[];
    };
  };
  const result = module.runPreflight({ base: "HEAD~1", head: "HEAD" });
  assert.ok(Array.isArray(result.requiredChecks));
  assert.ok(Array.isArray(result.categories));
  assert.deepEqual(result.violations, []);
});

test("review workflow preserves required branch-protection contexts locally", () => {
  const workflow = readFileSync(new URL("../.github/workflows/review-preflight.yml", import.meta.url), "utf8");
  assert.match(workflow, /name: Droid Review Preflight/);
  assert.match(workflow, /name: Droid Review Required/);
  assert.match(workflow, /needs: droid-review-preflight/);
  assert.match(workflow, /PREFLIGHT_RESULT: \$\{\{ needs\.droid-review-preflight\.result \}\}/);
  assert.doesNotMatch(workflow, /Factory-AI|pull-requests:\s*write|issues:\s*write|contents:\s*write/);
});
