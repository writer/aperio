#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith("--")) continue;
    const key = value.slice(2);
    args[key] = argv[index + 1]?.startsWith("--") ? true : argv[++index] ?? true;
  }
  return args;
}

function changedFiles(base, head) {
  if (!base || !head) return [];
  const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", `${base}...${head}`], {
    encoding: "utf8"
  });
  return output.split(/\r?\n/).map((file) => file.trim()).filter(Boolean);
}

function categoriesFor(files) {
  const categories = new Set();
  for (const file of files) {
    if (/^(cmd|internal|proto|gen|go\.(mod|sum))\//.test(file) || /^go\.(mod|sum)$/.test(file)) {
      categories.add("go");
    }
    if (/^(apps|packages|package(-lock)?\.json|tsconfig\.json)/.test(file)) {
      categories.add("node");
    }
    if (/(\.github\/workflows|Dockerfile|docker-compose|\.env\.example)/.test(file)) {
      categories.add("delivery");
    }
    if (/^(packages\/db\/prisma|.*migration)/.test(file)) {
      categories.add("database");
    }
    if (/^(SECURITY|CONTRIBUTING|CHANGELOG|README|docs|droid-wiki|\.github\/(ISSUE_TEMPLATE|PULL_REQUEST_TEMPLATE))/.test(file)) {
      categories.add("docs");
    }
  }
  return [...categories].sort();
}

function requiredChecks(files, categories) {
  const checks = new Set(["npm run leak:check"]);
  if (categories.includes("go")) checks.add("go test ./...");
  if (categories.includes("node")) checks.add("npm run typecheck");
  if (categories.includes("database")) checks.add("npm run db:validate");
  if (files.some((file) => file === "package.json" || file === "package-lock.json")) {
    checks.add("npm run audit:prod");
  }
  if (categories.includes("delivery")) checks.add("make lint");
  return [...checks].sort();
}

function workflowPinViolations(files) {
  const violations = [];
  for (const file of files.filter((entry) => /^\.github\/workflows\/.*\.ya?ml$/.test(entry))) {
    if (!existsSync(file)) continue;
    const content = readFileSync(file, "utf8");
    for (const [lineNumber, line] of content.split(/\r?\n/).entries()) {
      const match = line.match(/^\s*-\s*uses:\s*([^#\s]+)/);
      if (!match || match[1].startsWith("./")) continue;
      const reference = match[1].split("@")[1] ?? "";
      if (!/^[0-9a-f]{40}$/i.test(reference)) {
        violations.push(`${file}:${lineNumber + 1} uses ${match[1]} without a full commit pin`);
      }
    }
  }
  return violations;
}

function renderMarkdown(result) {
  const lines = [
    "## Review preflight",
    "",
    `- Base: \\\`${result.base || "not supplied"}\\\``,
    `- Head: \\\`${result.head || "not supplied"}\\\``,
    `- Changed files: ${result.changedFiles.length}`,
    `- Categories: ${result.categories.join(", ") || "none"}`,
    "",
    "### Required local checks",
    "",
    ...(result.requiredChecks.length ? result.requiredChecks.map((check) => `- \\\`${check}\\\``) : ["- None"]),
    ""
  ];
  if (result.violations.length) {
    lines.push("### Violations", "", ...result.violations.map((violation) => `- ${violation}`), "");
  } else {
    lines.push("No preflight violations found.", "");
  }
  return lines.join("\n");
}

export function runPreflight({ base = "", head = "" } = {}) {
  const files = changedFiles(base, head);
  const categories = categoriesFor(files);
  const result = {
    ok: true,
    base,
    head,
    changedFiles: files,
    categories,
    requiredChecks: requiredChecks(files, categories),
    violations: workflowPinViolations(files)
  };
  result.ok = result.violations.length === 0;
  return result;
}

const args = parseArgs(process.argv.slice(2));
if (import.meta.url === `file://${process.argv[1]}`) {
  const result = runPreflight({ base: String(args.base || ""), head: String(args.head || "") });
  const json = JSON.stringify(result, null, 2);
  const markdown = renderMarkdown(result);
  for (const [key, content] of [["json-out", json], ["markdown-out", markdown]]) {
    if (!args[key] || args[key] === true) continue;
    const outputPath = path.resolve(String(args[key]));
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, content + "\n");
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    writeFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  }
  console.log(json);
  if (!result.ok) process.exitCode = 1;
}
