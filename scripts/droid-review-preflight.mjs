#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import {
  appendStepSummary,
  gitChangedFiles,
  parseArgs,
  writeGitHubOutputs,
  writeJSON,
  writeText,
} from "./droid-common.mjs";

export const categories = [
  {
    id: "critical_auth_security",
    label: "Critical auth/security",
    model: "claude-sonnet-4-6",
    patterns: [
      /^packages\/security\//,
      /^packages\/shared\/src\/(?:auth|security|siem-security)\.ts$/,
      /^apps\/api\/src\/routes\/auth\.ts$/,
      /^apps\/api\/src\/middleware\/(?:security|rate-limit)\.ts$/,
    ],
  },
  {
    id: "tenant_data_integrity",
    label: "Tenant/data integrity",
    model: "claude-sonnet-4-6",
    patterns: [
      /^packages\/db\//,
      /^apps\/api\/src\/routes\/(?:admin|findings|ingestion|security|shadow-it)\.ts$/,
      /^tests\/.*(?:tenant|isolation|ingestion|queue).*\.test\.ts$/,
    ],
  },
  {
    id: "agents_remediation_mcp_siem",
    label: "Agents/remediation/MCP/SIEM",
    model: "claude-sonnet-4-6",
    patterns: [
      /^apps\/api\/src\/routes\/(?:agents|remediations|siem)\.ts$/,
      /^apps\/api\/src\/remediation\//,
      /^apps\/mcp\//,
      /^cmd\/siem-dispatcher\//,
      /^internal\/siemdispatcher\//,
      /^cmd\/mcp-broker\//,
      /^internal\/mcpbroker\//,
      /^workers\//,
      /^packages\/shared\/src\/siem.*\.ts$/,
    ],
  },
  {
    id: "connectors_integrations_ingestion",
    label: "Connectors/integrations/ingestion",
    model: "claude-sonnet-4-6",
    patterns: [
      /^apps\/api\/src\/routes\/integrations\.ts$/,
      /^packages\/shared\/src\/connectors\.ts$/,
      /^cmd\/ingestion-worker\//,
      /^internal\/ingestionworker\//,
    ],
  },
  {
    id: "supply_chain_workflow",
    label: "Supply chain/workflow",
    model: "claude-sonnet-4-6",
    patterns: [
      /^\.github\/workflows\//,
      /^scripts\//,
      /^package(?:-lock)?\.json$/,
      /^docker-compose\.ya?ml$/,
      /^Dockerfile(?:\..*)?$/,
      /^\.env/,
    ],
  },
  {
    id: "web_ui",
    label: "Web/UI",
    model: "gpt-5.4",
    patterns: [/^apps\/web\//],
  },
  {
    id: "api_app",
    label: "API/app",
    model: "gpt-5.4",
    patterns: [/^apps\/api\//, /^packages\/shared\//],
  },
];

export function matchesAny(file, patterns) {
  return patterns.some((pattern) => pattern.test(file));
}

export function isDocsOnlyFile(file) {
  return (
    /\.(?:md|mdx|txt)$/i.test(file) ||
    file === "LICENSE" ||
    file.startsWith("droid-wiki/") ||
    file.startsWith("docs/")
  );
}

export function matchedCategoriesForChangedFiles(changedFiles) {
  const matchedCategories = [];
  for (const category of categories) {
    const files = changedFiles.filter((file) => matchesAny(file, category.patterns));
    if (files.length > 0) {
      matchedCategories.push({ ...category, files });
    }
  }
  return matchedCategories;
}

export function probePlanForCategories(matchedCategories, runDroidReview) {
  const probePlan = [];
  if (matchedCategories.some((category) => category.id === "critical_auth_security")) {
    probePlan.push("Review authentication, session handling, secret boundaries, rate limiting, and bypass paths.");
  }
  if (matchedCategories.some((category) => category.id === "tenant_data_integrity")) {
    probePlan.push("Verify tenant isolation, Prisma migrations, durable queue semantics, and data integrity invariants.");
  }
  if (matchedCategories.some((category) => category.id === "agents_remediation_mcp_siem")) {
    probePlan.push("Inspect worker leases, SIEM dispatch idempotency, MCP exposure, and remediation side effects.");
  }
  if (matchedCategories.some((category) => category.id === "supply_chain_workflow")) {
    probePlan.push("Check workflow permissions, action pinning, package supply chain changes, and script safety.");
  }
  if (probePlan.length === 0 && runDroidReview) {
    probePlan.push("Review changed application behavior and test coverage.");
  }
  return probePlan;
}

export function buildPreflightReport({ base = "", head = "HEAD", changedFiles = [] } = {}) {
  const matchedCategories = matchedCategoriesForChangedFiles(changedFiles);
  const docsOnly = changedFiles.length > 0 && changedFiles.every(isDocsOnlyFile);
  const runDroidReview = changedFiles.length > 0 && !docsOnly;
  const highRisk = matchedCategories.some((category) => category.model === "claude-sonnet-4-6");
  const reviewModel = highRisk ? "claude-sonnet-4-6" : "gpt-5.4";
  const reviewReason = (() => {
    if (changedFiles.length === 0) {
      return "no changed files";
    }
    if (docsOnly) {
      return "documentation-only changes";
    }
    if (matchedCategories.length === 0) {
      return "application changes detected";
    }
    return matchedCategories.map((category) => category.label).join(", ");
  })();
  const probePlan = probePlanForCategories(matchedCategories, runDroidReview);

  const result = {
    base,
    head,
    run_droid_review: String(runDroidReview),
    review_model: reviewModel,
    review_reason: reviewReason,
    changed_file_count: changedFiles.length,
    changed_files: changedFiles,
    docs_only: docsOnly,
    risk_categories: matchedCategories.map((category) => ({
      id: category.id,
      label: category.label,
      file_count: category.files.length,
      files: category.files,
    })),
    probe_plan: probePlan,
  };

  const markdown = [
    "### Droid Review Preflight",
    "",
    `- Run Droid review: ${runDroidReview}`,
    `- Review model: \`${reviewModel}\``,
    `- Reason: ${reviewReason}`,
    `- Changed files: ${changedFiles.length}`,
    "",
    matchedCategories.length
      ? [
          "#### Risk categories",
          "",
          ...matchedCategories.map((category) => `- ${category.label}: ${category.files.length} file(s)`),
        ].join("\n")
      : "#### Risk categories\n\n- none",
    "",
    probePlan.length
      ? [
          "#### Droid probe plan",
          "",
          ...probePlan.map((item) => `- ${item}`),
        ].join("\n")
      : "",
  ].filter(Boolean).join("\n");

  return { result, markdown };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const args = parseArgs(argv);
  const base = args.base || env.DROID_REVIEW_BASE || env.GITHUB_BASE_REF || "";
  const head = args.head || env.DROID_REVIEW_HEAD || env.GITHUB_SHA || "HEAD";
  const jsonOut = args["json-out"] || env.DROID_PREFLIGHT_JSON_OUT || "tmp/droid-preflight.json";
  const markdownOut = args["markdown-out"] || env.DROID_PREFLIGHT_OUT || "tmp/droid-preflight.md";
  const changedFiles = gitChangedFiles(base, head);
  const { result, markdown } = buildPreflightReport({ base, head, changedFiles });

  writeJSON(jsonOut, result);
  writeText(markdownOut, markdown);
  writeGitHubOutputs({
    run_droid_review: result.run_droid_review,
    review_model: result.review_model,
    review_reason: result.review_reason,
    risk_categories: result.risk_categories.map((category) => category.id).join(","),
    changed_file_count: String(changedFiles.length),
  });
  appendStepSummary(markdown);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
