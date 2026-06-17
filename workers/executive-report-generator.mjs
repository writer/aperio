// Executive report generator. Invoked as a Node subprocess by the Go API when an
// operator requests an on-demand report. Gathers data via Prisma, computes a KPI
// snapshot for the requested period, builds a deterministic narrative comparing
// against the prior period, renders branded HTML, optionally rasterizes the HTML
// to PDF via puppeteer, and persists artifact paths on the executive_reports row.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prisma } from "../packages/db/src/client.mjs";
import {
  artifactRoot,
  escapeHtml,
  fmtHours,
  fmtNumber,
  fmtPercent,
  percentDelta,
  renderPdfFromHtml
} from "./report-utils.mjs";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_COLORS = {
  CRITICAL: "#b91c1c",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#0f766e",
  INFO: "#6b7280"
};

function median(numbers) {
  if (numbers.length === 0) return null;
  const sorted = [...numbers].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1] + sorted[mid]) / 2;
  return sorted[mid];
}

function quantile(numbers, q) {
  if (numbers.length === 0) return null;
  const sorted = [...numbers].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sorted[base + 1] !== undefined) {
    return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  }
  return sorted[base];
}

async function gatherReportData(report) {
  const { organizationId, periodStart, periodEnd } = report;
  const priorStart = new Date(
    periodStart.getTime() - (periodEnd.getTime() - periodStart.getTime())
  );

  const [
    organization,
    integrations,
    openFindings,
    periodOpenedFindings,
    periodResolvedFindings,
    priorOpenedFindings,
    priorResolvedFindings,
    identities,
    assets,
    auditCount,
    priorAuditCount,
    topActorRows
  ] = await Promise.all([
    prisma.organization.findUnique({ where: { id: organizationId } }),
    prisma.integrationConnection.findMany({
      where: { organizationId },
      select: {
        id: true,
        provider: true,
        displayName: true,
        status: true,
        lastSyncAt: true
      }
    }),
    prisma.securityFinding.findMany({
      where: { organizationId, status: "OPEN" },
      select: {
        id: true,
        title: true,
        severity: true,
        riskScore: true,
        detectedAt: true,
        assetId: true,
        integration: { select: { provider: true, displayName: true } }
      },
      orderBy: { riskScore: "desc" },
      take: 200
    }),
    prisma.securityFinding.findMany({
      where: { organizationId, detectedAt: { gte: periodStart, lte: periodEnd } },
      select: { id: true, severity: true, status: true, detectedAt: true, resolvedAt: true }
    }),
    prisma.securityFinding.findMany({
      where: {
        organizationId,
        status: "RESOLVED",
        resolvedAt: { gte: periodStart, lte: periodEnd }
      },
      select: { id: true, severity: true, detectedAt: true, resolvedAt: true }
    }),
    prisma.securityFinding.findMany({
      where: { organizationId, detectedAt: { gte: priorStart, lt: periodStart } },
      select: { id: true, severity: true }
    }),
    prisma.securityFinding.findMany({
      where: {
        organizationId,
        status: "RESOLVED",
        resolvedAt: { gte: priorStart, lt: periodStart }
      },
      select: { id: true, detectedAt: true, resolvedAt: true }
    }),
    prisma.saasIdentity.findMany({
      where: { organizationId },
      select: {
        id: true,
        mfaEnabled: true,
        status: true,
        isPrivileged: true,
        isExternal: true,
        lastObservedAt: true,
        provider: true
      }
    }),
    prisma.securityAsset.findMany({
      where: { organizationId },
      select: {
        id: true,
        type: true,
        criticality: true,
        exposureLevel: true,
        containsSensitiveData: true,
        riskScore: true
      }
    }),
    prisma.tenantAuditLog.count({
      where: { organizationId, createdAt: { gte: periodStart, lte: periodEnd } }
    }),
    prisma.tenantAuditLog.count({
      where: { organizationId, createdAt: { gte: priorStart, lt: periodStart } }
    }),
    prisma.tenantAuditLog.groupBy({
      by: ["actorUserId"],
      where: {
        organizationId,
        createdAt: { gte: periodStart, lte: periodEnd },
        actorUserId: { not: null }
      },
      _count: { actorUserId: true },
      orderBy: { _count: { actorUserId: "desc" } },
      take: 5
    })
  ]);

  if (!organization) {
    throw new Error(`organization ${organizationId} not found`);
  }

  const actorIds = topActorRows
    .map((row) => row.actorUserId)
    .filter((id) => typeof id === "string");
  const actorUsers = actorIds.length
    ? await prisma.user.findMany({
        where: { id: { in: actorIds } },
        select: { id: true, email: true, displayName: true }
      })
    : [];
  const actorIndex = new Map(actorUsers.map((u) => [u.id, u]));

  const assetIds = [
    ...new Set(openFindings.map((f) => f.assetId).filter(Boolean))
  ];
  const assetIndex = assetIds.length
    ? new Map(
        (
          await prisma.securityAsset.findMany({
            where: { id: { in: assetIds } },
            select: { id: true, name: true, type: true }
          })
        ).map((a) => [a.id, a])
      )
    : new Map();

  const openBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const finding of openFindings) {
    openBySeverity[finding.severity] = (openBySeverity[finding.severity] ?? 0) + 1;
  }

  const openedBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const finding of periodOpenedFindings) {
    openedBySeverity[finding.severity] = (openedBySeverity[finding.severity] ?? 0) + 1;
  }

  const resolvedTimes = periodResolvedFindings
    .map((f) => {
      if (!f.detectedAt || !f.resolvedAt) return null;
      return (f.resolvedAt.getTime() - f.detectedAt.getTime()) / 1000 / 3600;
    })
    .filter((v) => v != null && v >= 0);
  const mttrMedianHours = median(resolvedTimes);
  const mttrP90Hours = quantile(resolvedTimes, 0.9);

  const priorMttrTimes = priorResolvedFindings
    .map((f) => {
      if (!f.detectedAt || !f.resolvedAt) return null;
      return (f.resolvedAt.getTime() - f.detectedAt.getTime()) / 1000 / 3600;
    })
    .filter((v) => v != null && v >= 0);
  const priorMttrMedianHours = median(priorMttrTimes);

  const userIdentities = identities.filter((i) => i.status === "ACTIVE");
  const mfaCovered = userIdentities.filter((i) => i.mfaEnabled === true).length;
  const mfaCoveragePercent = userIdentities.length
    ? (mfaCovered / userIdentities.length) * 100
    : 0;
  const dormantIdentities = identities.filter(
    (i) =>
      i.status === "DORMANT" ||
      (i.lastObservedAt &&
        Date.now() - i.lastObservedAt.getTime() > 1000 * 3600 * 24 * 90)
  ).length;

  const findingsByAsset = new Map();
  for (const f of openFindings) {
    if (!f.assetId) continue;
    findingsByAsset.set(f.assetId, (findingsByAsset.get(f.assetId) ?? 0) + 1);
  }
  const topAffectedAssets = [...findingsByAsset.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([assetId, count]) => {
      const asset = assetIndex.get(assetId);
      return {
        assetId,
        name: asset?.name ?? "(unknown asset)",
        type: asset?.type ?? "—",
        openFindings: count
      };
    });

  const topRisks = openFindings
    .slice()
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5)
    .map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      riskScore: f.riskScore,
      provider: f.integration?.provider ?? "—",
      detectedAt: f.detectedAt
    }));

  const topActors = topActorRows.map((row) => {
    const user = actorIndex.get(row.actorUserId);
    return {
      email: user?.email ?? "(unknown)",
      displayName: user?.displayName ?? null,
      actions: row._count?.actorUserId ?? 0
    };
  });

  return {
    organization,
    integrations,
    kpis: {
      findings: {
        openTotal: openFindings.length,
        opened: periodOpenedFindings.length,
        resolved: periodResolvedFindings.length,
        priorOpened: priorOpenedFindings.length,
        priorResolved: priorResolvedFindings.length,
        openBySeverity,
        openedBySeverity
      },
      mttr: {
        medianHours: mttrMedianHours,
        p90Hours: mttrP90Hours,
        priorMedianHours: priorMttrMedianHours
      },
      coverage: {
        connectedProviders: integrations.map((i) => i.provider),
        activeIntegrations: integrations.filter((i) => i.status === "CONNECTED").length,
        totalAssets: assets.length,
        totalIdentities: identities.length,
        userIdentities: userIdentities.length,
        mfaCoveragePercent,
        dormantIdentities,
        privilegedIdentities: identities.filter((i) => i.isPrivileged).length,
        externalIdentities: identities.filter((i) => i.isExternal).length,
        sensitiveDataAssets: assets.filter((a) => a.containsSensitiveData).length,
        publicExposureAssets: assets.filter((a) => a.exposureLevel === "PUBLIC").length
      },
      activity: {
        auditActions: auditCount,
        priorAuditActions: priorAuditCount,
        topActors
      },
      topRisks,
      topAffectedAssets
    }
  };
}

function buildNarrative(report, data) {
  const { kpis } = data;
  const changes = [];
  const better = [];
  const worse = [];
  const recommendations = [];

  const openedDelta = percentDelta(kpis.findings.opened, kpis.findings.priorOpened);
  if (Math.abs(openedDelta) > 5) {
    const direction = openedDelta > 0 ? "increased" : "decreased";
    changes.push(
      `New findings ${direction} ${Math.abs(openedDelta).toFixed(0)}% vs. the prior period (${kpis.findings.opened} vs ${kpis.findings.priorOpened}).`
    );
    if (openedDelta > 15) {
      worse.push(
        "Detection volume is rising — review whether a recent connector change or rule update is responsible."
      );
    } else if (openedDelta < -15) {
      better.push(
        "Detection volume dropped meaningfully — confirm this is real improvement and not silent connector breakage."
      );
    }
  }

  const resolvedDelta = percentDelta(kpis.findings.resolved, kpis.findings.priorResolved);
  if (kpis.findings.resolved > 0) {
    changes.push(
      `Team resolved ${fmtNumber(kpis.findings.resolved)} findings this period (${resolvedDelta >= 0 ? "+" : ""}${resolvedDelta.toFixed(0)}% vs prior).`
    );
    if (resolvedDelta > 10) better.push("Throughput on closing findings improved.");
    if (resolvedDelta < -10) worse.push("Resolution throughput declined; check for capacity or on-call gaps.");
  }

  if (kpis.mttr.medianHours != null && kpis.mttr.priorMedianHours != null) {
    const mttrDelta = kpis.mttr.medianHours - kpis.mttr.priorMedianHours;
    if (Math.abs(mttrDelta) > 1) {
      const direction = mttrDelta > 0 ? "slowed" : "improved";
      changes.push(
        `Median time-to-resolve ${direction} from ${fmtHours(kpis.mttr.priorMedianHours)} to ${fmtHours(kpis.mttr.medianHours)}.`
      );
      if (mttrDelta < 0) better.push("Findings are closing faster on average.");
      if (mttrDelta > 0)
        worse.push("Time-to-resolve regressed; review oldest open findings for stale ownership.");
    }
  }

  const criticalOpen = kpis.findings.openBySeverity.CRITICAL ?? 0;
  if (criticalOpen > 0) {
    recommendations.push(
      `Drive ${criticalOpen} open CRITICAL finding${criticalOpen === 1 ? "" : "s"} to closure or formal risk-acceptance.`
    );
  }
  if (kpis.coverage.mfaCoveragePercent < 95 && kpis.coverage.userIdentities > 0) {
    recommendations.push(
      `MFA coverage at ${fmtPercent(kpis.coverage.mfaCoveragePercent)} — enforce MFA on the remaining ${kpis.coverage.userIdentities - Math.round((kpis.coverage.mfaCoveragePercent / 100) * kpis.coverage.userIdentities)} identities.`
    );
  }
  if (kpis.coverage.dormantIdentities > 0) {
    recommendations.push(
      `Review ${kpis.coverage.dormantIdentities} dormant identit${kpis.coverage.dormantIdentities === 1 ? "y" : "ies"} for offboarding.`
    );
  }
  if (kpis.coverage.publicExposureAssets > 0) {
    recommendations.push(
      `Audit ${kpis.coverage.publicExposureAssets} publicly exposed asset${kpis.coverage.publicExposureAssets === 1 ? "" : "s"}; verify the exposure is intentional.`
    );
  }
  if (recommendations.length === 0) {
    recommendations.push("Detection signal is stable; continue current cadence.");
  }
  if (changes.length === 0) {
    changes.push("Detection indicators were broadly flat versus the prior period.");
  }

  const summary = changes.slice(0, 3).join(" ");
  return { changes, better, worse, recommendations, summary };
}

function renderHtml(report, data, narrative) {
  const { organization, kpis } = data;
  const periodLabel = `${report.periodStart.toISOString().slice(0, 10)} → ${report.periodEnd.toISOString().slice(0, 10)}`;
  const severityRows = SEVERITIES.map((sev) => {
    const open = kpis.findings.openBySeverity[sev] ?? 0;
    const opened = kpis.findings.openedBySeverity[sev] ?? 0;
    return `<tr>
      <td><span class="sev-dot" style="background:${SEVERITY_COLORS[sev]}"></span>${sev}</td>
      <td class="num">${fmtNumber(open)}</td>
      <td class="num">${fmtNumber(opened)}</td>
    </tr>`;
  }).join("");

  const topRisksRows =
    kpis.topRisks.length === 0
      ? `<tr><td colspan="4" class="muted">No open findings.</td></tr>`
      : kpis.topRisks
          .map(
            (r) => `<tr>
              <td>${escapeHtml(r.title)}</td>
              <td><span class="badge sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
              <td>${escapeHtml(r.provider)}</td>
              <td class="num">${fmtNumber(r.riskScore)}</td>
            </tr>`
          )
          .join("");

  const topAssetsRows =
    kpis.topAffectedAssets.length === 0
      ? `<tr><td colspan="3" class="muted">No assets carry open findings.</td></tr>`
      : kpis.topAffectedAssets
          .map(
            (a) => `<tr>
              <td>${escapeHtml(a.name)}</td>
              <td>${escapeHtml(a.type)}</td>
              <td class="num">${fmtNumber(a.openFindings)}</td>
            </tr>`
          )
          .join("");

  const topActorsRows =
    kpis.activity.topActors.length === 0
      ? `<tr><td colspan="2" class="muted">No tenant audit activity in window.</td></tr>`
      : kpis.activity.topActors
          .map(
            (a) => `<tr>
              <td>${escapeHtml(a.displayName ?? a.email)}<div class="muted small">${escapeHtml(a.email)}</div></td>
              <td class="num">${fmtNumber(a.actions)}</td>
            </tr>`
          )
          .join("");

  const integrationsList = data.integrations
    .map(
      (i) => `<li>
        <strong>${escapeHtml(i.displayName)}</strong>
        <span class="muted small">· ${escapeHtml(i.provider)} · ${escapeHtml(i.status)}</span>
      </li>`
    )
    .join("");

  const better = narrative.better.length
    ? `<ul>${narrative.better.map((b) => `<li>${escapeHtml(b)}</li>`).join("")}</ul>`
    : `<p class="muted">No notable improvements in this window.</p>`;
  const worse = narrative.worse.length
    ? `<ul>${narrative.worse.map((b) => `<li>${escapeHtml(b)}</li>`).join("")}</ul>`
    : `<p class="muted">No notable regressions in this window.</p>`;
  const recommendations = `<ul>${narrative.recommendations.map((b) => `<li>${escapeHtml(b)}</li>`).join("")}</ul>`;
  const changes = `<ul>${narrative.changes.map((b) => `<li>${escapeHtml(b)}</li>`).join("")}</ul>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(report.title)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0; background: #f8fafc; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.5; }
  .container { max-width: 900px; margin: 0 auto; padding: 32px; }
  header { border-bottom: 1px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 28px; }
  header h1 { margin: 0 0 4px; font-size: 24px; color: #0f172a; }
  header .meta { color: #475569; font-size: 13px; }
  h2 { font-size: 16px; color: #0f172a; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: .05em; }
  h3 { font-size: 14px; color: #334155; margin: 18px 0 8px; }
  p, li { font-size: 13px; color: #334155; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .kpi-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; }
  .kpi-card .label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #64748b; margin-bottom: 4px; }
  .kpi-card .value { font-size: 22px; font-weight: 600; color: #0f172a; }
  .kpi-card .sub { font-size: 12px; color: #64748b; margin-top: 4px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left; font-size: 12.5px; border-bottom: 1px solid #e2e8f0; }
  th { background: #f1f5f9; color: #475569; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; font-size: 11px; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  tr:last-child td { border-bottom: none; }
  .muted { color: #94a3b8; }
  .small { font-size: 11px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .sev-critical { background: #fee2e2; color: #991b1b; }
  .sev-high { background: #ffedd5; color: #9a3412; }
  .sev-medium { background: #fef3c7; color: #854d0e; }
  .sev-low { background: #ccfbf1; color: #115e59; }
  .sev-info { background: #e5e7eb; color: #374151; }
  .sev-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
  ul { padding-left: 18px; margin: 6px 0 12px; }
  .panel { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 11px; text-align: center; }
  @media print {
    body { background: white; }
    .container { padding: 16px; max-width: 100%; }
    .kpi-card, table, .panel { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>${escapeHtml(report.title)}</h1>
    <div class="meta">
      <strong>${escapeHtml(organization.name)}</strong> · ${escapeHtml(periodLabel)} · generated ${new Date().toISOString().slice(0, 10)}
    </div>
  </header>

  <h2>Executive summary</h2>
  <p>${escapeHtml(narrative.summary)}</p>

  <h2>Key indicators</h2>
  <div class="kpi-grid">
    <div class="kpi-card"><div class="label">Open findings</div><div class="value">${fmtNumber(kpis.findings.openTotal)}</div><div class="sub">${fmtNumber(kpis.findings.openBySeverity.CRITICAL ?? 0)} critical · ${fmtNumber(kpis.findings.openBySeverity.HIGH ?? 0)} high</div></div>
    <div class="kpi-card"><div class="label">New this period</div><div class="value">${fmtNumber(kpis.findings.opened)}</div><div class="sub">${fmtNumber(kpis.findings.resolved)} resolved</div></div>
    <div class="kpi-card"><div class="label">Median MTTR</div><div class="value">${fmtHours(kpis.mttr.medianHours)}</div><div class="sub">P90 ${fmtHours(kpis.mttr.p90Hours)}</div></div>
    <div class="kpi-card"><div class="label">MFA coverage</div><div class="value">${fmtPercent(kpis.coverage.mfaCoveragePercent)}</div><div class="sub">${fmtNumber(kpis.coverage.userIdentities)} user identities</div></div>
    <div class="kpi-card"><div class="label">Connected providers</div><div class="value">${fmtNumber(kpis.coverage.activeIntegrations)}</div><div class="sub">${fmtNumber(kpis.coverage.totalAssets)} assets in scope</div></div>
    <div class="kpi-card"><div class="label">Privileged identities</div><div class="value">${fmtNumber(kpis.coverage.privilegedIdentities)}</div><div class="sub">${fmtNumber(kpis.coverage.externalIdentities)} external</div></div>
    <div class="kpi-card"><div class="label">Dormant identities</div><div class="value">${fmtNumber(kpis.coverage.dormantIdentities)}</div><div class="sub">Inactive 90d+ or status DORMANT</div></div>
    <div class="kpi-card"><div class="label">Sensitive-data assets</div><div class="value">${fmtNumber(kpis.coverage.sensitiveDataAssets)}</div><div class="sub">${fmtNumber(kpis.coverage.publicExposureAssets)} publicly exposed</div></div>
  </div>

  <h2>What changed</h2>
  <div class="panel">${changes}</div>

  <div class="two-col" style="margin-top:16px;">
    <div class="panel"><h3>Getting better</h3>${better}</div>
    <div class="panel"><h3>Getting worse</h3>${worse}</div>
  </div>

  <h2>Recommendations</h2>
  <div class="panel">${recommendations}</div>

  <h2>Findings by severity</h2>
  <table>
    <thead><tr><th>Severity</th><th class="num">Open now</th><th class="num">Opened this period</th></tr></thead>
    <tbody>${severityRows}</tbody>
  </table>

  <h2>Top open risks</h2>
  <table>
    <thead><tr><th>Finding</th><th>Severity</th><th>Provider</th><th class="num">Risk score</th></tr></thead>
    <tbody>${topRisksRows}</tbody>
  </table>

  <h2>Most affected assets</h2>
  <table>
    <thead><tr><th>Asset</th><th>Type</th><th class="num">Open findings</th></tr></thead>
    <tbody>${topAssetsRows}</tbody>
  </table>

  <h2>Notable activity</h2>
  <div class="two-col">
    <div class="panel">
      <h3>Audit activity</h3>
      <p>${fmtNumber(kpis.activity.auditActions)} actions this period (${kpis.activity.priorAuditActions === 0 ? "no comparable prior period" : `${percentDelta(kpis.activity.auditActions, kpis.activity.priorAuditActions).toFixed(0)}% vs prior`}).</p>
      <h3>Top actors</h3>
      <table>
        <thead><tr><th>Actor</th><th class="num">Actions</th></tr></thead>
        <tbody>${topActorsRows}</tbody>
      </table>
    </div>
    <div class="panel">
      <h3>Connected providers</h3>
      <ul>${integrationsList || '<li class="muted">No connectors configured.</li>'}</ul>
    </div>
  </div>

  <footer>
    Aperio · SaaS Detection &amp; Response · For CISO &amp; executive distribution.
  </footer>
</div>
</body>
</html>`;
}

export async function generateExecutiveReport(reportId) {
  const report = await prisma.executiveReport.findUnique({
    where: { id: reportId }
  });
  if (!report) {
    throw new Error(`executive_report ${reportId} not found`);
  }
  if (report.status === "READY") {
    return report; // idempotent re-runs are no-ops
  }

  const data = await gatherReportData(report);
  const narrative = buildNarrative(report, data);
  const html = renderHtml(report, data, narrative);

  const root = artifactRoot();
  await mkdir(root, { recursive: true });
  const htmlPath = join(root, `${report.id}.html`);
  const pdfPath = join(root, `${report.id}.pdf`);
  await writeFile(htmlPath, html, "utf-8");

  let pdfWritten = false;
  try {
    pdfWritten = await renderPdfFromHtml(htmlPath, pdfPath);
  } catch (err) {
    process.stderr.write(`pdf render failed: ${err.message ?? err}\n`);
  }

  await prisma.executiveReport.update({
    where: { id: report.id },
    data: {
      status: "READY",
      htmlPath,
      pdfPath: pdfWritten ? pdfPath : null,
      summary: narrative.summary,
      kpiSnapshot: data.kpis,
      generatedAt: new Date(),
      errorMessage: null
    }
  });

  return { reportId: report.id, htmlPath, pdfPath: pdfWritten ? pdfPath : null };
}
