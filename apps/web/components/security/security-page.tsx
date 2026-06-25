"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ArrowUpRight,
  ChevronsUpDown,
  Search
} from "lucide-react";
import {
  fetchEmailDomainHealth,
  fetchSecurityOverview,
  type AttackPath,
  type DomainWideDelegation,
  type EmailDomainHealth,
  type SecurityAsset,
  type SecurityCerebroContext,
  type SecurityOverview
} from "../../lib/api";
import { CerebroMCPResourceTemplateList } from "../cerebro/mcp-resource-template-list";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import { EmptyState } from "../ui/empty-state";
import { Input } from "../ui/input";
import { Skeleton } from "../ui/skeleton";
import { AsyncSection } from "../ui/async-section";
import { cn } from "../../lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";

type SortKey = "title" | "score" | "owner";
type SortDir = "asc" | "desc";

export function SecurityPage() {
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [domainHealth, setDomainHealth] = useState<EmailDomainHealth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [overviewResponse, domainResponse] = await Promise.all([
        fetchSecurityOverview(),
        fetchEmailDomainHealth({ refreshIfStale: true }).catch(() => ({
          data: [] as EmailDomainHealth[]
        }))
      ]);
      setOverview(overviewResponse.data);
      setDomainHealth(domainResponse.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load security");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Security"
        title="Security graph"
        description="Privileged identities, risky OAuth apps, exposed data, attack paths, and ownership gaps."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" asChild>
              <Link href="/security/privileged-identities">
                Privileged identities
                <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/security/email-domain-health">
                Email domain health
                <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
          </div>
        }
      />

      <AsyncSection
        data={overview}
        loading={loading}
        error={error}
        className="space-y-5"
        onRetry={() => void load()}
        errorTitle="Unable to load security"
        skeleton={
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <SkeletonStat />
              <SkeletonStat />
              <SkeletonStat />
              <SkeletonStat />
            </div>
            <Card>
              <CardContent className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </CardContent>
            </Card>
          </div>
        }
      >
        {(data) => (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label="Privileged identities"
                value={data.summary.privilegedIdentities}
              />
              <Stat
                label="Admins without MFA"
                value={data.summary.adminIdentitiesWithoutMfa}
                tone={
                  data.summary.adminIdentitiesWithoutMfa > 0
                    ? "critical"
                    : "neutral"
                }
              />
              <Stat
                label="Risky OAuth apps"
                value={data.summary.riskyOauthApps}
              />
              <Stat
                label="Top blast radius"
                value={data.summary.topBlastRadiusScore}
                helper="0-100, weighted across paths"
                tone={
                  data.summary.topBlastRadiusScore >= 75
                    ? "critical"
                    : "signal"
                }
              />
            </section>

            <EmailDomainHealthSummaryCard domains={domainHealth} />

            <SecurityCerebroContextCard context={data.cerebroContext ?? null} />

            <AttackPathsCard paths={data.attackPaths} />

            {(data.domainWideDelegations ?? []).length > 0 ? (
              <DomainWideDelegationCard
                delegations={data.domainWideDelegations ?? []}
              />
            ) : null}

            <div className="grid gap-4 lg:grid-cols-2">
              <AssetListCard
                title="Risky OAuth apps"
                description="OAuth grants ranked by risk score."
                assets={data.oauthApps}
                emptyMessage="No risky OAuth apps right now."
                badgeFor={(asset) =>
                  asset.riskScore >= 75
                    ? "critical"
                    : asset.riskScore >= 50
                      ? "warning"
                      : "secondary"
                }
                valueFor={(asset) => asset.riskScore.toString()}
              />
              <AssetListCard
                title="Ownership gaps"
                description="Tracked assets with no business owner."
                assets={data.ownershipGaps}
                emptyMessage="Every tracked asset has an owner."
                badgeFor={() => "warning"}
                valueFor={(asset) => asset.criticality}
              />
            </div>
          </>
        )}
      </AsyncSection>
    </div>
  );
}

function SecurityCerebroContextCard({
  context
}: {
  context: SecurityCerebroContext | null;
}) {
  if (!context) return null;
  const modeLabel = context.mode.replaceAll("-", " ");
  const linked =
    context.mode === "claim-linked" || context.mode === "graph-linked";
  const webLinks = context.webLinks ?? [];
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>Cerebro graph context</CardTitle>
            <CardDescription>
              Security overview provenance for the Cerebro source runtime and
              MCP investigation surface.
            </CardDescription>
          </div>
          <Badge variant={linked ? "secondary" : "outline"}>{modeLabel}</Badge>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-[1fr_1fr]">
        <dl className="grid gap-2 text-sm">
          <CerebroContextRow
            label="Runtime"
            value={context.sourceRuntimeId || "Not configured"}
          />
          <CerebroContextRow
            label="Contract"
            value={context.findingContract || "cerebro.v1.Finding"}
          />
          <CerebroContextRow
            label="MCP resource"
            value={context.mcp?.resourceUri || "Not configured"}
          />
          <CerebroContextRow
            label="MCP server"
            value={context.mcp?.server || "Not configured"}
          />
        </dl>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4">
          <CerebroMiniStat label="Claims" value={context.claimCount} />
          <CerebroMiniStat label="Signals" value={context.graphSignalCount} />
          <CerebroMiniStat label="Entities" value={context.entityCount} />
          <CerebroMiniStat label="Paths" value={context.graphPathCount} />
        </div>
        {webLinks.length ? (
          <div className="lg:col-span-2">
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Open in Cerebro
            </p>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {webLinks.slice(0, 4).map((link) => (
                <a
                  key={`${link.kind ?? link.label}:${link.url}`}
                  href={link.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center justify-between gap-2 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs font-medium text-foreground transition hover:border-signal/40 hover:bg-signal/10"
                >
                  <span>{link.label}</span>
                  <ArrowUpRight
                    className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                </a>
              ))}
            </div>
          </div>
        ) : null}
        {context.mcp?.tools.length ? (
          <div className="lg:col-span-2">
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              MCP tools
            </p>
            <div className="flex flex-wrap gap-1.5">
              {context.mcp.tools.map((tool) => (
                <span
                  key={tool}
                  className="rounded border border-border/70 bg-muted/30 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                >
                  {tool}
                </span>
              ))}
            </div>
          </div>
        ) : null}
        <CerebroMCPResourceTemplateList
          className="lg:col-span-2"
          templates={context.mcp?.resourceTemplates}
        />
      </CardContent>
    </Card>
  );
}

function CerebroContextRow({
  label,
  value
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[100px_minmax(0,1fr)] gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate font-mono text-xs text-foreground">{value}</dd>
    </div>
  );
}

function CerebroMiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border/70 bg-background/40 px-3 py-2">
      <p className="text-[11px] text-muted-foreground">{label}</p>
      <p className="font-mono text-lg text-foreground tabular-nums">{value}</p>
    </div>
  );
}

function DomainWideDelegationCard({
  delegations
}: {
  delegations: DomainWideDelegation[];
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Domain-wide delegation</CardTitle>
        <CardDescription>
          Google Workspace service accounts authorized to impersonate users for
          mailbox-state scanning. Each row shows the workspace domain it acts
          on, the scopes granted, and any open findings that depend on this
          surface.
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Workspace</TableHead>
              <TableHead>Service account</TableHead>
              <TableHead>Scopes</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Last sync</TableHead>
              <TableHead className="text-right">Open findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {delegations.map((entry) => (
              <TableRow key={entry.integrationId}>
                <TableCell className="font-medium">
                  {entry.workspaceDomain}
                  <p className="text-xs text-muted-foreground">
                    {entry.displayName}
                  </p>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {entry.serviceAccountClientEmail ? (
                    <span className="font-mono text-xs">
                      {entry.serviceAccountClientEmail}
                    </span>
                  ) : (
                    <span className="text-xs italic">Not configured</span>
                  )}
                </TableCell>
                <TableCell>
                  {entry.scopes.length > 0 ? (
                    <ul className="space-y-0.5">
                      {entry.scopes.map((scope) => (
                        <li
                          key={scope}
                          className="font-mono text-[11px] text-muted-foreground"
                        >
                          {scope}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-xs text-muted-foreground italic">
                      None
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <Badge
                    variant={
                      entry.status === "ENABLED"
                        ? entry.integrationStatus === "ERROR"
                          ? "warning"
                          : "secondary"
                        : "warning"
                    }
                  >
                    {entry.status === "ENABLED"
                      ? entry.integrationStatus === "CONNECTED"
                        ? "Enabled"
                        : `Enabled · ${entry.integrationStatus.toLowerCase()}`
                      : "Not configured"}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {entry.lastSyncAt
                    ? new Date(entry.lastSyncAt).toLocaleString()
                    : "Never"}
                </TableCell>
                <TableCell className="text-right">
                  <Badge
                    variant={
                      entry.openMailboxFindings > 0 ? "warning" : "secondary"
                    }
                    className="font-mono tabular-nums"
                  >
                    {entry.openMailboxFindings}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function AttackPathsCard({ paths }: { paths: AttackPath[] }) {
  const [query, setQuery] = useState("");
  const [highOnly, setHighOnly] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const filtered = useMemo(() => {
    // Attack paths are already pre-ranked by the API. Client-side filtering keeps
    // the table exploratory without changing the backend's top-path selection.
    const q = query.trim().toLowerCase();
    let rows = paths;
    if (q) {
      rows = rows.filter(
        (p) =>
          p.title.toLowerCase().includes(q) ||
          p.entryPoint.toLowerCase().includes(q) ||
          p.target.toLowerCase().includes(q) ||
          p.owner.toLowerCase().includes(q)
      );
    }
    if (highOnly) rows = rows.filter((p) => p.score >= 75);
    const dir = sortDir === "asc" ? 1 : -1;
    // Always sort a copy so the memo never mutates the overview payload shared
    // with other cards.
    return [...rows].sort((a, b) => {
      switch (sortKey) {
        case "title":
          return a.title.localeCompare(b.title) * dir;
        case "owner":
          return a.owner.localeCompare(b.owner) * dir;
        case "score":
        default:
          return (a.score - b.score) * dir;
      }
    });
  }, [paths, query, highOnly, sortKey, sortDir]);

  function toggleSort(next: SortKey) {
    if (sortKey === next) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(next);
      // Scores default high-to-low for triage; text columns default A-to-Z for
      // scanning owners and path names.
      setSortDir(next === "score" ? "desc" : "asc");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack paths</CardTitle>
        <CardDescription>
          Highest-scoring blast radius scenarios across the connected graph.
        </CardDescription>
      </CardHeader>
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div className="relative w-full max-w-xs">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search title, owner, target…"
            aria-label="Search attack paths"
            className="h-8 pl-7 text-xs"
          />
        </div>
        <button
          type="button"
          onClick={() => setHighOnly((p) => !p)}
          aria-pressed={highOnly}
          className={cn(
            "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
            highOnly
              ? "border-critical/40 bg-critical/15 text-critical"
              : "border-border/80 bg-card text-muted-foreground hover:border-border hover:text-foreground"
          )}
        >
          High blast radius
        </button>
        <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
          {filtered.length} of {paths.length}
        </span>
      </div>
      <CardContent className="p-0">
        {filtered.length === 0 ? (
          <EmptyState
            title={paths.length === 0 ? "No attack paths surfaced" : "No matches"}
            description={
              paths.length === 0
                ? "When findings combine with privileged identities or exposed data, the highest-impact paths will appear here."
                : "Try a different search or remove the high-risk filter."
            }
            className="m-6"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <SortableHead
                  label="Path"
                  active={sortKey === "title"}
                  dir={sortDir}
                  onClick={() => toggleSort("title")}
                />
                <TableHead>Entry</TableHead>
                <TableHead>Target</TableHead>
                <SortableHead
                  label="Owner"
                  active={sortKey === "owner"}
                  dir={sortDir}
                  onClick={() => toggleSort("owner")}
                />
                <SortableHead
                  label="Score"
                  align="right"
                  active={sortKey === "score"}
                  dir={sortDir}
                  onClick={() => toggleSort("score")}
                />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((path) => (
                <TableRow key={path.id}>
                  <TableCell className="font-medium">
                    {path.title}
                    <p className="text-xs text-muted-foreground">
                      {path.reason}
                    </p>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {path.entryPoint}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {path.target}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {path.owner}
                  </TableCell>
                  <TableCell className="text-right">
                    <Badge
                      variant={path.score >= 75 ? "critical" : "warning"}
                      className="font-mono tabular-nums"
                    >
                      {path.score}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function AssetListCard({
  title,
  description,
  assets,
  emptyMessage,
  badgeFor,
  valueFor
}: {
  title: string;
  description?: string;
  assets: SecurityAsset[];
  emptyMessage: string;
  badgeFor: (
    asset: SecurityAsset
  ) => "critical" | "warning" | "secondary" | "destructive";
  valueFor: (asset: SecurityAsset) => string;
}) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return assets;
    // These cards receive already-curated asset groups from the overview API, so
    // search only narrows by analyst-readable name/summary instead of re-scoring.
    return assets.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        (a.summary ?? "").toLowerCase().includes(q)
    );
  }, [assets, query]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description ? (
          <CardDescription>{description}</CardDescription>
        ) : null}
      </CardHeader>
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="relative w-full max-w-xs">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search…"
            aria-label={`Search ${title.toLowerCase()}`}
            className="h-8 pl-7 text-xs"
          />
        </div>
        <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
          {filtered.length} of {assets.length}
        </span>
      </div>
      <CardContent className="p-0">
        {filtered.length === 0 ? (
          <p className="px-6 py-6 text-sm text-muted-foreground">
            {assets.length === 0 ? emptyMessage : "No matches."}
          </p>
        ) : (
          <ul role="list" className="divide-y divide-border">
            {/* Cap compact cards so lower-priority assets do not crowd out the
                attack-path table above; the count still reflects all matches. */}
            {filtered.slice(0, 12).map((asset) => (
              <li
                key={asset.id}
                className="flex items-start justify-between gap-3 px-6 py-3"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-foreground">
                    {asset.name}
                  </p>
                  <p className="truncate text-xs text-muted-foreground">
                    {asset.summary || asset.type}
                  </p>
                </div>
                <Badge
                  variant={badgeFor(asset)}
                  className="font-mono tabular-nums"
                >
                  {valueFor(asset)}
                </Badge>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function EmailDomainHealthSummaryCard({
  domains
}: {
  domains: EmailDomainHealth[];
}) {
  const failing = domains.filter((domain) => domain.status === "FAILING").length;
  const warning = domains.filter((domain) => domain.status === "WARNING").length;
  const healthy = domains.filter((domain) => domain.status === "HEALTHY").length;
  const status =
    failing > 0 ? "FAILING" : warning > 0 ? "WARNING" : domains.length > 0 ? "HEALTHY" : "UNKNOWN";
  return (
    <Card>
      <CardHeader>
        <CardTitle>Email domain health</CardTitle>
        <CardDescription>
          SPF, DKIM, and DMARC posture for domains auto-discovered from integrations.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={statusBadgeVariant(status)}>{status.toLowerCase()}</Badge>
          <span className="font-mono text-xs text-muted-foreground tabular-nums">
            {domains.length} domains · {failing} failing · {warning} warning · {healthy} healthy
          </span>
        </div>
        <Button variant="outline" size="sm" asChild>
          <Link href="/security/email-domain-health">
            Open domain health
            <ArrowRight className="ml-2 h-3.5 w-3.5" aria-hidden />
          </Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function statusBadgeVariant(status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN") {
  if (status === "FAILING") return "critical";
  if (status === "WARNING") return "warning";
  if (status === "HEALTHY") return "secondary";
  return "outline";
}

type Tone = "neutral" | "signal" | "critical";

const toneRail: Record<Tone, string> = {
  neutral: "bg-border",
  signal: "bg-signal/70",
  critical: "bg-critical critical-pulse"
};

function Stat({
  label,
  value,
  helper,
  tone = "neutral"
}: {
  label: string;
  value: number;
  helper?: string;
  tone?: Tone;
}) {
  return (
    <Card className="relative overflow-hidden animate-fade-in-up">
      <span
        aria-hidden
        className={`absolute left-0 top-0 h-full w-[3px] ${toneRail[tone]}`}
      />
      <CardContent className="p-5">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        <p className="mt-2 font-mono text-2xl font-semibold tracking-tight text-foreground tabular-nums">
          {value}
        </p>
        {helper ? (
          <p className="mt-1 text-xs text-muted-foreground">{helper}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function SkeletonStat() {
  return (
    <Card>
      <CardContent className="space-y-2 p-5">
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-6 w-16" />
      </CardContent>
    </Card>
  );
}

function SortableHead({
  label,
  active,
  dir,
  onClick,
  align = "left"
}: {
  label: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
  align?: "left" | "right";
}) {
  const Icon = active ? (dir === "asc" ? ArrowUp : ArrowDown) : ChevronsUpDown;
  return (
    <TableHead className={align === "right" ? "text-right" : undefined}>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          active ? "text-foreground" : "text-muted-foreground"
        )}
        aria-label={`Sort by ${label}`}
      >
        <span>{label}</span>
        <Icon className="h-3 w-3" aria-hidden />
      </button>
    </TableHead>
  );
}
