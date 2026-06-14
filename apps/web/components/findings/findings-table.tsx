"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  Search,
  X
} from "lucide-react";
import type { Finding } from "../../lib/api";
import { Badge, SeverityBadge, type Severity } from "../ui/badge";
import { Button } from "../ui/button";
import { EmptyState } from "../ui/empty-state";
import { Input } from "../ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { cn } from "../../lib/utils";
import {
  findingUserLabel,
  formatRelative,
  providerLabel
} from "../../lib/format";

type StatusFilter = "ALL" | Finding["status"];
type SortKey = "detectedAt" | "riskScore" | "severity" | "title";
type SortDir = "asc" | "desc";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1
};

const STATUS_VARIANTS: Record<
  Finding["status"],
  "destructive" | "success" | "secondary"
> = {
  OPEN: "destructive",
  RESOLVED: "success",
  MUTED: "secondary"
};

const ALL_SEVERITIES: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO"
];

const STATUS_FILTERS: StatusFilter[] = ["ALL", "OPEN", "RESOLVED", "MUTED"];

export type FindingsTableProps = {
  findings: Finding[];
  pageSize?: number;
  showApp?: boolean;
  showUser?: boolean;
  showRiskScore?: boolean;
  showStatusFilter?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
  /** When provided, the empty state is suppressed when the unfiltered set is non-empty. */
  total?: number;
};

export function FindingsTable({
  findings,
  pageSize = 10,
  showApp = true,
  showUser = true,
  showRiskScore = true,
  showStatusFilter = true,
  emptyTitle = "No findings",
  emptyDescription = "Nothing matched the current filters."
}: FindingsTableProps) {
  const [severities, setSeverities] = React.useState<Set<Severity>>(new Set());
  const [status, setStatus] = React.useState<StatusFilter>("ALL");
  const [query, setQuery] = React.useState("");
  const [sortKey, setSortKey] = React.useState<SortKey>("detectedAt");
  const [sortDir, setSortDir] = React.useState<SortDir>("desc");
  const [page, setPage] = React.useState(0);

  React.useEffect(() => {
    setPage(0);
  }, [severities, status, query, findings.length]);

  const filtered = React.useMemo(() => {
    let rows = findings;
    if (severities.size > 0) {
      rows = rows.filter((row) => severities.has(row.severity));
    }
    if (status !== "ALL") {
      rows = rows.filter((row) => row.status === status);
    }
    const q = query.trim().toLowerCase();
    if (q.length > 0) {
      rows = rows.filter((row) => {
        const haystacks = [
          row.title,
          row.description,
          row.integration.displayName,
          providerLabel(row.integration.provider),
          findingUserLabel(row.evidence) ?? ""
        ];
        return haystacks.some((value) =>
          value.toLowerCase().includes(q)
        );
      });
    }
    const dir = sortDir === "asc" ? 1 : -1;
    const sorted = [...rows].sort((a, b) => {
      switch (sortKey) {
        case "riskScore":
          return (a.riskScore - b.riskScore) * dir;
        case "severity":
          return (
            (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) * dir
          );
        case "title":
          return a.title.localeCompare(b.title) * dir;
        case "detectedAt":
        default: {
          const at = new Date(a.detectedAt).getTime();
          const bt = new Date(b.detectedAt).getTime();
          return (at - bt) * dir;
        }
      }
    });
    return sorted;
  }, [findings, severities, status, query, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages - 1);
  const start = safePage * pageSize;
  const visible = filtered.slice(start, start + pageSize);

  function toggleSeverity(sev: Severity) {
    setSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  }

  function toggleSort(next: SortKey) {
    if (sortKey === next) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(next);
      setSortDir(next === "title" ? "asc" : "desc");
    }
  }

  const filtersActive =
    severities.size > 0 || status !== "ALL" || query.trim().length > 0;

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
        <div className="relative w-full sm:w-64">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="h-8 pl-8 pr-8 text-sm"
          />
          {query.length > 0 ? (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="h-3 w-3" aria-hidden />
            </button>
          ) : null}
        </div>
        <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Severity
        </span>
        <div className="flex flex-wrap items-center gap-1">
          {ALL_SEVERITIES.map((sev) => {
            const active = severities.has(sev);
            return (
              <button
                key={sev}
                type="button"
                onClick={() => toggleSeverity(sev)}
                aria-pressed={active}
                className={cn(
                  "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                  active
                    ? severityChipActive[sev]
                    : "border-border/80 bg-card text-muted-foreground hover:border-border hover:text-foreground"
                )}
              >
                {sev}
              </button>
            );
          })}
        </div>
        {showStatusFilter ? (
          <>
            <span className="ml-3 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Status
            </span>
            <div className="flex flex-wrap items-center gap-1">
              {STATUS_FILTERS.map((s) => {
                const active = status === s;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setStatus(s)}
                    aria-pressed={active}
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                      active
                        ? "border-signal/40 bg-signal/15 text-signal"
                        : "border-border/80 bg-card text-muted-foreground hover:border-border hover:text-foreground"
                    )}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
          </>
        ) : null}
        <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
          {filtered.length} of {findings.length}
        </span>
        {filtersActive ? (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-xs"
            onClick={() => {
              setSeverities(new Set());
              setStatus("ALL");
              setQuery("");
            }}
          >
            Clear
          </Button>
        ) : null}
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title={emptyTitle}
          description={
            filtersActive
              ? "No findings match the current filters. Clear them to see all results."
              : emptyDescription
          }
          className="m-6"
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <SortHeader
                  label="Finding"
                  active={sortKey === "title"}
                  dir={sortDir}
                  onClick={() => toggleSort("title")}
                />
                {showApp ? <TableHead>App</TableHead> : null}
                {showUser ? <TableHead>User</TableHead> : null}
                <SortHeader
                  label="Severity"
                  active={sortKey === "severity"}
                  dir={sortDir}
                  onClick={() => toggleSort("severity")}
                />
                {showStatusFilter ? <TableHead>Status</TableHead> : null}
                {showRiskScore ? (
                  <SortHeader
                    label="Risk"
                    align="right"
                    active={sortKey === "riskScore"}
                    dir={sortDir}
                    onClick={() => toggleSort("riskScore")}
                  />
                ) : null}
                <SortHeader
                  label="Detected"
                  align="right"
                  active={sortKey === "detectedAt"}
                  dir={sortDir}
                  onClick={() => toggleSort("detectedAt")}
                />
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((finding) => (
                <TableRow key={finding.id}>
                  <TableCell className="font-medium">
                    <Link
                      href={`/findings/${finding.id}`}
                      className="rounded-sm hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {finding.title}
                    </Link>
                    {finding.tags && finding.tags.length > 0 ? (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {finding.tags.map((tag) => (
                          <span
                            key={tag}
                            className="inline-flex items-center rounded border border-border bg-muted/50 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </TableCell>
                  {showApp ? (
                    <TableCell className="text-muted-foreground">
                      {finding.integration.displayName}
                      <span className="ml-1 text-xs">
                        ({providerLabel(finding.integration.provider)})
                      </span>
                    </TableCell>
                  ) : null}
                  {showUser ? (
                    <TableCell className="text-muted-foreground">
                      {(() => {
                        const user = findingUserLabel(finding.evidence);
                        return user ? (
                          <span className="font-mono text-xs">{user}</span>
                        ) : (
                          <span className="text-xs text-muted-foreground/70">
                            —
                          </span>
                        );
                      })()}
                    </TableCell>
                  ) : null}
                  <TableCell>
                    <SeverityBadge severity={finding.severity} />
                  </TableCell>
                  {showStatusFilter ? (
                    <TableCell>
                      <Badge variant={STATUS_VARIANTS[finding.status]}>
                        {finding.status}
                      </Badge>
                    </TableCell>
                  ) : null}
                  {showRiskScore ? (
                    <TableCell className="text-right font-mono text-sm text-foreground tabular-nums">
                      {finding.riskScore}
                    </TableCell>
                  ) : null}
                  <TableCell className="text-right font-mono text-xs text-muted-foreground tabular-nums">
                    {formatRelative(finding.detectedAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {totalPages > 1 ? (
            <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3 text-xs">
              <span className="font-mono text-muted-foreground tabular-nums">
                Page {safePage + 1} of {totalPages}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={safePage === 0}
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
                  Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 px-2"
                  onClick={() =>
                    setPage((p) => Math.min(totalPages - 1, p + 1))
                  }
                  disabled={safePage >= totalPages - 1}
                  aria-label="Next page"
                >
                  Next
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                </Button>
              </div>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

const severityChipActive: Record<Severity, string> = {
  CRITICAL: "border-critical/50 bg-critical/15 text-critical",
  HIGH: "border-destructive/40 bg-destructive/15 text-destructive",
  MEDIUM: "border-warning/40 bg-warning/15 text-warning",
  LOW: "border-border bg-muted text-foreground",
  INFO: "border-border bg-muted text-foreground"
};

function SortHeader({
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
