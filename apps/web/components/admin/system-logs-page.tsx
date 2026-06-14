"use client";

import * as React from "react";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Filter,
  Pause,
  Play,
  RefreshCw,
  Search,
  Sparkles,
  X
} from "lucide-react";
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
import { Input } from "../ui/form";
import { cn } from "../../lib/utils";

type Severity = "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE";

const SEVERITIES: Severity[] = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

const severityTone: Record<
  Severity,
  { dot: string; pill: string; bar: string; text: string }
> = {
  ERROR: {
    dot: "bg-destructive",
    pill: "border-destructive/30 bg-destructive/15 text-destructive",
    bar: "bg-destructive/80",
    text: "text-destructive"
  },
  WARN: {
    dot: "bg-warning",
    pill: "border-warning/30 bg-warning/15 text-warning",
    bar: "bg-warning/80",
    text: "text-warning"
  },
  INFO: {
    dot: "bg-signal",
    pill: "border-signal/40 bg-signal/15 text-signal",
    bar: "bg-signal/70",
    text: "text-signal"
  },
  DEBUG: {
    dot: "bg-muted-foreground/70",
    pill: "border-muted-foreground/30 bg-muted text-muted-foreground",
    bar: "bg-muted-foreground/40",
    text: "text-muted-foreground"
  },
  TRACE: {
    dot: "bg-muted-foreground/40",
    pill: "border-muted-foreground/20 bg-muted/60 text-muted-foreground",
    bar: "bg-muted-foreground/25",
    text: "text-muted-foreground"
  }
};

type LogEntry = {
  id: string;
  timestamp: number;
  severity: Severity;
  service: string;
  message: string;
  attributes: Record<string, string>;
};

const SERVICES = [
  "aperio-go-connect",
  "ingestion-worker",
  "siem-dispatcher",
  "google-workspace-poller",
  "google-workspace-directory-sync",
  "google-workspace-oauth-sync"
];

const RANGE_PRESETS: { label: string; minutes: number }[] = [
  { label: "Last 5m", minutes: 5 },
  { label: "Last 15m", minutes: 15 },
  { label: "Last 1h", minutes: 60 },
  { label: "Last 6h", minutes: 60 * 6 },
  { label: "Last 24h", minutes: 60 * 24 }
];

// Deterministic seeded PRNG so the mock dataset is stable across renders
// without pulling in a date-dependent random source on the server.
function mulberry32(seed: number) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function generateLogs(now: number, windowMinutes: number, seed = 1): LogEntry[] {
  const rng = mulberry32(seed);
  const windowMs = windowMinutes * 60_000;
  const targetCount = Math.min(2400, Math.max(280, Math.round(windowMinutes * 18)));
  const templates: { service: string; severity: Severity; message: string; attrs: Record<string, string> }[] = [
    {
      service: "aperio-go-connect",
      severity: "INFO",
      message: "connect.rpc completed",
      attrs: { route: "/aperio.v1.AperioService/ListFindings", status: "success", duration_ms: "8" }
    },
    {
      service: "aperio-go-connect",
      severity: "WARN",
      message: "rate limit threshold reached for tenant",
      attrs: { tenant: "org_demo_security", limit: "120/min", remaining: "0" }
    },
    {
      service: "aperio-go-connect",
      severity: "ERROR",
      message: "session refresh failed: encryption key rotated",
      attrs: { user_id: "usr_demo_001", error: "EKM_KEY_NOT_FOUND" }
    },
    {
      service: "ingestion-worker",
      severity: "INFO",
      message: "drained ingestion_jobs batch",
      attrs: { batch_size: "32", provider: "GOOGLE_WORKSPACE", duration_ms: "412" }
    },
    {
      service: "ingestion-worker",
      severity: "ERROR",
      message: "dead-lettered job after max attempts",
      attrs: { job_id: "job_8f3a2c1", attempts: "3", reason: "ColumnNotFound" }
    },
    {
      service: "ingestion-worker",
      severity: "WARN",
      message: "duplicate event suppressed",
      attrs: { idempotency_key: "evt_5a9b...", source: "aperio.force_sync" }
    },
    {
      service: "siem-dispatcher",
      severity: "INFO",
      message: "delivered finding to destination",
      attrs: { destination: "siem_demo_json_file", kind: "JSON_FILE", duration_ms: "27" }
    },
    {
      service: "siem-dispatcher",
      severity: "WARN",
      message: "retry scheduled for downstream timeout",
      attrs: { destination: "siem_splunk_prod", retry_in_ms: "3000", attempts: "1" }
    },
    {
      service: "siem-dispatcher",
      severity: "ERROR",
      message: "destination credential decryption failed",
      attrs: { destination: "siem_panther", error: "DECRYPT_AUTH_TAG" }
    },
    {
      service: "google-workspace-poller",
      severity: "INFO",
      message: "wake-up triggered out-of-band poll",
      attrs: { integration: "int_demo_google", channel: "aperio_google_workspace_sync_requested" }
    },
    {
      service: "google-workspace-poller",
      severity: "WARN",
      message: "integration poll failed: oauth client unresolved",
      attrs: { integration: "int_demo_google", organization: "org_demo_security" }
    },
    {
      service: "google-workspace-poller",
      severity: "ERROR",
      message: "Reports API request returned 401",
      attrs: { integration: "int_demo_google", endpoint: "admin.googleapis.com/admin/reports/v1/activity" }
    },
    {
      service: "google-workspace-directory-sync",
      severity: "INFO",
      message: "directory sweep complete",
      attrs: { users_processed: "1284", duration_ms: "9120" }
    },
    {
      service: "google-workspace-oauth-sync",
      severity: "INFO",
      message: "oauth grant scan complete",
      attrs: { grants: "47", new_apps: "2" }
    },
    {
      service: "google-workspace-oauth-sync",
      severity: "DEBUG",
      message: "skipping unchanged grant",
      attrs: { grant_id: "oauth_grant_223", reason: "etag_match" }
    },
    {
      service: "aperio-go-connect",
      severity: "DEBUG",
      message: "compat audit row written",
      attrs: { entity: "integration_connection", actor: "security@aperio.local" }
    },
    {
      service: "aperio-go-connect",
      severity: "TRACE",
      message: "session middleware ran",
      attrs: {
        route: "/aperio.v1.AperioService/ListIntegrations",
        duration_ms: "1"
      }
    }
  ];

  const out: LogEntry[] = [];
  for (let i = 0; i < targetCount; i++) {
    const t = now - Math.floor(rng() * windowMs);
    const tpl = templates[Math.floor(rng() * templates.length)];
    out.push({
      id: `log_${i.toString(16).padStart(6, "0")}`,
      timestamp: t,
      severity: tpl.severity,
      service: tpl.service,
      message: tpl.message,
      attributes: tpl.attrs
    });
  }
  return out.sort((a, b) => b.timestamp - a.timestamp);
}

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${d
    .getMilliseconds()
    .toString()
    .padStart(3, "0")}`;
}

function bucketize(
  logs: LogEntry[],
  now: number,
  windowMinutes: number,
  bucketCount = 60
) {
  const windowMs = windowMinutes * 60_000;
  const bucketMs = windowMs / bucketCount;
  const start = now - windowMs;
  const buckets = Array.from({ length: bucketCount }, () => ({
    ERROR: 0,
    WARN: 0,
    INFO: 0,
    DEBUG: 0,
    TRACE: 0
  })) as { ERROR: number; WARN: number; INFO: number; DEBUG: number; TRACE: number }[];
  for (const log of logs) {
    const idx = Math.min(
      bucketCount - 1,
      Math.max(0, Math.floor((log.timestamp - start) / bucketMs))
    );
    buckets[idx][log.severity] += 1;
  }
  return { buckets, bucketMs };
}

export function SystemLogsPage() {
  const [now, setNow] = React.useState<number>(() => Date.now());
  const [rangeIdx, setRangeIdx] = React.useState<number>(2);
  const [query, setQuery] = React.useState("");
  const [activeSeverities, setActiveSeverities] = React.useState<Set<Severity>>(
    () => new Set(SEVERITIES)
  );
  const [activeServices, setActiveServices] = React.useState<Set<string>>(
    () => new Set(SERVICES)
  );
  const [liveTail, setLiveTail] = React.useState<boolean>(false);
  const [expanded, setExpanded] = React.useState<string | null>(null);

  const windowMinutes = RANGE_PRESETS[rangeIdx].minutes;

  React.useEffect(() => {
    if (!liveTail) return;
    const id = window.setInterval(() => setNow(Date.now()), 2000);
    return () => window.clearInterval(id);
  }, [liveTail]);

  const allLogs = React.useMemo(
    () => generateLogs(now, windowMinutes, 42),
    [now, windowMinutes]
  );

  const filteredLogs = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return allLogs.filter((log) => {
      if (!activeSeverities.has(log.severity)) return false;
      if (!activeServices.has(log.service)) return false;
      if (!q) return true;
      if (log.message.toLowerCase().includes(q)) return true;
      if (log.service.toLowerCase().includes(q)) return true;
      for (const [k, v] of Object.entries(log.attributes)) {
        if (k.toLowerCase().includes(q) || v.toLowerCase().includes(q)) return true;
      }
      return false;
    });
  }, [allLogs, activeSeverities, activeServices, query]);

  const { buckets, bucketMs } = React.useMemo(
    () => bucketize(filteredLogs, now, windowMinutes),
    [filteredLogs, now, windowMinutes]
  );

  const maxBucket = React.useMemo(
    () =>
      buckets.reduce(
        (max, b) => Math.max(max, b.ERROR + b.WARN + b.INFO + b.DEBUG + b.TRACE),
        0
      ),
    [buckets]
  );

  const severityCounts = React.useMemo(() => {
    const counts: Record<Severity, number> = {
      ERROR: 0,
      WARN: 0,
      INFO: 0,
      DEBUG: 0,
      TRACE: 0
    };
    for (const log of filteredLogs) counts[log.severity] += 1;
    return counts;
  }, [filteredLogs]);

  const topServices = React.useMemo(() => {
    const map = new Map<string, number>();
    for (const log of filteredLogs) {
      map.set(log.service, (map.get(log.service) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [filteredLogs]);

  const topPatterns = React.useMemo(() => {
    const map = new Map<string, { count: number; severity: Severity; service: string }>();
    for (const log of filteredLogs) {
      const cur = map.get(log.message);
      if (cur) {
        cur.count += 1;
      } else {
        map.set(log.message, { count: 1, severity: log.severity, service: log.service });
      }
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5);
  }, [filteredLogs]);

  const errorRate =
    filteredLogs.length === 0
      ? 0
      : Math.round(
          ((severityCounts.ERROR + severityCounts.WARN) / filteredLogs.length) *
            100
        );

  function toggleSeverity(s: Severity) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function toggleService(s: string) {
    setActiveServices((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Reports"
        title="System logs"
        description="Structured logs from every Aperio worker and the Connect API. Filter by severity, service, or attribute; tail live as new events arrive."
        actions={
          <>
            <Button
              variant={liveTail ? "default" : "outline"}
              size="sm"
              onClick={() => setLiveTail((v) => !v)}
              aria-pressed={liveTail}
            >
              {liveTail ? (
                <Pause className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <Play className="h-3.5 w-3.5" aria-hidden />
              )}
              {liveTail ? "Pause tail" : "Live tail"}
            </Button>
            <div className="flex items-center gap-1 rounded-md border border-border bg-card/60 p-0.5">
              <Clock
                className="ml-1.5 h-3.5 w-3.5 text-muted-foreground"
                aria-hidden
              />
              {RANGE_PRESETS.map((p, i) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => setRangeIdx(i)}
                  className={cn(
                    "rounded-sm px-2 py-1 text-xs font-medium transition-colors",
                    rangeIdx === i
                      ? "bg-muted text-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setNow(Date.now())}
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              Refresh
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card/60 p-2">
        <div className="relative min-w-[240px] flex-1">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Search message or attributes (e.g. "401" or route:/api)'
            aria-label="Search logs"
            className="h-8 pl-7 text-xs"
          />
          {query ? (
            <button
              type="button"
              aria-label="Clear search"
              onClick={() => setQuery("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <X className="h-3 w-3" aria-hidden />
            </button>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <Filter
            className="h-3.5 w-3.5 text-muted-foreground"
            aria-hidden
          />
          {SEVERITIES.map((s) => {
            const active = activeSeverities.has(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSeverity(s)}
                aria-pressed={active}
                className={cn(
                  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide transition-colors",
                  active
                    ? severityTone[s].pill
                    : "border-border bg-background text-muted-foreground hover:border-foreground/30"
                )}
              >
                <span
                  aria-hidden
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    active ? severityTone[s].dot : "bg-muted-foreground/40"
                  )}
                />
                {s}
              </button>
            );
          })}
        </div>
        <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
          {filteredLogs.length.toLocaleString()} events
        </span>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-end justify-between gap-3 p-4 pb-2">
          <div className="flex flex-col gap-1">
            <CardTitle>Log volume</CardTitle>
            <CardDescription>
              Stacked counts by severity over the last {RANGE_PRESETS[rangeIdx].label.toLowerCase().replace("last ", "")}.
            </CardDescription>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
            {SEVERITIES.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className={cn("h-2 w-2 rounded-sm", severityTone[s].bar)}
                />
                {s.toLowerCase()}
              </span>
            ))}
          </div>
        </CardHeader>
        <CardContent className="p-4 pt-2">
          <div
            role="img"
            aria-label="Log volume histogram"
            className="flex h-32 items-end gap-[2px]"
          >
            {buckets.map((b, i) => {
              const total = b.ERROR + b.WARN + b.INFO + b.DEBUG + b.TRACE;
              const heightPct = maxBucket === 0 ? 0 : (total / maxBucket) * 100;
              return (
                <div
                  key={i}
                  className="flex h-full flex-1 flex-col-reverse"
                  style={{ minHeight: 1 }}
                  title={`${total} events`}
                >
                  <div
                    className="flex w-full flex-col-reverse overflow-hidden rounded-t-[2px]"
                    style={{ height: `${heightPct}%` }}
                  >
                    {SEVERITIES.map((s) =>
                      b[s] > 0 ? (
                        <div
                          key={s}
                          className={severityTone[s].bar}
                          style={{ flexGrow: b[s] }}
                        />
                      ) : null
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="mt-2 flex justify-between font-mono text-[10px] text-muted-foreground">
            <span>
              {new Date(now - windowMinutes * 60_000).toLocaleTimeString()}
            </span>
            <span>now</span>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_280px]">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-3 p-4 pb-2">
            <div className="flex flex-col gap-1">
              <CardTitle>Events</CardTitle>
              <CardDescription>
                {filteredLogs.length.toLocaleString()} matching ·{" "}
                {severityCounts.ERROR} error · {severityCounts.WARN} warn ·{" "}
                {errorRate}% error+warn share
              </CardDescription>
            </div>
            {liveTail ? (
              <Badge variant="signal" className="uppercase">
                <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-signal" />
                Live
              </Badge>
            ) : null}
          </CardHeader>
          <CardContent className="max-h-[640px] overflow-y-auto p-0">
            {filteredLogs.length === 0 ? (
              <div className="px-6 py-12 text-center text-sm text-muted-foreground">
                No log events match the current filters.
              </div>
            ) : (
              <ul className="divide-y divide-border font-mono text-[12px]">
                {filteredLogs.slice(0, 400).map((log) => {
                  const open = expanded === log.id;
                  return (
                    <li
                      key={log.id}
                      className="flex flex-col"
                    >
                      <button
                        type="button"
                        onClick={() => setExpanded(open ? null : log.id)}
                        className="grid w-full grid-cols-[16px_104px_72px_minmax(140px,180px)_1fr] items-baseline gap-2 px-4 py-1.5 text-left hover:bg-muted/40"
                      >
                        {open ? (
                          <ChevronDown
                            className="h-3 w-3 text-muted-foreground"
                            aria-hidden
                          />
                        ) : (
                          <ChevronRight
                            className="h-3 w-3 text-muted-foreground"
                            aria-hidden
                          />
                        )}
                        <span className="tabular-nums text-muted-foreground">
                          {formatTimestamp(log.timestamp)}
                        </span>
                        <span
                          className={cn(
                            "rounded-sm border px-1.5 text-[10px] font-semibold uppercase tracking-wide",
                            severityTone[log.severity].pill
                          )}
                        >
                          {log.severity}
                        </span>
                        <span className="truncate text-muted-foreground">
                          {log.service}
                        </span>
                        <span className="truncate text-foreground">
                          {log.message}
                        </span>
                      </button>
                      {open ? (
                        <div className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1 border-l-2 border-border bg-muted/30 px-6 py-3 text-[11px]">
                          <span className="text-muted-foreground">timestamp</span>
                          <span className="tabular-nums">
                            {new Date(log.timestamp).toISOString()}
                          </span>
                          <span className="text-muted-foreground">severity</span>
                          <span
                            className={cn(
                              "font-semibold uppercase tracking-wide",
                              severityTone[log.severity].text
                            )}
                          >
                            {log.severity}
                          </span>
                          <span className="text-muted-foreground">service</span>
                          <span>{log.service}</span>
                          <span className="text-muted-foreground">message</span>
                          <span className="text-foreground">{log.message}</span>
                          {Object.entries(log.attributes).map(([k, v]) => (
                            <React.Fragment key={k}>
                              <span className="text-muted-foreground">{k}</span>
                              <span className="break-all">{v}</span>
                            </React.Fragment>
                          ))}
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            )}
            {filteredLogs.length > 400 ? (
              <div className="border-t border-border px-4 py-2 text-center text-[11px] text-muted-foreground">
                Showing first 400 of {filteredLogs.length.toLocaleString()} —
                narrow your filters or query to see more.
              </div>
            ) : null}
          </CardContent>
        </Card>

        <aside className="flex flex-col gap-4">
          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle className="flex items-center gap-2">
                <Filter className="h-3.5 w-3.5" aria-hidden /> Services
              </CardTitle>
              <CardDescription>
                Click to include or exclude a service.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-1 p-2">
              {SERVICES.map((s) => {
                const active = activeServices.has(s);
                const count = filteredLogs.filter((l) => l.service === s).length;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => toggleService(s)}
                    aria-pressed={active}
                    className={cn(
                      "flex items-center justify-between rounded-md px-2 py-1.5 text-xs transition-colors",
                      active
                        ? "bg-muted/60 text-foreground"
                        : "text-muted-foreground hover:bg-muted/40"
                    )}
                  >
                    <span className="truncate font-mono">{s}</span>
                    <span className="ml-2 shrink-0 tabular-nums text-muted-foreground">
                      {count.toLocaleString()}
                    </span>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle>Severity mix</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 p-4 pt-0">
              {SEVERITIES.map((s) => {
                const c = severityCounts[s];
                const pct =
                  filteredLogs.length === 0 ? 0 : (c / filteredLogs.length) * 100;
                return (
                  <div key={s} className="flex flex-col gap-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1.5 font-semibold uppercase tracking-wide",
                          severityTone[s].text
                        )}
                      >
                        <span
                          aria-hidden
                          className={cn(
                            "h-1.5 w-1.5 rounded-full",
                            severityTone[s].dot
                          )}
                        />
                        {s}
                      </span>
                      <span className="font-mono tabular-nums text-muted-foreground">
                        {c.toLocaleString()} · {pct.toFixed(0)}%
                      </span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-sm bg-muted">
                      <div
                        className={cn("h-full", severityTone[s].bar)}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle className="flex items-center gap-2">
                <Sparkles className="h-3.5 w-3.5" aria-hidden /> Top patterns
              </CardTitle>
              <CardDescription>
                Auto-grouped by exact message.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 p-4 pt-0">
              {topPatterns.length === 0 ? (
                <span className="text-xs text-muted-foreground">
                  No patterns in window.
                </span>
              ) : (
                topPatterns.map(([msg, data]) => (
                  <div
                    key={msg}
                    className="flex flex-col gap-1 rounded-md border border-border/60 bg-muted/30 p-2"
                  >
                    <div className="flex items-center justify-between gap-2 text-[11px]">
                      <span
                        className={cn(
                          "rounded-sm border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide",
                          severityTone[data.severity].pill
                        )}
                      >
                        {data.severity}
                      </span>
                      <span className="font-mono tabular-nums text-muted-foreground">
                        ×{data.count}
                      </span>
                    </div>
                    <span className="line-clamp-2 text-xs text-foreground">
                      {msg}
                    </span>
                    <span className="truncate font-mono text-[10px] text-muted-foreground">
                      {data.service}
                    </span>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="p-4 pb-2">
              <CardTitle>Top services</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-1.5 p-4 pt-0">
              {topServices.map(([service, count]) => {
                const pct =
                  filteredLogs.length === 0
                    ? 0
                    : (count / filteredLogs.length) * 100;
                return (
                  <div key={service} className="flex flex-col gap-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="truncate font-mono text-foreground">
                        {service}
                      </span>
                      <span className="font-mono tabular-nums text-muted-foreground">
                        {count.toLocaleString()}
                      </span>
                    </div>
                    <div className="h-1 overflow-hidden rounded-sm bg-muted">
                      <div
                        className="h-full bg-signal/60"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}
