"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  RadioTower,
  ShieldAlert,
  Zap
} from "lucide-react";
import {
  fetchSaasIncidents,
  type SaasIncident,
  type SaasIncidentMetrics,
  type SaasIncidentStatus
} from "../../lib/api";
import { formatDateTime, formatNumber } from "../../lib/format";
import { PageHeader } from "../layout/page-header";
import { AsyncSection } from "../ui/async-section";
import { Badge, SeverityBadge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import { EmptyState } from "../ui/empty-state";
import { Skeleton } from "../ui/skeleton";

const PAGE_LIMIT = 100;

export function IncidentsListPage() {
  const [incidents, setIncidents] = useState<SaasIncident[] | null>(null);
  const [metrics, setMetrics] = useState<SaasIncidentMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (mode: "initial" | "refresh" = "initial") => {
    if (mode === "initial") setLoading(true);
    else setReloading(true);
    setError("");
    try {
      const response = await fetchSaasIncidents({
        status: "ALL",
        limit: PAGE_LIMIT
      });
      setIncidents(response.data);
      setMetrics(response.metrics);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load incidents");
    } finally {
      setLoading(false);
      setReloading(false);
    }
  }, []);

  useEffect(() => {
    void load("initial");
  }, [load]);

  const active = useMemo(
    () =>
      incidents?.filter(
        (incident) =>
          incident.status === "OPEN" || incident.status === "INVESTIGATING"
      ) ?? [],
    [incidents]
  );

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="SaaS Detection & Response"
        title="SaaS incidents"
        description="Investigate high-signal SaaS detections with Cerebro context, timelines, and response actions."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => void load("refresh")}
            loading={reloading}
            loadingText="Refreshing…"
          >
            Refresh
          </Button>
        }
      />

      <AsyncSection
        data={incidents}
        loading={loading}
        error={error}
        className="space-y-5"
        onRetry={() => void load("initial")}
        errorTitle="Unable to load posture incidents"
        skeleton={
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <MetricSkeleton />
              <MetricSkeleton />
              <MetricSkeleton />
              <MetricSkeleton />
            </div>
            <Card>
              <CardContent className="space-y-3 p-6">
                <Skeleton className="h-5 w-64" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-4/5" />
              </CardContent>
            </Card>
          </div>
        }
      >
        {(rows) => (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Metric
                icon={ShieldAlert}
                label="Active incidents"
                value={formatNumber(active.length)}
                tone={active.length > 0 ? "critical" : "neutral"}
              />
              <Metric
                icon={Zap}
                label="Critical active"
                value={formatNumber(metrics?.criticalOpen ?? 0)}
                tone={(metrics?.criticalOpen ?? 0) > 0 ? "critical" : "neutral"}
              />
              <Metric
                icon={Clock3}
                label="Pending response"
                value={formatNumber(metrics?.responseActionsPending ?? 0)}
                tone="signal"
              />
              <Metric
                icon={CheckCircle2}
                label="Contained / resolved"
                value={formatNumber(
                  (metrics?.contained ?? 0) + (metrics?.resolved ?? 0)
                )}
                tone="neutral"
              />
            </section>

            <Card>
              <CardHeader>
                <CardTitle>Incident queue</CardTitle>
                <CardDescription>
                  Grouped posture findings with linked context, SLA, and response
                  progress.
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {rows.length === 0 ? (
                  <div className="p-6">
                    <EmptyState
                      title="No posture incidents yet"
                      description="Create incidents from high-signal detections to drive triage and response."
                    />
                  </div>
                ) : (
                  <div className="divide-y divide-border">
                    {rows.map((incident) => (
                      <IncidentRow key={incident.id} incident={incident} />
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </AsyncSection>
    </div>
  );
}

function IncidentRow({ incident }: { incident: SaasIncident }) {
  const cerebroSignalCount = incident.cerebroContext.graphSignals.length;
  const cerebroMCPToolCount = incident.cerebroContext.mcp?.tools.length ?? 0;

  return (
    <Link
      href={`/incidents/${incident.id}`}
      className="group grid gap-3 p-5 transition-colors hover:bg-muted/35 lg:grid-cols-[1fr_220px]"
    >
      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          <Badge variant="outline">Confidence {incident.confidenceScore}</Badge>
          {incident.ownerTeam ? (
            <Badge variant="secondary">{incident.ownerTeam}</Badge>
          ) : null}
          <Badge variant="signal">
            <RadioTower className="h-3.5 w-3.5" />
            {cerebroSignalCount} Cerebro signals
          </Badge>
        </div>
        <div>
          <h3 className="truncate text-sm font-semibold text-foreground">
            {incident.title}
          </h3>
          <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
            {incident.summary}
          </p>
        </div>
        <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
          <span>{incident.findingCount} findings</span>
          <span>{incident.responseActionCount} response actions</span>
          <span>{incident.cerebroContext.mode.replaceAll("-", " ")} graph context</span>
          {cerebroMCPToolCount > 0 ? (
            <span>{cerebroMCPToolCount} Cerebro MCP tools</span>
          ) : null}
          <span>Last activity {formatDateTime(incident.lastActivityAt)}</span>
        </div>
      </div>
      <div className="flex items-center justify-between gap-3 lg:justify-end">
        <div className="text-right text-xs text-muted-foreground">
          <div>SLA {formatDateTime(incident.slaDueAt)}</div>
          <div>{incident.assignee?.displayName ?? incident.assignee?.email ?? "Unassigned"}</div>
        </div>
        <ArrowRight
          className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-foreground"
          aria-hidden
        />
      </div>
    </Link>
  );
}

function StatusBadge({ status }: { status: SaasIncidentStatus }) {
  const variant =
    status === "RESOLVED"
      ? "success"
      : status === "CONTAINED"
        ? "signal"
        : status === "INVESTIGATING"
          ? "warning"
          : "destructive";
  return (
    <Badge variant={variant} className="uppercase">
      {status.replaceAll("_", " ")}
    </Badge>
  );
}

type Tone = "neutral" | "signal" | "critical";

const toneRail: Record<Tone, string> = {
  neutral: "bg-border",
  signal: "bg-signal/70",
  critical: "bg-critical critical-pulse"
};

const toneIcon: Record<Tone, string> = {
  neutral: "text-muted-foreground",
  signal: "text-signal",
  critical: "text-critical"
};

function Metric({
  icon: Icon,
  label,
  value,
  tone
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  tone: Tone;
}) {
  return (
    <Card className="relative overflow-hidden">
      <span
        aria-hidden
        className={`absolute left-0 top-0 h-full w-[3px] ${toneRail[tone]}`}
      />
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <Icon className={`h-4 w-4 ${toneIcon[tone]}`} aria-hidden />
        </div>
        <p className="mt-2 font-mono text-2xl font-semibold tracking-tight tabular-nums">
          {value}
        </p>
      </CardContent>
    </Card>
  );
}

function MetricSkeleton() {
  return (
    <Card>
      <CardContent className="space-y-2 p-5">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-7 w-14" />
      </CardContent>
    </Card>
  );
}
