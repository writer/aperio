"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowRight, Plug, ShieldAlert } from "lucide-react";
import {
  fetchDashboardMetrics,
  fetchFindings,
  type DashboardMetrics,
  type Finding
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import { Skeleton, MetricCardSkeleton } from "../ui/skeleton";
import { formatNumber } from "../../lib/format";
import { SeverityDistribution } from "./severity-distribution";
import { FindingsTable } from "../findings/findings-table";

const FINDINGS_LIMIT = 100;

export function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (mode: "initial" | "refresh" = "initial") => {
    if (mode === "initial") setLoading(true);
    else setReloading(true);
    setError("");
    try {
      const [m, findingsRes] = await Promise.all([
        fetchDashboardMetrics(),
        fetchFindings({ status: "OPEN", limit: FINDINGS_LIMIT })
      ]);
      setMetrics(m.data);
      setFindings(findingsRes.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load dashboard");
    } finally {
      setLoading(false);
      setReloading(false);
    }
  }, []);

  useEffect(() => {
    void load("initial");
  }, [load]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Overview"
        title="Posture dashboard"
        description="Tenant-scoped posture, ingestion, incidents, and the latest open findings."
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

      {error ? (
        <Alert variant="destructive" className="animate-fade-in-up">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Unable to load dashboard</AlertTitle>
          <AlertDescription className="flex items-center justify-between gap-3">
            <span>{error}</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void load("initial")}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <section
        aria-label="Posture metrics"
        className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
      >
        {loading || !metrics ? (
          <>
            <MetricCardSkeleton />
            <MetricCardSkeleton />
            <MetricCardSkeleton />
            <MetricCardSkeleton />
          </>
        ) : (
          <>
            <Metric
              icon={ShieldAlert}
              label="Overall risk score"
              value={formatNumber(metrics.totalRiskScore)}
              helper="Weighted by severity, recency, breadth"
              tone="signal"
            />
            <Metric
              icon={AlertTriangle}
              label="Open critical"
              value={formatNumber(metrics.openCriticalFindings)}
              helper="Needs an owner today"
              tone={metrics.openCriticalFindings > 0 ? "critical" : "neutral"}
            />
            <Metric
              icon={Plug}
              label="Connected apps"
              value={formatNumber(metrics.connectedApps)}
              helper="Active SaaS integrations"
              tone="neutral"
            />
            <Metric
              icon={Activity}
              label="Event ingestion"
              value={`${formatNumber(metrics.eventIngestionRate)}/min`}
              helper="Tenant-scoped events processed"
              tone="signal"
            />
          </>
        )}
      </section>

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <Card className="animate-fade-in-up">
          <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
            <div>
              <CardTitle>Open findings</CardTitle>
              <CardDescription>
                Filter, sort, and triage posture findings across all connected apps.
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link href="/apps">
                View by app
                <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </div>
            ) : (
              <FindingsTable
                findings={findings}
                pageSize={10}
                showStatusFilter={false}
                showUser={false}
                emptyTitle="No open findings"
                emptyDescription="When new posture findings surface, they will appear here."
              />
            )}
          </CardContent>
        </Card>

        <Card className="animate-fade-in-up">
          <CardHeader>
            <CardTitle>Severity mix</CardTitle>
            <CardDescription>
              Distribution across the most recent open findings.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-3">
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-2/3" />
              </div>
            ) : (
              <SeverityDistribution findings={findings} />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

type Tone = "neutral" | "signal" | "critical";

const toneAccent: Record<Tone, string> = {
  neutral: "text-muted-foreground",
  signal: "text-signal",
  critical: "text-critical"
};

const toneRail: Record<Tone, string> = {
  neutral: "bg-border",
  signal: "bg-signal/70",
  critical: "bg-critical critical-pulse"
};

function Metric({
  icon: Icon,
  label,
  value,
  helper,
  tone = "neutral"
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  helper: string;
  tone?: Tone;
}) {
  return (
    <Card className="relative overflow-hidden animate-fade-in-up">
      <span
        aria-hidden
        className={`absolute left-0 top-0 h-full w-[3px] ${toneRail[tone]}`}
      />
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <Icon className={`h-4 w-4 ${toneAccent[tone]}`} aria-hidden />
        </div>
        <p className="mt-3 font-mono text-3xl font-semibold tracking-tight text-foreground tabular-nums">
          {value}
        </p>
        <p className="mt-1.5 text-xs text-muted-foreground">{helper}</p>
      </CardContent>
    </Card>
  );
}
