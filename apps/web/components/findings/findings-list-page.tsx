"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchFindings, type Finding } from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { AsyncSection } from "../ui/async-section";
import { FindingsTable } from "./findings-table";
import { SeverityDistribution } from "../dashboard/severity-distribution";

const PAGE_LIMIT = 100;

export function FindingsListPage() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(
    async (mode: "initial" | "refresh" = "initial") => {
      if (mode === "initial") setLoading(true);
      else setReloading(true);
      setError("");
      try {
        const response = await fetchFindings({
          status: "ALL",
          limit: PAGE_LIMIT
        });
        setFindings(response.data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to load findings");
      } finally {
        setLoading(false);
        setReloading(false);
      }
    },
    []
  );

  useEffect(() => {
    void load("initial");
  }, [load]);

  const stats = useMemo(() => {
    if (!findings) return null;
    const open = findings.filter((f) => f.status === "OPEN");
    const critical = open.filter((f) => f.severity === "CRITICAL").length;
    const avgRisk =
      open.length === 0
        ? 0
        : Math.round(
            open.reduce((sum, f) => sum + f.riskScore, 0) / open.length
          );
    return {
      total: findings.length,
      open: open.length,
      critical,
      avgRisk
    };
  }, [findings]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Findings"
        title="All findings"
        description="Sort, filter, and triage every finding across the tenant."
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
        data={findings}
        loading={loading}
        error={error}
        className="space-y-5"
        onRetry={() => void load("initial")}
        errorTitle="Unable to load findings"
        skeleton={
          <div className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-4">
              <StatSkeleton />
              <StatSkeleton />
              <StatSkeleton />
              <StatSkeleton />
            </div>
            <Card>
              <CardContent className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </CardContent>
            </Card>
          </div>
        }
      >
        {(rows) => (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat label="Total" value={stats?.total ?? 0} />
              <Stat
                label="Open"
                value={stats?.open ?? 0}
                tone="signal"
              />
              <Stat
                label="Open · Critical"
                value={stats?.critical ?? 0}
                tone={stats && stats.critical > 0 ? "critical" : "neutral"}
              />
              <Stat label="Avg open risk" value={stats?.avgRisk ?? 0} />
            </section>

            <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
              <Card>
                <CardContent className="p-0">
                  <FindingsTable
                    findings={rows}
                    pageSize={15}
                    showRiskScore={false}
                    emptyTitle="No findings yet"
                    emptyDescription="Once connectors finish syncing, findings will appear here."
                  />
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-6">
                  <SeverityDistribution
                    findings={rows.filter((f) => f.status === "OPEN")}
                  />
                </CardContent>
              </Card>
            </div>
          </>
        )}
      </AsyncSection>
    </div>
  );
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
  tone = "neutral"
}: {
  label: string;
  value: number;
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
      </CardContent>
    </Card>
  );
}

function StatSkeleton() {
  return (
    <Card>
      <CardContent className="space-y-2 p-5">
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-6 w-16" />
      </CardContent>
    </Card>
  );
}
