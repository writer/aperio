"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowRight, RefreshCw } from "lucide-react";
import {
  fetchEmailDomainHealth,
  fetchEmailDomainHealthDetail,
  refreshEmailDomainHealth,
  type EmailDomainHealth,
  type EmailDomainHealthDetail
} from "../../lib/api";
import { PageHeader } from "../layout/page-header";
import { AsyncSection } from "../ui/async-section";
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
import { Skeleton } from "../ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { cn } from "../../lib/utils";

export function EmailDomainHealthPage() {
  const [domains, setDomains] = useState<EmailDomainHealth[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [detail, setDetail] = useState<EmailDomainHealthDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  const loadDomains = useCallback(async (refreshIfStale = true) => {
    setLoading(true);
    setError("");
    try {
      const response = await fetchEmailDomainHealth({ refreshIfStale });
      setDomains(response.data);
      setSelectedDomain((current) =>
        current && response.data.some((row) => row.domain === current)
          ? current
          : response.data[0]?.domain ?? ""
      );
    } catch (err) {
      if (isUnavailableRpcError(err)) {
        setDomains([]);
        setSelectedDomain("");
        setError("");
        return;
      }
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load email domain health"
      );
      setDomains([]);
      setSelectedDomain("");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (domain: string) => {
    if (!domain) {
      setDetail(null);
      setDetailError("");
      return;
    }
    setDetailLoading(true);
    setDetailError("");
    try {
      const response = await fetchEmailDomainHealthDetail(domain);
      setDetail(response.data);
    } catch (err) {
      setDetail(null);
      setDetailError(
        err instanceof Error ? err.message : "Unable to load domain detail"
      );
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refreshEmailDomainHealth();
      await loadDomains(false);
      if (selectedDomain) {
        await loadDetail(selectedDomain);
      }
    } catch (err) {
      if (isUnavailableRpcError(err)) {
        setDomains([]);
        setSelectedDomain("");
        setDetail(null);
        setError("");
        return;
      }
      setError(
        err instanceof Error
          ? err.message
          : "Unable to refresh email domain health"
      );
    } finally {
      setRefreshing(false);
    }
  }, [loadDetail, loadDomains, selectedDomain]);

  useEffect(() => {
    void loadDomains(true);
  }, [loadDomains]);

  useEffect(() => {
    void loadDetail(selectedDomain);
  }, [loadDetail, selectedDomain]);

  const counts = useMemo(() => {
    const rows = domains ?? [];
    return {
      healthy: rows.filter((row) => row.status === "HEALTHY").length,
      warning: rows.filter((row) => row.status === "WARNING").length,
      failing: rows.filter((row) => row.status === "FAILING").length,
      unknown: rows.filter((row) => row.status === "UNKNOWN").length
    };
  }, [domains]);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Security"
        title="Email domain health"
        description="SPF, DKIM, DMARC posture with DNS records and issue diagnostics for domains discovered from connected integrations."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" asChild>
              <Link href="/security">
                Security graph
                <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
            <Button onClick={() => void refresh()} disabled={refreshing}>
              <RefreshCw
                className={cn("mr-2 h-3.5 w-3.5", refreshing && "animate-spin")}
                aria-hidden
              />
              Refresh checks
            </Button>
          </div>
        }
      />

      <AsyncSection
        data={domains}
        loading={loading}
        error={error}
        className="space-y-5"
        onRetry={() => void loadDomains(true)}
        errorTitle="Unable to load email domain health"
        skeleton={
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Skeleton className="h-24" />
              <Skeleton className="h-24" />
              <Skeleton className="h-24" />
              <Skeleton className="h-24" />
            </div>
            <Card>
              <CardContent className="space-y-2 p-6">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-2/3" />
              </CardContent>
            </Card>
          </div>
        }
      >
        {(rows) =>
          rows.length === 0 ? (
            <Card>
              <CardContent className="p-6">
                <EmptyState
                  title="No domains discovered yet"
                  description="Connect Google Workspace, Microsoft 365, or other identity/email integrations to auto-discover domains."
                />
              </CardContent>
            </Card>
          ) : (
            <>
              <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <StatusStat label="Healthy" value={counts.healthy} status="HEALTHY" />
                <StatusStat label="Warning" value={counts.warning} status="WARNING" />
                <StatusStat label="Failing" value={counts.failing} status="FAILING" />
                <StatusStat label="Unknown" value={counts.unknown} status="UNKNOWN" />
              </section>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
                <Card>
                  <CardHeader>
                    <CardTitle>Discovered domains</CardTitle>
                    <CardDescription>
                      Auto-discovered from integration connections.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Domain</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>SPF</TableHead>
                          <TableHead>DKIM</TableHead>
                          <TableHead>DMARC</TableHead>
                          <TableHead className="text-right">Issues</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {rows.map((row) => {
                          const selected = row.domain === selectedDomain;
                          return (
                            <TableRow
                              key={row.domain}
                              onClick={() => setSelectedDomain(row.domain)}
                              className={cn(
                                "cursor-pointer",
                                selected && "bg-muted/60"
                              )}
                            >
                              <TableCell className="font-medium">
                                {row.domain}
                                <p className="text-xs text-muted-foreground">
                                  {row.providerSources.join(", ")}
                                </p>
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={row.status} />
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={row.spfStatus} />
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={row.dkimStatus} />
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={row.dmarcStatus} />
                              </TableCell>
                              <TableCell className="text-right font-mono tabular-nums">
                                {row.issueCount}
                              </TableCell>
                              <TableCell className="text-right font-mono tabular-nums">
                                {row.score}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Domain details</CardTitle>
                    <CardDescription>
                      Records, diagnostics, and recommended fixes.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {detailLoading ? (
                      <div className="space-y-2">
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-5/6" />
                      </div>
                    ) : detailError ? (
                      <EmptyState
                        title="Unable to load details"
                        description={detailError}
                      />
                    ) : !detail ? (
                      <EmptyState
                        title="Select a domain"
                        description="Choose a domain row to inspect SPF, DKIM, DMARC records and issues."
                      />
                    ) : (
                      <>
                        <div className="grid gap-2 sm:grid-cols-3">
                          <ProtocolStat label="SPF" status={detail.domain.spfStatus} />
                          <ProtocolStat label="DKIM" status={detail.domain.dkimStatus} />
                          <ProtocolStat label="DMARC" status={detail.domain.dmarcStatus} />
                        </div>
                        <RecordBlock title="SPF records" records={detail.spfRecords} />
                        <RecordBlock title="DMARC records" records={detail.dmarcRecords} />
                        <RecordBlock title="MX records" records={detail.mxRecords} />
                        <RecordBlock title="Related records" records={detail.relatedRecords} />

                        <div className="space-y-2">
                          <h3 className="text-sm font-semibold">DKIM selectors</h3>
                          {detail.dkimSelectors.length === 0 ? (
                            <p className="text-sm text-muted-foreground">
                              No selectors found.
                            </p>
                          ) : (
                            <ul className="space-y-2">
                              {detail.dkimSelectors.map((selector) => (
                                <li
                                  key={selector.selector}
                                  className="rounded-md border border-border/70 p-2"
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <p className="font-mono text-xs">
                                      {selector.selector}
                                    </p>
                                    <div className="flex items-center gap-2">
                                      <StatusBadge status={selector.status} />
                                      <span className="text-xs text-muted-foreground">
                                        {selector.keyBits > 0
                                          ? `${selector.keyBits} bits`
                                          : "unknown key size"}
                                      </span>
                                    </div>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="space-y-2">
                          <h3 className="text-sm font-semibold">Issues</h3>
                          {detail.issues.length === 0 ? (
                            <p className="text-sm text-muted-foreground">
                              No issues detected.
                            </p>
                          ) : (
                            <ul className="space-y-2">
                              {detail.issues.map((issue) => (
                                <li
                                  key={`${issue.id}:${issue.code}`}
                                  className="rounded-md border border-border/70 p-2"
                                >
                                  <div className="flex items-center gap-2">
                                    <Badge variant={severityVariant(issue.severity)}>
                                      {issue.severity}
                                    </Badge>
                                    <Badge variant="outline">{issue.protocol}</Badge>
                                    <p className="text-sm font-medium">{issue.title}</p>
                                  </div>
                                  <p className="mt-1 text-sm text-muted-foreground">
                                    {issue.detail}
                                  </p>
                                  <p className="mt-1 text-xs text-muted-foreground">
                                    Recommended: {issue.recommendation}
                                  </p>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>

                        <div className="space-y-2">
                          <h3 className="text-sm font-semibold">Recent history</h3>
                          {detail.history.length === 0 ? (
                            <p className="text-sm text-muted-foreground">
                              No historical checks yet.
                            </p>
                          ) : (
                            <ul className="space-y-1 text-xs text-muted-foreground">
                              {detail.history.slice(0, 8).map((point) => (
                                <li
                                  key={`${point.checkedAt}:${point.score}`}
                                  className="flex items-center justify-between gap-3 rounded border border-border/60 px-2 py-1"
                                >
                                  <span>{new Date(point.checkedAt).toLocaleString()}</span>
                                  <span className="font-mono">
                                    {point.status} · {point.issueCount} issues · score{" "}
                                    {point.score}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
              </div>
            </>
          )
        }
      </AsyncSection>
    </div>
  );
}

function StatusStat({
  label,
  value,
  status
}: {
  label: string;
  value: number;
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums">{value}</CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <StatusBadge status={status} />
      </CardContent>
    </Card>
  );
}

function ProtocolStat({
  label,
  status
}: {
  label: string;
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
}) {
  return (
    <div className="rounded-md border border-border/70 p-2">
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="mt-1">
        <StatusBadge status={status} />
      </div>
    </div>
  );
}

function RecordBlock({ title, records }: { title: string; records: string[] }) {
  return (
    <div className="space-y-1">
      <h3 className="text-sm font-semibold">{title}</h3>
      {records.length === 0 ? (
        <p className="text-sm text-muted-foreground">None</p>
      ) : (
        <ul className="space-y-1">
          {records.map((record) => (
            <li
              key={`${title}:${record}`}
              className="rounded border border-border/60 bg-muted/30 px-2 py-1 font-mono text-[11px] text-muted-foreground"
            >
              {record}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function statusVariant(status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN") {
  if (status === "FAILING") return "critical";
  if (status === "WARNING") return "warning";
  if (status === "HEALTHY") return "secondary";
  return "outline";
}

function severityVariant(
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
) {
  if (severity === "CRITICAL" || severity === "HIGH") return "critical";
  if (severity === "MEDIUM" || severity === "LOW") return "warning";
  return "outline";
}

function StatusBadge({
  status
}: {
  status: "HEALTHY" | "WARNING" | "FAILING" | "UNKNOWN";
}) {
  return <Badge variant={statusVariant(status)}>{status.toLowerCase()}</Badge>;
}

function isUnavailableRpcError(error: unknown): boolean {
  if (!error) return false;
  const message =
    error instanceof Error
      ? error.message.toLowerCase()
      : String(error).toLowerCase();
  if (message.includes("unimplemented") || message.includes("http 404")) {
    return true;
  }
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = String((error as { code?: unknown }).code ?? "").toLowerCase();
    return code.includes("unimplemented") || code.includes("not_found");
  }
  return false;
}
