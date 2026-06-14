"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, ShieldX } from "lucide-react";
import {
  acceptFindingRisk,
  fetchFinding,
  resolveFinding,
  type Finding
} from "../../lib/api";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge, SeverityBadge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle
} from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { formatDateTime, providerLabel } from "../../lib/format";

export function FindingDetailPage({ findingId }: { findingId: string }) {
  const { toast } = useToast();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<"resolve" | "mute" | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetchFinding(findingId);
      setFinding(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load finding");
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleResolve() {
    setBusy("resolve");
    try {
      await resolveFinding(findingId);
      toast({ title: "Finding resolved", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to resolve",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setBusy(null);
    }
  }

  async function handleAccept() {
    setBusy("mute");
    try {
      await acceptFindingRisk(findingId);
      toast({ title: "Risk accepted", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to accept risk",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {loading ? (
        <Card>
          <CardContent className="space-y-3 p-6">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-6 w-full max-w-md" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
          </CardContent>
        </Card>
      ) : error || !finding ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            {error || "Finding not found"}
          </CardContent>
        </Card>
      ) : (
        <>
          <PageHeader
            eyebrow={`${providerLabel(finding.integration.provider)} · ${finding.integration.displayName}`}
            title={finding.title}
            description={finding.description}
            actions={
              <div className="flex items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <Badge
                  variant={
                    finding.status === "OPEN"
                      ? "destructive"
                      : finding.status === "RESOLVED"
                        ? "success"
                        : "secondary"
                  }
                >
                  {finding.status}
                </Badge>
                <Badge variant="outline">Risk {finding.riskScore}</Badge>
                {finding.tags?.map((tag) => (
                  <Badge
                    key={tag}
                    variant="outline"
                    className="font-mono text-[10px]"
                  >
                    {tag}
                  </Badge>
                ))}
              </div>
            }
          />

          <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
            <div className="flex flex-col gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Remediation steps</CardTitle>
                </CardHeader>
                <CardContent>
                  {finding.remediationSteps.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      No remediation guidance available for this finding.
                    </p>
                  ) : (
                    <ol className="list-decimal space-y-2 pl-4 text-sm text-foreground">
                      {finding.remediationSteps.map((step, index) => (
                        <li key={index}>{step}</li>
                      ))}
                    </ol>
                  )}
                </CardContent>
              </Card>

              {finding.evidence ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Evidence</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                      {JSON.stringify(finding.evidence, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              ) : null}
            </div>

            <div className="flex flex-col gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <Row label="Detected">
                    {formatDateTime(finding.detectedAt)}
                  </Row>
                  <Row label="Resolved">
                    {formatDateTime(finding.resolvedAt)}
                  </Row>
                  <Row label="Integration">
                    {finding.integration.displayName}
                  </Row>
                  <Row label="Provider">
                    {providerLabel(finding.integration.provider)}
                  </Row>
                  {finding.assetId ? (
                    <Row label="Asset">
                      <span className="font-mono text-xs">
                        {finding.assetId}
                      </span>
                    </Row>
                  ) : null}
                </CardContent>
              </Card>

              {finding.status === "OPEN" ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Actions</CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-2">
                    <Button
                      onClick={() => void handleResolve()}
                      loading={busy === "resolve"}
                      loadingText="Resolving…"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      Mark resolved
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => void handleAccept()}
                      loading={busy === "mute"}
                      loadingText="Accepting…"
                    >
                      <ShieldX className="h-4 w-4" />
                      Accept risk
                    </Button>
                  </CardContent>
                </Card>
              ) : null}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Row({
  label,
  children
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-border pb-2 last:border-b-0 last:pb-0">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <span className="text-right text-sm text-foreground">{children}</span>
    </div>
  );
}
