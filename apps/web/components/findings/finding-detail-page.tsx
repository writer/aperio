"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CheckCircle2,
  GitBranch,
  Network,
  RadioTower,
  Server,
  ShieldAlert,
  ShieldX
} from "lucide-react";
import {
  acceptFindingRisk,
  createSaasIncident,
  fetchFinding,
  resolveFinding,
  type Finding,
  type FindingCerebroContext
} from "../../lib/api";
import { CerebroMCPResourceTemplateList } from "../cerebro/mcp-resource-template-list";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge, SeverityBadge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { formatDateTime, providerLabel } from "../../lib/format";

export function FindingDetailPage({ findingId }: { findingId: string }) {
  const { toast } = useToast();
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<"resolve" | "mute" | "incident" | null>(null);

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

  async function handleCreateIncident() {
    if (!finding) return;
    setBusy("incident");
    try {
      const response = await createSaasIncident({
        title: `SaaS incident: ${finding.title}`,
        summary: finding.description,
        severity: finding.severity,
        findingIds: [finding.id],
        ownerTeam: "SecOps"
      });
      toast({ title: "Incident created", tone: "success" });
      router.push(`/incidents/${response.data.incident.id}`);
    } catch (err) {
      toast({
        title: "Unable to create incident",
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
              <FindingCerebroContextCard
                context={finding.cerebroContext ?? null}
              />

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
                      variant="outline"
                      onClick={() => void handleCreateIncident()}
                      loading={busy === "incident"}
                      loadingText="Creating…"
                    >
                      <ShieldAlert className="h-4 w-4" />
                      Create incident
                    </Button>
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

function FindingCerebroContextCard({
  context
}: {
  context: FindingCerebroContext | null;
}) {
  if (!context) return null;
  const mode = context.mode || "not-configured";
  const claimCount = context.claimCount ?? context.claimSummaries.length;
  const graphSignalCount = context.graphSignals.length;
  const graphPathCount = context.graphPaths.length;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle>Cerebro graph context</CardTitle>
            <CardDescription>
              {context.sourceRuntimeId ?? "Local projection"} ·{" "}
              {context.findingContract ?? "cerebro.v1.Finding"}
            </CardDescription>
          </div>
          <Badge variant={mode === "graph-linked" ? "signal" : "outline"}>
            {mode.replaceAll("-", " ")}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-3 gap-2">
          <CerebroStat icon={RadioTower} label="Claims" value={claimCount} />
          <CerebroStat
            icon={Network}
            label="Signals"
            value={graphSignalCount}
          />
          <CerebroStat icon={GitBranch} label="Paths" value={graphPathCount} />
        </div>

        <div className="space-y-2 text-sm">
          <Row label="Source event">
            {context.sourceEventId ? (
              <span className="font-mono text-xs">{context.sourceEventId}</span>
            ) : (
              "Not captured"
            )}
          </Row>
          <Row label="MCP resource">
            {context.mcp?.resourceUri ? (
              <span className="font-mono text-xs">{context.mcp.resourceUri}</span>
            ) : (
              "Not configured"
            )}
          </Row>
        </div>

        {context.mcp ? (
          <section className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <Server className="h-3.5 w-3.5" aria-hidden />
              Cerebro MCP
            </div>
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
          </section>
        ) : null}

        <CerebroMCPResourceTemplateList
          templates={context.mcp?.resourceTemplates}
        />

        {context.claimSummaries.length ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Claim sample
            </h4>
            <div className="space-y-1">
              {context.claimSummaries.slice(0, 3).map((claim) => (
                <div
                  key={`${claim.claimType}:${claim.predicate}:${claim.subjectUrn}:${claim.objectUrn ?? ""}`}
                  className="truncate rounded border border-border/70 bg-muted/25 px-2 py-1 font-mono text-[11px] text-muted-foreground"
                  title={`${claim.claimType} ${claim.predicate} ${claim.subjectUrn}`}
                >
                  {claim.claimType} · {claim.predicate}
                </div>
              ))}
            </div>
          </section>
        ) : null}
      </CardContent>
    </Card>
  );
}

function CerebroStat({
  icon: Icon,
  label,
  value
}: {
  icon: typeof RadioTower;
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-md border border-border bg-muted/20 p-2">
      <Icon className="mb-1 h-3.5 w-3.5 text-signal" aria-hidden />
      <div className="text-base font-semibold leading-none text-foreground">
        {value}
      </div>
      <div className="mt-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
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
