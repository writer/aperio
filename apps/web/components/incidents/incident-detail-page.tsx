"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  GitBranch,
  Link2,
  Network,
  PlayCircle,
  RadioTower,
  Server,
  ShieldCheck,
  Workflow
} from "lucide-react";
import {
  executeSaasResponseAction,
  fetchSaasIncident,
  updateSaasIncidentStatus,
  type SaasIncidentDetail,
  type SaasIncidentStatus,
  type SaasResponseAction
} from "../../lib/api";
import { formatDateTime, providerLabel } from "../../lib/format";
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
import { useToast } from "../ui/toast";

export function IncidentDetailPage({ incidentId }: { incidentId: string }) {
  const { toast } = useToast();
  const [detail, setDetail] = useState<SaasIncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetchSaasIncident(incidentId);
      setDetail(response.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load incident");
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function changeStatus(status: SaasIncidentStatus) {
    setBusy(`status:${status}`);
    try {
      await updateSaasIncidentStatus(incidentId, {
        status,
        note: `Incident moved to ${status.toLowerCase()} from Aperio.`
      });
      toast({ title: "Incident updated", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to update incident",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setBusy(null);
    }
  }

  async function executeAction(action: SaasResponseAction) {
    setBusy(`action:${action.id}`);
    try {
      await executeSaasResponseAction(
        action.id,
        "Recorded from the posture incident workbench"
      );
      toast({ title: "Response action recorded", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to execute response",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setBusy(null);
    }
  }

  const pendingActions = useMemo(
    () =>
      detail?.responseActions.filter((action) =>
        ["PROPOSED", "APPROVED", "EXECUTING"].includes(action.status)
      ) ?? [],
    [detail]
  );

  if (loading) {
    return (
      <Card>
        <CardContent className="space-y-3 p-6">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-7 w-full max-w-lg" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-4/5" />
        </CardContent>
      </Card>
    );
  }

  if (error || !detail) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-destructive">
          {error || "Incident not found"}
        </CardContent>
      </Card>
    );
  }

  const { incident } = detail;
  const { cerebroContext } = incident;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Posture incident"
        title={incident.title}
        description={incident.summary}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <Badge variant="outline">Confidence {incident.confidenceScore}</Badge>
            <Badge variant="signal">
              <RadioTower className="h-3.5 w-3.5" />
              Cerebro {cerebroContext.mode.replaceAll("-", " ")}
            </Badge>
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Incident timeline</CardTitle>
              <CardDescription>
                Detection, Cerebro context, investigation updates, and response
                outcomes in one replayable trail.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ol className="relative space-y-4 border-l border-border pl-5">
                {detail.timeline.map((event) => (
                  <li key={event.id} className="relative">
                    <span className="absolute -left-[27px] top-1 h-3 w-3 rounded-full border border-background bg-signal" />
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {event.kind.replaceAll("_", " ")}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {formatDateTime(event.occurredAt)}
                      </span>
                    </div>
                    <h3 className="mt-1 text-sm font-semibold text-foreground">
                      {event.title}
                    </h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {event.description}
                    </p>
                    {event.actor ? (
                      <p className="mt-1 text-xs text-muted-foreground">
                        Actor: {event.actor}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Linked findings</CardTitle>
              <CardDescription>
                Findings are grouped into incidents with Cerebro graph context
                and claim provenance attached.
              </CardDescription>
            </CardHeader>
            <CardContent className="divide-y divide-border p-0">
              {detail.findings.map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="block p-4 transition-colors hover:bg-muted/35"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <Badge variant="outline">
                      {providerLabel(finding.integration.provider)}
                    </Badge>
                    <Badge variant={finding.status === "OPEN" ? "destructive" : "secondary"}>
                      {finding.status}
                    </Badge>
                  </div>
                  <p className="mt-2 text-sm font-medium text-foreground">
                    {finding.title}
                  </p>
                  <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                    {finding.description}
                  </p>
                </Link>
              ))}
            </CardContent>
          </Card>
        </div>

        <aside className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Response workbench</CardTitle>
              <CardDescription>
                Human-gated response actions with native approval and
                execution tracking.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {pendingActions.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No response actions are waiting.
                </p>
              ) : (
                pendingActions.map((action) => (
                  <div
                    key={action.id}
                    className="rounded-lg border border-border bg-muted/25 p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-foreground">
                          {action.action.replaceAll("_", " ")}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {action.targetType}: {action.targetIdentifier}
                        </p>
                      </div>
                      <Badge variant="warning">{action.status}</Badge>
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {action.rationale}
                    </p>
                    <Button
                      className="mt-3 w-full"
                      size="sm"
                      onClick={() => void executeAction(action)}
                      loading={busy === `action:${action.id}`}
                      loadingText="Recording…"
                    >
                      <PlayCircle className="h-4 w-4" />
                      Record execution
                    </Button>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Incident actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => void changeStatus("INVESTIGATING")}
                loading={busy === "status:INVESTIGATING"}
              >
                <Workflow className="h-4 w-4" />
                Mark investigating
              </Button>
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => void changeStatus("CONTAINED")}
                loading={busy === "status:CONTAINED"}
              >
                <ShieldCheck className="h-4 w-4" />
                Mark contained
              </Button>
              <Button
                className="w-full justify-start"
                onClick={() => void changeStatus("RESOLVED")}
                loading={busy === "status:RESOLVED"}
              >
                <CheckCircle2 className="h-4 w-4" />
                Resolve incident
              </Button>
            </CardContent>
          </Card>

          <CerebroContextCard context={cerebroContext} />

          <Card>
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <Row label="Owner team">{incident.ownerTeam ?? "Unassigned"}</Row>
              <Row label="Assignee">
                {incident.assignee?.displayName ??
                  incident.assignee?.email ??
                  "Unassigned"}
              </Row>
              <Row label="First detected">
                {formatDateTime(incident.firstDetectedAt)}
              </Row>
              <Row label="SLA">{formatDateTime(incident.slaDueAt)}</Row>
              <Row label="Response">
                {incident.completedResponseActionCount}/
                {incident.responseActionCount} complete
              </Row>
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}

type CerebroContext = SaasIncidentDetail["incident"]["cerebroContext"];

function CerebroContextCard({ context }: { context: CerebroContext }) {
  const entityByUrn = new Map(
    context.entities.map((entity) => [entity.urn, entity])
  );
  const graphSignalCount = context.graphSignals.length;
  const graphPathCount = context.graphPaths.length;
  const claimCount = context.claimCount ?? context.claimSummaries.length;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle>Cerebro graph context</CardTitle>
            <CardDescription>
              {context.sourceRuntimeId ?? "Cerebro runtime"} ·{" "}
              {context.findingContract ?? "cerebro.v1.Finding"}
            </CardDescription>
          </div>
          <Badge variant="signal" className="shrink-0 uppercase">
            {context.mode.replaceAll("-", " ")}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-3">
          <CerebroStat
            icon={RadioTower}
            label="Claims"
            value={String(claimCount)}
          />
          <CerebroStat
            icon={Network}
            label="Graph signals"
            value={String(graphSignalCount)}
          />
          <CerebroStat
            icon={GitBranch}
            label="Paths"
            value={String(graphPathCount)}
          />
        </div>

        {context.mcp ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Cerebro MCP
            </h4>
            <div className="rounded-md border border-border bg-muted/25 p-3">
              <div className="flex items-start gap-2">
                <Server
                  className="mt-0.5 h-4 w-4 shrink-0 text-signal"
                  aria-hidden
                />
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    {context.mcp.server ? (
                      <Badge variant="outline">{context.mcp.server}</Badge>
                    ) : null}
                    {context.mcp.mimeType ? (
                      <Badge variant="secondary">{context.mcp.mimeType}</Badge>
                    ) : null}
                  </div>
                  {context.mcp.resourceUri ? (
                    <p className="break-all font-mono text-xs text-muted-foreground">
                      {context.mcp.resourceUri}
                    </p>
                  ) : null}
                  {context.mcp.tools.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {context.mcp.tools.map((tool) => (
                        <Badge
                          key={tool}
                          variant="signal"
                          className="max-w-full truncate font-mono text-[10px]"
                        >
                          {tool}
                        </Badge>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          </section>
        ) : null}

        {context.graphSignals.length > 0 ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Signals
            </h4>
            <div className="space-y-2">
              {context.graphSignals.map((signal) => (
                <div
                  key={`${signal.label}:${signal.entityUrn ?? ""}`}
                  className="rounded-md border border-border bg-muted/25 p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm font-medium text-foreground">
                      {signal.label}
                    </p>
                    {signal.confidence ? (
                      <Badge variant="outline" className="shrink-0">
                        {formatCerebroConfidence(signal.confidence)}
                      </Badge>
                    ) : null}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    {signal.predicate ? <span>{signal.predicate}</span> : null}
                    {signal.evidence ? <span>{signal.evidence}</span> : null}
                    {signal.entityUrn ? (
                      <span className="max-w-full truncate font-mono">
                        {shortCerebroUrn(signal.entityUrn)}
                      </span>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        {context.graphPaths.length > 0 ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Entity paths
            </h4>
            <div className="space-y-2">
              {context.graphPaths.map((path) => (
                <div
                  key={path.id}
                  className="rounded-md border border-border bg-muted/25 p-3"
                >
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-medium text-foreground">
                      {path.title}
                    </p>
                    {path.risk ? (
                      <Badge variant="warning" className="shrink-0">
                        {path.risk}
                      </Badge>
                    ) : null}
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    {path.nodes.map((node, index) => (
                      <div
                        key={`${path.id}:${node.urn}`}
                        className="flex min-w-0 items-center gap-2"
                      >
                        {index > 0 ? (
                          <Link2
                            className="h-3.5 w-3.5 shrink-0 text-muted-foreground"
                            aria-hidden
                          />
                        ) : null}
                        <span className="min-w-0 rounded-md border border-border bg-background px-2 py-1 text-xs">
                          <span className="font-medium text-foreground">
                            {node.label}
                          </span>
                          <span className="ml-1 text-muted-foreground">
                            {node.type}
                          </span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>
        ) : null}

        {context.claimSummaries.length > 0 ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Claim provenance
            </h4>
            <div className="space-y-2">
              {context.claimSummaries.map((claim) => {
                const subject = entityByUrn.get(claim.subjectUrn);
                const object = claim.objectUrn
                  ? entityByUrn.get(claim.objectUrn)
                  : null;
                return (
                  <div
                    key={`${claim.claimType}:${claim.predicate}:${claim.subjectUrn}:${claim.objectUrn ?? ""}`}
                    className="rounded-md border border-border bg-muted/25 p-3 text-xs"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className="font-mono">
                        {claim.claimType}
                      </Badge>
                      <span className="font-medium text-foreground">
                        {claim.predicate}
                      </span>
                      {claim.sourceEvent ? (
                        <span className="text-muted-foreground">
                          {claim.sourceEvent}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-2 text-muted-foreground">
                      {subject?.label ?? shortCerebroUrn(claim.subjectUrn)}
                      {claim.objectUrn ? " -> " : ""}
                      {claim.objectUrn
                        ? object?.label ?? shortCerebroUrn(claim.objectUrn)
                        : ""}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        ) : null}

        {context.responseHints.length > 0 ? (
          <section className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Response hints
            </h4>
            <ul className="space-y-2">
              {context.responseHints.map((hint) => (
                <li
                  key={hint}
                  className="rounded-md border border-border bg-muted/25 px-3 py-2 text-sm text-muted-foreground"
                >
                  {hint}
                </li>
              ))}
            </ul>
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
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-md border border-border bg-muted/25 p-3">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5 text-signal" />
        {label}
      </div>
      <div className="mt-2 text-lg font-semibold text-foreground">{value}</div>
    </div>
  );
}

function formatCerebroConfidence(confidence: number) {
  const normalized = confidence <= 1 ? confidence * 100 : confidence;
  return `${Math.round(normalized)}%`;
}

function shortCerebroUrn(urn: string) {
  const parts = urn.split(":").filter(Boolean);
  return parts.slice(-2).join(":") || urn;
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
