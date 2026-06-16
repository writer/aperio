"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, PlayCircle, ShieldCheck, Workflow } from "lucide-react";
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
        "Executed from the SaaS D&R incident workbench"
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

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="SaaS D&R incident"
        title={incident.title}
        description={incident.summary}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <Badge variant="outline">Confidence {incident.confidenceScore}</Badge>
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
                Findings are grouped into incidents while Cerebro remains the
                posture and graph context source of truth.
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
                Human-gated SaaS response actions with native approval and
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

          <Card>
            <CardHeader>
              <CardTitle>Cerebro context</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                {JSON.stringify(incident.cerebroContext, null, 2)}
              </pre>
            </CardContent>
          </Card>

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
