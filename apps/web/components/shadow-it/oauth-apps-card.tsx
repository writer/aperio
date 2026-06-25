"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, Search, ShieldAlert } from "lucide-react";
import {
  createSaasIncident,
  fetchShadowItOauthAppGrants,
  proposeSaasResponseAction,
  type Provider,
  type ShadowItOauthApp,
  type ShadowItOauthAppDetail
} from "../../lib/api";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle
} from "../ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { EmptyState } from "../ui/empty-state";
import { Input } from "../ui/input";
import { Skeleton } from "../ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "../ui/table";
import { useToast } from "../ui/toast";
import { cn } from "../../lib/utils";

type Criticality = ShadowItOauthApp["criticality"];

const criticalityVariant: Record<
  Criticality,
  "critical" | "destructive" | "warning" | "secondary"
> = {
  CRITICAL: "critical",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "secondary"
};

function shortScope(scope: string) {
  const trimmed = scope.trim();
  if (!trimmed) return "(empty)";
  const match = trimmed.match(/auth\/([^?#\s]+)/);
  if (match) return match[1];
  if (trimmed === "https://mail.google.com/") return "mail.google.com/";
  return trimmed.replace(/^https?:\/\//, "");
}

function scopeRiskDrivers(scopes: string[]) {
  const drivers = new Set<string>();
  for (const scope of scopes) {
    const normalized = scope.toLowerCase();
    if (
      normalized === "https://mail.google.com/" ||
      normalized.includes("gmail.modify") ||
      normalized.includes("gmail.settings")
    ) {
      drivers.add("Full mailbox access");
    } else if (
      normalized.includes("gmail.readonly") ||
      normalized.includes("gmail.send") ||
      normalized.includes("gmail.compose") ||
      normalized.includes("gmail.metadata")
    ) {
      drivers.add("Mailbox read/send");
    }
    if (
      normalized === "https://www.googleapis.com/auth/drive" ||
      normalized.includes("/auth/drive.")
    ) {
      drivers.add("Drive file access");
    }
    if (normalized.includes("admin.directory") || normalized.includes("/auth/admin.")) {
      drivers.add("Directory/admin access");
    }
    if (normalized.includes("cloud-platform") || normalized.includes("bigquery")) {
      drivers.add("Cloud data access");
    }
  }
  return Array.from(drivers);
}

function scopeExplanation(scope: string) {
  const normalized = scope.toLowerCase();
  if (normalized === "https://mail.google.com/") {
    return "Full Gmail mailbox access, including read, send, delete, and settings-adjacent operations.";
  }
  if (normalized.includes("gmail.modify")) {
    return "Mailbox read/write access that can change or delete messages.";
  }
  if (
    normalized.includes("gmail.readonly") ||
    normalized.includes("gmail.metadata") ||
    normalized.includes("gmail.send") ||
    normalized.includes("gmail.compose")
  ) {
    return "Gmail read, send, compose, or metadata access.";
  }
  if (normalized === "https://www.googleapis.com/auth/drive") {
    return "Broad Google Drive file access across visible files.";
  }
  if (normalized.includes("/auth/drive.")) {
    return "Google Drive file or metadata access.";
  }
  if (normalized.includes("admin.directory") || normalized.includes("/auth/admin.")) {
    return "Google Workspace directory or administrative access.";
  }
  if (normalized.includes("cloud-platform") || normalized.includes("bigquery")) {
    return "Google Cloud or BigQuery data-plane access.";
  }
  return scope;
}

function workflowProvider(app: ShadowItOauthApp): Provider {
  return app.provider ?? app.integration?.provider ?? "GOOGLE_WORKSPACE";
}

function looksLikeClientId(value: string) {
  if (/apps\.googleusercontent\.com$/i.test(value)) return true;
  if (/^\d{8,}-[a-z0-9]+/i.test(value)) return true;
  return false;
}

export function appDisplay(app: ShadowItOauthApp) {
  const hasDistinctName =
    app.name &&
    app.name.trim().length > 0 &&
    app.name !== app.externalId &&
    !looksLikeClientId(app.name);
  return {
    primary: hasDistinctName ? app.name : "Unknown app",
    secondary: app.externalId ?? (hasDistinctName ? null : app.name)
  };
}

export function OauthAppsCard({
  apps,
  limit,
  viewAllHref,
  title = "OAuth Apps",
  description = "Third-party applications authorized via user OAuth grants. Click any row to see scopes and users."
}: {
  apps: ShadowItOauthApp[];
  limit?: number;
  viewAllHref?: string;
  title?: string;
  description?: string;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<ShadowItOauthApp | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return apps;
    return apps.filter((app) => {
      if (app.name.toLowerCase().includes(q)) return true;
      if ((app.summary ?? "").toLowerCase().includes(q)) return true;
      if ((app.externalId ?? "").toLowerCase().includes(q)) return true;
      if (app.scopes.some((scope) => scope.toLowerCase().includes(q)))
        return true;
      return false;
    });
  }, [apps, query]);

  const totalUsers = useMemo(
    () => apps.reduce((sum, app) => sum + app.userCount, 0),
    [apps]
  );

  const visible =
    limit && !query.trim() ? filtered.slice(0, limit) : filtered;
  const truncated =
    Boolean(limit) && !query.trim() && filtered.length > (limit ?? 0);

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>{title}</CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="font-mono tabular-nums">
              {apps.length} app{apps.length === 1 ? "" : "s"}
            </Badge>
            <Badge variant="outline" className="font-mono tabular-nums">
              {totalUsers} grant{totalUsers === 1 ? "" : "s"}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="relative w-full max-w-xs">
          <Search
            className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search app, client ID, or scope…"
            aria-label="Search OAuth apps"
            className="h-8 pl-7 text-xs"
          />
        </div>
        <span className="ml-auto font-mono text-[11px] text-muted-foreground tabular-nums">
          {limit && !query.trim()
            ? `${visible.length} of ${apps.length}`
            : `${filtered.length} of ${apps.length}`}
        </span>
      </div>
      <CardContent className="p-0">
        {visible.length === 0 ? (
          <EmptyState
            title={apps.length === 0 ? "No OAuth apps detected" : "No matches"}
            description={
              apps.length === 0
                ? "Once Google Workspace sync completes with the directory.user.security scope, user-authorized OAuth applications will appear here."
                : "Try a different search."
            }
            className="m-6"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>App</TableHead>
                <TableHead className="text-right">Users</TableHead>
                <TableHead>Top scopes</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead className="text-right">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((app) => {
                const display = appDisplay(app);
                const riskDrivers = scopeRiskDrivers(app.scopes);
                return (
                  <TableRow
                    key={app.id}
                    onClick={() => setActive(app)}
                    className="cursor-pointer"
                  >
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-foreground">
                          {display.primary}
                        </span>
                        {display.secondary &&
                        display.secondary !== display.primary ? (
                          <span className="truncate font-mono text-[11px] text-muted-foreground">
                            {display.secondary}
                          </span>
                        ) : null}
                        {app.containsSensitiveData ? (
                          <span className="mt-1">
                            <Badge
                              variant="warning"
                              className="text-[10px]"
                            >
                              Sensitive data scopes
                            </Badge>
                          </span>
                        ) : null}
                        {riskDrivers.length > 0 ? (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {riskDrivers.slice(0, 2).map((driver) => (
                              <Badge key={driver} variant="outline" className="text-[10px]">
                                {driver}
                              </Badge>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums text-sm text-muted-foreground">
                      {app.userCount}
                    </TableCell>
                    <TableCell>
                      {app.scopes.length === 0 ? (
                        <span className="text-xs italic text-muted-foreground">
                          none recorded
                        </span>
                      ) : (
                        <div className="flex max-w-md flex-wrap gap-1">
                          {app.scopes.slice(0, 4).map((scope) => (
                            <span
                              key={scope}
                              className="rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                              title={scopeExplanation(scope)}
                            >
                              {shortScope(scope)}
                            </span>
                          ))}
                          {app.scopes.length > 4 ? (
                            <span className="text-[10px] text-muted-foreground">
                              +{app.scopes.length - 4} more
                            </span>
                          ) : null}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={criticalityVariant[app.criticality]}
                        className={cn(
                          "font-mono tabular-nums uppercase",
                          app.criticality === "CRITICAL"
                            ? "critical-pulse"
                            : undefined
                        )}
                      >
                        {app.criticality} · {app.riskScore}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right text-xs text-muted-foreground">
                      {app.lastObservedAt
                        ? new Date(app.lastObservedAt).toLocaleString()
                        : "Never"}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        {truncated && viewAllHref ? (
          <div className="flex items-center justify-between gap-3 border-t border-border px-6 py-3 text-xs text-muted-foreground">
            <span>
              Showing top {visible.length} of {filtered.length} apps by risk.
            </span>
            <Button asChild variant="outline" size="sm">
              <Link href={viewAllHref}>
                View all
                <ArrowRight className="h-3.5 w-3.5" aria-hidden />
              </Link>
            </Button>
          </div>
        ) : null}
      </CardContent>

      <OauthAppDetailsDialog
        app={active}
        open={active !== null}
        onOpenChange={(open) => {
          if (!open) setActive(null);
        }}
      />
    </Card>
  );
}

function OauthAppDetailsDialog({
  app,
  open,
  onOpenChange
}: {
  app: ShadowItOauthApp | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [detail, setDetail] = useState<ShadowItOauthAppDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [workflowBusy, setWorkflowBusy] = useState(false);

  useEffect(() => {
    if (!app) {
      setDetail(null);
      setError("");
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    setDetail(null);
    fetchShadowItOauthAppGrants(app.id)
      .then((response) => {
        if (cancelled) return;
        setDetail(response.data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Unable to load users");
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [app]);

  const display = app ? appDisplay(app) : null;
  const riskDrivers = app ? scopeRiskDrivers(app.scopes) : [];

  async function openRevokeWorkflow() {
    if (!app || !display) return;
    setWorkflowBusy(true);
    try {
      const targetIdentifier = app.externalId || app.name || app.id;
      const scopeSummary =
        app.scopes.length > 0
          ? app.scopes.slice(0, 8).map(shortScope).join(", ")
          : "no scopes recorded";
      const response = await createSaasIncident({
        title: `Review OAuth app: ${display.primary}`,
        summary: `${display.primary} has ${app.userCount} active user grant${
          app.userCount === 1 ? "" : "s"
        }, risk ${app.criticality} ${app.riskScore}, and scopes: ${scopeSummary}.`,
        severity: app.criticality,
        ownerTeam: "SecOps"
      });
      await proposeSaasResponseAction({
        incidentId: response.data.incident.id,
        action: "REVOKE_OAUTH_GRANT",
        provider: workflowProvider(app),
        targetType: "oauth_app",
        targetIdentifier,
        rationale: `Review and revoke OAuth grants for ${display.primary}. Risk drivers: ${
          riskDrivers.length > 0 ? riskDrivers.join(", ") : "OAuth app grant review"
        }.`,
        approvalRequired: true
      });
      toast({
        tone: "success",
        title: "Revoke workflow opened",
        description: "Incident and approval-gated response action created."
      });
      router.push(`/incidents/${response.data.incident.id}`);
    } catch (err) {
      toast({
        tone: "error",
        title: "Unable to open workflow",
        description: err instanceof Error ? err.message : "Try again"
      });
    } finally {
      setWorkflowBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{display?.primary ?? "OAuth app"}</DialogTitle>
          <DialogDescription>
            {display?.secondary && display.secondary !== display.primary ? (
              <>
                Client ID:{" "}
                <span className="font-mono text-xs">{display.secondary}</span>
              </>
            ) : (
              "OAuth app details and user grants."
            )}
          </DialogDescription>
        </DialogHeader>

        {app ? (
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant={criticalityVariant[app.criticality]}
              className={cn(
                "font-mono tabular-nums uppercase",
                app.criticality === "CRITICAL" ? "critical-pulse" : undefined
              )}
            >
              {app.criticality} · {app.riskScore}
            </Badge>
            <Badge variant="outline" className="font-mono tabular-nums">
              {app.userCount} user{app.userCount === 1 ? "" : "s"}
            </Badge>
            <Badge variant="outline" className="font-mono tabular-nums">
              {app.scopes.length} scope{app.scopes.length === 1 ? "" : "s"}
            </Badge>
            {app.containsSensitiveData ? (
              <Badge variant="warning">Sensitive data scopes</Badge>
            ) : null}
            {app.integration ? (
              <Badge variant="secondary">{app.integration.displayName}</Badge>
            ) : null}
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="ml-auto"
              disabled={workflowBusy}
              onClick={() => void openRevokeWorkflow()}
            >
              <ShieldAlert className="mr-1 h-3.5 w-3.5" aria-hidden />
              {workflowBusy ? "Opening..." : "Open revoke workflow"}
            </Button>
          </div>
        ) : null}

        {riskDrivers.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {riskDrivers.map((driver) => (
              <Badge key={driver} variant="outline">
                {driver}
              </Badge>
            ))}
          </div>
        ) : null}

        {app && app.scopes.length > 0 ? (
          <div className="space-y-1">
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Scopes
            </p>
            <div className="flex flex-wrap gap-1">
              {app.scopes.map((scope) => (
                <span
                  key={scope}
                  className="rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  title={scope}
                  aria-label={scopeExplanation(scope)}
                >
                  {shortScope(scope)}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        <div className="space-y-1">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Users
          </p>
          <div className="max-h-[45vh] overflow-auto rounded border border-border">
            {loading ? (
              <div className="space-y-2 px-4 py-4">
                <Skeleton className="h-4 w-2/3" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-1/2" />
              </div>
            ) : error ? (
              <p className="px-4 py-4 text-sm text-destructive">{error}</p>
            ) : !detail || detail.grants.length === 0 ? (
              <p className="px-4 py-4 text-sm text-muted-foreground">
                No user grants recorded.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Scopes</TableHead>
                    <TableHead className="text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {detail.grants.map((grant) => (
                    <TableRow key={grant.id}>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          <span className="text-sm font-medium text-foreground">
                            {grant.userDisplayName ?? grant.userEmail}
                          </span>
                          <span className="font-mono text-[11px] text-muted-foreground">
                            {grant.userEmail}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        {grant.scopes.length === 0 ? (
                          <span className="text-xs italic text-muted-foreground">
                            none recorded
                          </span>
                        ) : (
                          <div className="flex max-w-sm flex-wrap gap-1">
                            {grant.scopes.map((scope) => (
                              <span
                                key={scope}
                                className="rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                                title={scopeExplanation(scope)}
                              >
                                {shortScope(scope)}
                              </span>
                            ))}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        {new Date(grant.lastObservedAt).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
