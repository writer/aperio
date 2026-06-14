"use client";

import { useCallback, useEffect, useId, useMemo, useState } from "react";
import {
  CheckCircle2,
  Copy,
  ExternalLink,
  ListChecks,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Unplug
} from "lucide-react";
import { ConnectorRulesDialog } from "./connector-rules-dialog";
import { FindingsDialog } from "./findings-dialog";
import { cn } from "../../lib/utils";
import {
  clearIntegrationOAuthClient,
  connectIntegration,
  disconnectIntegration,
  fetchConnectorCatalog,
  fetchGoogleWorkspaceBigQueryConfig,
  fetchIntegrationOAuthClient,
  fetchIntegrations,
  forceSyncIntegration,
  saveIntegrationOAuthClient,
  startGoogleWorkspaceOAuth,
  updateGoogleWorkspaceBigQueryConfig,
  validateGoogleWorkspaceBigQueryConfig,
  type ConnectIntegrationPayload,
  type ConnectorDefinition,
  type IntegrationConnection,
  type IntegrationMode,
  type IntegrationOAuthClient
} from "../../lib/api";
import { useToast } from "../ui/toast";
import { PageHeader } from "../layout/page-header";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import { Field, FormBanner, Input } from "../ui/form";
import { Textarea } from "../ui/input";
import { Skeleton } from "../ui/skeleton";
import { formatRelative, providerLabel } from "../../lib/format";
import {
  buildGoogleWorkspaceBigQueryWifSetupScript,
  googleWorkspaceBigQueryWifDefaults,
  type GoogleWorkspaceBigQueryWifAccessMode,
  type GoogleWorkspaceBigQueryWifOutputMode
} from "@aperio/shared/google-workspace-bigquery-wif";

type StatusFilter = "ALL" | IntegrationConnection["status"];
const STATUS_FILTERS: StatusFilter[] = ["ALL", "CONNECTED", "ERROR", "DISABLED"];

// compatForceSync on the API only succeeds for CONNECTED Google Workspace
// integrations today; every other provider/status combination returns
// CodeUnimplemented or NotFound. Gate the Sync action so operators do not
// see a button whose only outcome is a "Sync failed" toast.
function supportsForceSync(integration: IntegrationConnection): boolean {
  return (
    integration.provider === "GOOGLE_WORKSPACE" &&
    integration.status === "CONNECTED"
  );
}

export function ConnectorsPage() {
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<ConnectorDefinition[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [active, setActive] = useState<ConnectorDefinition | null>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");
  const [catalogQuery, setCatalogQuery] = useState("");
  const [rulesIntegration, setRulesIntegration] = useState<IntegrationConnection | null>(null);
  const [findingsIntegration, setFindingsIntegration] =
    useState<IntegrationConnection | null>(null);
  const [bigQueryIntegration, setBigQueryIntegration] =
    useState<IntegrationConnection | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);

  const filteredIntegrations = useMemo(() => {
    // Active integrations are searched by both display labels and provider-owned
    // tenant ids because operators often know only one of those identifiers.
    const q = query.trim().toLowerCase();
    return integrations.filter((i) => {
      if (statusFilter !== "ALL" && i.status !== statusFilter) return false;
      if (!q) return true;
      const haystack =
        `${i.displayName} ${providerLabel(i.provider)} ${i.externalAccountId}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [integrations, query, statusFilter]);

  const filteredCatalog = useMemo(() => {
    const q = catalogQuery.trim().toLowerCase();
    if (!q) return catalog;
    // Catalog search intentionally excludes credential field metadata so secret
    // labels/placeholders do not affect connector discovery results.
    return catalog.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q)
    );
  }, [catalog, catalogQuery]);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [c, i] = await Promise.all([
        fetchConnectorCatalog(),
        fetchIntegrations()
      ]);
      setCatalog(c.data);
      setIntegrations(i.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load connectors");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const outcome = params.get("google_connect");
    if (outcome !== "success" && outcome !== "error") return;
    const providerName = providerLabel(params.get("provider") || "GOOGLE_WORKSPACE");
    if (outcome === "success") {
      toast({
        title: `${providerName} connected`,
        description: "Your workspace is now linked. Audit log ingestion will begin shortly.",
        tone: "success"
      });
      void load();
    } else {
      const message = params.get("message") || "We could not finish connecting Google Workspace.";
      toast({
        title: `${providerName} connection failed`,
        description: message,
        tone: "error"
      });
    }
    params.delete("google_connect");
    params.delete("provider");
    params.delete("message");
    const next = params.toString();
    const cleanUrl = window.location.pathname + (next ? `?${next}` : "");
    window.history.replaceState({}, "", cleanUrl);
  }, [load, toast]);

  async function handleDisconnect(id: string) {
    try {
      await disconnectIntegration(id);
      toast({ title: "Integration disconnected", tone: "success" });
      await load();
    } catch (err) {
      toast({
        title: "Unable to disconnect",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    }
  }

  async function handleSync(integration: IntegrationConnection) {
    if (syncingId) return;
    if (!supportsForceSync(integration)) return;
    setSyncingId(integration.id);
    try {
      const result = await forceSyncIntegration(integration.id);
      const ingested = result.sync?.eventsIngested ?? 0;
      const opened = result.sync?.findingsOpened ?? 0;
      toast({
        title: `Sync queued · ${integration.displayName}`,
        description:
          ingested === 0 && opened === 0
            ? "New events will appear once the ingestion worker finishes."
            : `${ingested} event${ingested === 1 ? "" : "s"} ingested · ${opened} new finding${opened === 1 ? "" : "s"}`,
        tone: "success"
      });
      await load();
    } catch (err) {
      toast({
        title: "Sync failed",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setSyncingId(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="Connectors"
        title="SaaS connectors"
        description="Connect SaaS apps to ingest audit logs and configuration drift events. Tokens are encrypted at rest."
      />

      <section className="flex flex-col gap-3">
        <div className="flex items-end justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">
            Active integrations
          </h2>
          {integrations.length > 0 ? (
            <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
              {filteredIntegrations.length} of {integrations.length}
            </span>
          ) : null}
        </div>

        {integrations.length > 0 ? (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card/60 px-3 py-2">
            <div className="relative w-full max-w-xs">
              <Search
                className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search integrations…"
                aria-label="Search integrations"
                className="h-8 pl-7 text-xs"
              />
            </div>
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Status
            </span>
            <div className="flex items-center gap-1">
              {STATUS_FILTERS.map((s) => {
                const active = statusFilter === s;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setStatusFilter(s)}
                    aria-pressed={active}
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider transition-colors",
                      active
                        ? "border-signal/40 bg-signal/15 text-signal"
                        : "border-border/80 bg-background text-muted-foreground hover:border-border hover:text-foreground"
                    )}
                  >
                    {s}
                  </button>
                );
              })}
            </div>
          </div>
        ) : null}

        {loading ? (
          <Card>
            <CardContent className="space-y-2 p-4">
              <Skeleton className="h-4 w-1/2" />
              <Skeleton className="h-4 w-3/4" />
            </CardContent>
          </Card>
        ) : integrations.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No integrations yet. Pick a connector below to add one.
            </CardContent>
          </Card>
        ) : filteredIntegrations.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No integrations match the current filters.
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filteredIntegrations.map((integration) => (
              <Card
                key={integration.id}
                className={cn(
                  "relative overflow-hidden",
                  integration.status === "ERROR"
                    ? "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-destructive"
                    : integration.status === "CONNECTED"
                      ? "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-success/60"
                      : ""
                )}
              >
                <CardContent className="flex flex-col gap-3 p-5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                        {providerLabel(integration.provider)}
                      </p>
                      <p className="mt-1 truncate text-sm font-semibold text-foreground">
                        {integration.displayName}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                        {integration.externalAccountId}
                      </p>
                    </div>
                    <Badge
                      variant={
                        integration.status === "CONNECTED"
                          ? "success"
                          : integration.status === "ERROR"
                            ? "destructive"
                            : "secondary"
                      }
                    >
                      {integration.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Mode:{" "}
                    {integration.mode === "REMEDIATION"
                      ? "Read + remediate"
                      : "Read-only"}
                    {" · "}
                    <span className="font-mono tabular-nums">
                      synced {formatRelative(integration.lastSyncAt)}
                    </span>
                  </p>
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setRulesIntegration(integration)}
                      disabled={syncingId === integration.id}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      Rules
                    </Button>
                    {supportsForceSync(integration) ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void handleSync(integration)}
                        disabled={syncingId === integration.id}
                      >
                        {syncingId === integration.id ? (
                          <Loader2
                            className="h-3.5 w-3.5 animate-spin"
                            aria-hidden
                          />
                        ) : (
                          <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                        )}
                        {syncingId === integration.id ? "Syncing…" : "Sync"}
                      </Button>
                    ) : null}
                    {integration.provider === "GOOGLE_WORKSPACE" ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setBigQueryIntegration(integration)}
                        disabled={syncingId === integration.id}
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                        BigQuery
                      </Button>
                    ) : null}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setFindingsIntegration(integration)}
                      disabled={syncingId === integration.id}
                    >
                      <ListChecks className="h-3.5 w-3.5" aria-hidden />
                      Findings
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => void handleDisconnect(integration.id)}
                      disabled={syncingId === integration.id}
                    >
                      <Unplug className="h-3.5 w-3.5" />
                      Disconnect
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-sm font-semibold text-foreground">
            Available connectors
          </h2>
          {catalog.length > 0 ? (
            <div className="relative w-full max-w-xs">
              <Search
                className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                value={catalogQuery}
                onChange={(e) => setCatalogQuery(e.target.value)}
                placeholder="Search catalog…"
                aria-label="Search connector catalog"
                className="h-8 pl-7 text-xs"
              />
            </div>
          ) : null}
        </div>
        {error ? (
          <Card>
            <CardContent className="p-6 text-sm text-destructive">
              {error}
            </CardContent>
          </Card>
        ) : loading ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="space-y-2 p-5">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-5 w-40" />
                  <Skeleton className="h-3 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredCatalog.length === 0 ? (
          <Card>
            <CardContent className="p-6 text-sm text-muted-foreground">
              No connectors match your search.
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filteredCatalog.map((connector) => (
              <Card key={connector.provider}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base">
                      {connector.name}
                    </CardTitle>
                    <Badge variant="outline">{connector.category}</Badge>
                  </div>
                  <CardDescription>{connector.description}</CardDescription>
                </CardHeader>
                <CardContent className="flex items-center justify-between gap-2">
                  <a
                    href={connector.docsUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
                  >
                    Docs
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  </a>
                  <Button size="sm" onClick={() => setActive(connector)}>
                    <Plus className="h-3.5 w-3.5" />
                    Connect
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <ConnectDialog
        connector={active}
        onClose={() => setActive(null)}
        onConnected={async () => {
          setActive(null);
          toast({
            title: "Integration connected",
            tone: "success"
          });
          await load();
        }}
      />
      <ConnectorRulesDialog
        integrationId={rulesIntegration?.id ?? null}
        integrationLabel={rulesIntegration?.displayName ?? ""}
        open={rulesIntegration !== null}
        onOpenChange={(next) => {
          if (!next) setRulesIntegration(null);
        }}
      />
      <FindingsDialog
        integration={findingsIntegration}
        open={findingsIntegration !== null}
        onOpenChange={(next) => {
          if (!next) setFindingsIntegration(null);
        }}
        onSaved={() => void load()}
      />
      <GoogleWorkspaceBigQuerySetupDialog
        integration={bigQueryIntegration}
        open={bigQueryIntegration !== null}
        onOpenChange={(next) => {
          if (!next) setBigQueryIntegration(null);
        }}
      />
    </div>
  );
}

function GoogleWorkspaceBigQuerySetupDialog({
  integration,
  open,
  onOpenChange
}: {
  integration: IntegrationConnection | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const projectIdId = useId();
  const rawDatasetId = useId();
  const readDatasetId = useId();
  const locationId = useId();
  const issuerId = useId();
  const audienceId = useId();
  const subjectId = useId();
  const attributeConditionId = useId();
  const serviceAccountNameId = useId();
  const connectorDatasetId = useId();
  const serviceAccountEmailId = useId();
  const workloadIdentityProviderId = useId();
  const [projectId, setProjectId] = useState("");
  const [rawDataset, setRawDataset] = useState<string>(
    googleWorkspaceBigQueryWifDefaults.rawDatasetId
  );
  const [readDataset, setReadDataset] = useState<string>(
    googleWorkspaceBigQueryWifDefaults.readDatasetId
  );
  const [location, setLocation] = useState<string>(
    googleWorkspaceBigQueryWifDefaults.location
  );
  const [accessMode, setAccessMode] =
    useState<GoogleWorkspaceBigQueryWifAccessMode>(
      googleWorkspaceBigQueryWifDefaults.accessMode
    );
  const [outputMode, setOutputMode] =
    useState<GoogleWorkspaceBigQueryWifOutputMode>(
      googleWorkspaceBigQueryWifDefaults.outputMode
    );
  const [oidcIssuerUri, setOidcIssuerUri] = useState("");
  const [oidcAudience, setOidcAudience] = useState<string>(
    googleWorkspaceBigQueryWifDefaults.oidcAudience
  );
  const [principalSubject, setPrincipalSubject] = useState("");
  const [providerAttributeCondition, setProviderAttributeCondition] =
    useState("");
  const [serviceAccountName, setServiceAccountName] =
    useState<string>(googleWorkspaceBigQueryWifDefaults.serviceAccountName);
  const [workloadIdentityProvider, setWorkloadIdentityProvider] = useState("");
  const [configLoading, setConfigLoading] = useState(false);
  const [configSaving, setConfigSaving] = useState(false);
  const [configMessage, setConfigMessage] = useState("");
  const [configError, setConfigError] = useState("");
  const [validationMessage, setValidationMessage] = useState("");
  const [validationError, setValidationError] = useState("");
  const [validating, setValidating] = useState(false);
  const [copied, setCopied] = useState(false);
  const integrationId = integration?.id ?? "";

  useEffect(() => {
    if (!open) setCopied(false);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    setProjectId("");
    setRawDataset(googleWorkspaceBigQueryWifDefaults.rawDatasetId);
    setReadDataset(googleWorkspaceBigQueryWifDefaults.readDatasetId);
    setLocation(googleWorkspaceBigQueryWifDefaults.location);
    setAccessMode(googleWorkspaceBigQueryWifDefaults.accessMode);
    setOutputMode(googleWorkspaceBigQueryWifDefaults.outputMode);
    setOidcIssuerUri("");
    setOidcAudience(googleWorkspaceBigQueryWifDefaults.oidcAudience);
    setPrincipalSubject("");
    setProviderAttributeCondition("");
    setServiceAccountName(googleWorkspaceBigQueryWifDefaults.serviceAccountName);
    setWorkloadIdentityProvider("");
    setConfigMessage("");
    setConfigError("");
    setValidationMessage("");
    setValidationError("");
    setCopied(false);
    if (!integrationId) return;
    let cancelled = false;
    setConfigLoading(true);
    fetchGoogleWorkspaceBigQueryConfig(integrationId)
      .then(({ data }) => {
        if (cancelled || !data.enabled) return;
        setProjectId(data.projectId);
        setRawDataset(
          data.rawDatasetId || data.datasetId || googleWorkspaceBigQueryWifDefaults.rawDatasetId
        );
        setReadDataset(data.datasetId || googleWorkspaceBigQueryWifDefaults.readDatasetId);
        setLocation(data.location || googleWorkspaceBigQueryWifDefaults.location);
        setAccessMode(
          data.accessMode === "dataset" ? "dataset" : googleWorkspaceBigQueryWifDefaults.accessMode
        );
        setWorkloadIdentityProvider(data.workloadIdentityProvider);
        const suffix = `@${data.projectId}.iam.gserviceaccount.com`;
        if (data.serviceAccountEmail.endsWith(suffix)) {
          setServiceAccountName(data.serviceAccountEmail.slice(0, -suffix.length));
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setConfigError(
            err instanceof Error ? err.message : "Unable to load saved BigQuery settings"
          );
        }
      })
      .finally(() => {
        if (!cancelled) setConfigLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [integrationId, open]);

  const rawDatasetValue = rawDataset.trim() || "workspace_logs";
  const readDatasetValue = readDataset.trim() || "aperio_workspace_views";
  const connectorDatasetValue =
    accessMode === "views" ? readDatasetValue : rawDatasetValue;
  const serviceAccountEmail =
    projectId.trim() && serviceAccountName.trim()
      ? `${serviceAccountName.trim()}@${projectId.trim()}.iam.gserviceaccount.com`
      : "";
  const sameViewDataset =
    accessMode === "views" && rawDatasetValue === readDatasetValue;

  const setupScriptResult = useMemo(() => {
    try {
      return {
        script: buildGoogleWorkspaceBigQueryWifSetupScript({
          projectId: projectId.trim() || "<gcp-project-id>",
          rawDatasetId: rawDatasetValue,
          readDatasetId: readDatasetValue,
          location: location.trim() || "US",
          serviceAccountName: serviceAccountName.trim() || "aperio-bq-reader",
          poolId: googleWorkspaceBigQueryWifDefaults.poolId,
          providerId: googleWorkspaceBigQueryWifDefaults.providerId,
          oidcIssuerUri: oidcIssuerUri.trim() || "<aperio-oidc-issuer-uri>",
          oidcAudience: oidcAudience.trim() || "aperio",
          principalSubject:
            principalSubject.trim() || "<trusted-aperio-workload-subject>",
          accessMode,
          outputMode,
          providerAttributeCondition:
            providerAttributeCondition.trim() || undefined
        }),
        error: ""
      };
    } catch (err) {
      return {
        script: "# Fix the setup fields to generate commands.",
        error: err instanceof Error ? err.message : "Unable to generate setup commands"
      };
    }
  }, [
    accessMode,
    location,
    oidcAudience,
    oidcIssuerUri,
    outputMode,
    principalSubject,
    projectId,
    providerAttributeCondition,
    rawDatasetValue,
    readDatasetValue,
    serviceAccountName
  ]);
  const setupScript = setupScriptResult.script;
  const setupScriptError = setupScriptResult.error;

  async function copyScript() {
    if (setupScriptError) return;
    await navigator.clipboard.writeText(setupScript);
    setCopied(true);
  }

  async function saveBigQueryConfig() {
    if (!integrationId || configSaving) return;
    setConfigMessage("");
    setConfigError("");
    setValidationMessage("");
    setValidationError("");
    if (setupScriptError) {
      setConfigError(setupScriptError);
      return;
    }
    if (!projectId.trim() || !serviceAccountEmail || !workloadIdentityProvider.trim()) {
      setConfigError(
        "Project ID, service account email, and workload identity provider are required."
      );
      return;
    }
    setConfigSaving(true);
    try {
      await updateGoogleWorkspaceBigQueryConfig(integrationId, {
        enabled: true,
        projectId: projectId.trim(),
        rawDatasetId: rawDatasetValue,
        datasetId: connectorDatasetValue,
        location: location.trim() || "US",
        serviceAccountEmail,
        workloadIdentityProvider: workloadIdentityProvider.trim(),
        accessMode
      });
      setConfigMessage("BigQuery settings saved in Aperio.");
    } catch (err) {
      setConfigError(
        err instanceof Error ? err.message : "Unable to save BigQuery settings"
      );
    } finally {
      setConfigSaving(false);
    }
  }

  async function validateBigQueryConfig() {
    if (!integrationId || validating) return;
    setValidationMessage("");
    setValidationError("");
    setConfigError("");
    setValidating(true);
    try {
      const { data } = await validateGoogleWorkspaceBigQueryConfig(integrationId);
      const details = data.tableFound
        ? `Found ${data.activityTable} (${data.sampleRows} sample rows, ${data.estimatedBytes.toString()} estimated bytes).`
        : "Activity table was not found.";
      if (data.ok) {
        setValidationMessage(`${data.message || "Validation succeeded."} ${details}`);
      } else {
        setValidationError(`${data.message || "Validation failed."} ${details}`);
      }
    } catch (err) {
      setValidationError(
        err instanceof Error ? err.message : "Unable to validate BigQuery settings"
      );
    } finally {
      setValidating(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] max-w-5xl overflow-y-auto p-0">
        <DialogHeader>
          <div className="border-b border-border px-6 pb-4 pt-6">
            <DialogTitle>Google Workspace BigQuery intelligence</DialogTitle>
            <DialogDescription className="mt-2 max-w-3xl">
              Configure least-privilege BigQuery access for{" "}
              {integration?.displayName ?? "this Google Workspace integration"} using
              Workload Identity Federation. No service-account keys are stored in
              Aperio.
            </DialogDescription>
          </div>
        </DialogHeader>

        <div className="grid gap-6 px-6 pb-6 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
          <div className="space-y-4">
            <div className="grid gap-2 sm:grid-cols-3">
              {[
                ["1", "Export logs", "Workspace audit logs land in BigQuery."],
                ["2", "Limit reads", "Authorized views are recommended."],
                ["3", "Run setup", "Copy commands into the data-owner project."]
              ].map(([step, title, body]) => (
                <div
                  key={step}
                  className="rounded-lg border border-border bg-card/60 p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-signal/15 font-mono text-[10px] font-semibold text-signal">
                      {step}
                    </span>
                    <span className="text-xs font-semibold text-foreground">
                      {title}
                    </span>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                    {body}
                  </p>
                </div>
              ))}
            </div>

            <section className="rounded-lg border border-border bg-card/50 p-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  Data-owner BigQuery project
                </h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  Point Aperio at the smallest readable dataset, not the raw export
                  unless that is intentional. The generated views preserve
                  partition metadata so Aperio can scan incrementally.
                </p>
              </div>
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <Field label="GCP project ID" htmlFor={projectIdId} required>
                  <Input
                    id={projectIdId}
                    value={projectId}
                    onChange={(event) => setProjectId(event.target.value)}
                    placeholder="example-security-logs"
                  />
                </Field>
                <Field label="BigQuery location" htmlFor={locationId} required>
                  <Input
                    id={locationId}
                    value={location}
                    onChange={(event) => setLocation(event.target.value)}
                    placeholder="US"
                  />
                </Field>
                <Field
                  label="Raw Workspace log dataset"
                  htmlFor={rawDatasetId}
                  hint="Dataset receiving Google Workspace BigQuery exports."
                  required
                >
                  <Input
                    id={rawDatasetId}
                    value={rawDataset}
                    onChange={(event) => setRawDataset(event.target.value)}
                  />
                </Field>
                {accessMode === "views" ? (
                  <Field
                    label="Aperio read-view dataset"
                    htmlFor={readDatasetId}
                    hint="Aperio gets dataViewer on this curated dataset."
                    error={
                      sameViewDataset
                        ? "Use a read-view dataset that is different from the raw export dataset."
                        : undefined
                    }
                    required
                  >
                    <Input
                      id={readDatasetId}
                      value={readDataset}
                      onChange={(event) => setReadDataset(event.target.value)}
                    />
                  </Field>
                ) : null}
              </div>
            </section>

            <section className="rounded-lg border border-border bg-card/50 p-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  Read scope
                </h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  Authorized views keep the Workspace export private while giving
                  Aperio a separate dataset to read.
                </p>
              </div>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                {(["views", "dataset"] as const).map((mode) => {
                  const active = accessMode === mode;
                  return (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={active}
                      onClick={() => setAccessMode(mode)}
                      className={cn(
                        "rounded-lg border p-3 text-left transition-colors",
                        active
                          ? "border-signal/50 bg-signal/10 text-foreground"
                          : "border-border bg-background text-muted-foreground hover:border-border/80 hover:bg-muted/50"
                      )}
                    >
                      <span className="block text-xs font-semibold">
                        {mode === "views" ? "Authorized views" : "Raw dataset"}
                      </span>
                      <span className="mt-1 block text-[11px] leading-relaxed">
                        {mode === "views"
                          ? "Recommended, grant Aperio only the view dataset."
                          : "Simpler, but Aperio can read the whole export dataset."}
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="rounded-lg border border-border bg-card/50 p-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  Setup output
                </h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  Generate either copy-paste setup commands or reusable Terraform
                  built with the shared IaC renderer.
                </p>
              </div>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                {(["bash", "terraform"] as const).map((mode) => {
                  const active = outputMode === mode;
                  return (
                    <button
                      key={mode}
                      type="button"
                      aria-pressed={active}
                      onClick={() => setOutputMode(mode)}
                      className={cn(
                        "rounded-lg border p-3 text-left transition-colors",
                        active
                          ? "border-signal/50 bg-signal/10 text-foreground"
                          : "border-border bg-background text-muted-foreground hover:border-border/80 hover:bg-muted/50"
                      )}
                    >
                      <span className="block text-xs font-semibold">
                        {mode === "bash" ? "gcloud and bq" : "Terraform"}
                      </span>
                      <span className="mt-1 block text-[11px] leading-relaxed">
                        {mode === "bash"
                          ? "Operational commands for a one-time setup."
                          : "Declarative resources for code-reviewed infra."}
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>

            <section className="rounded-lg border border-border bg-card/50 p-4">
              <div>
                <h3 className="text-sm font-semibold text-foreground">
                  Workload Identity trust
                </h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  Aperio impersonates one reader service account through OIDC, with
                  no downloadable keys.
                </p>
              </div>
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <Field
                  label="Service account name"
                  htmlFor={serviceAccountNameId}
                  hint="Created in the data-owner project."
                  required
                >
                  <Input
                    id={serviceAccountNameId}
                    value={serviceAccountName}
                    onChange={(event) =>
                      setServiceAccountName(event.target.value)
                    }
                  />
                </Field>
                <Field label="OIDC audience" htmlFor={audienceId} required>
                  <Input
                    id={audienceId}
                    value={oidcAudience}
                    onChange={(event) => setOidcAudience(event.target.value)}
                  />
                </Field>
                <div className="sm:col-span-2">
                  <Field
                    label="Aperio OIDC issuer URI"
                    htmlFor={issuerId}
                    hint="Use the issuer for your Aperio deployment or runtime identity provider."
                    required
                  >
                    <Input
                      id={issuerId}
                      value={oidcIssuerUri}
                      onChange={(event) => setOidcIssuerUri(event.target.value)}
                      placeholder="https://issuer.example.com"
                    />
                  </Field>
                </div>
                <div className="sm:col-span-2">
                  <Field
                    label="Trusted subject"
                    htmlFor={subjectId}
                    hint="Exact OIDC subject allowed to impersonate the reader service account."
                    required
                  >
                    <Input
                      id={subjectId}
                      value={principalSubject}
                      onChange={(event) => setPrincipalSubject(event.target.value)}
                      placeholder="repo:example/aperio:ref:refs/heads/main"
                    />
                  </Field>
                </div>
                <div className="sm:col-span-2">
                  <Field
                    label="Provider attribute condition"
                    htmlFor={attributeConditionId}
                    hint="Optional CEL condition. Defaults to locking google.subject to the trusted subject."
                  >
                    <Input
                      id={attributeConditionId}
                      value={providerAttributeCondition}
                      onChange={(event) =>
                        setProviderAttributeCondition(event.target.value)
                      }
                      placeholder='assertion.repository == "example/aperio"'
                    />
                  </Field>
                </div>
              </div>
            </section>
          </div>

          <div className="space-y-3 lg:sticky lg:top-0 lg:self-start">
            <div className="rounded-lg border border-border bg-card/50">
              <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
                <div>
                  <div className="text-sm font-semibold text-foreground">
                    {outputMode === "terraform" ? "Terraform module" : "Commands to run"}
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {outputMode === "terraform"
                      ? "Reusable GCP resources for your infrastructure repo."
                      : "Generic `gcloud` and `bq` setup for any Aperio deployment."}
                  </div>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void copyScript()}
                  disabled={Boolean(setupScriptError)}
                  className="shrink-0"
                >
                  {copied ? (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                  ) : (
                    <Copy className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
              <Textarea
                readOnly
                value={setupScript}
                className="h-[560px] min-h-[560px] resize-none rounded-none border-0 bg-background/80 font-mono text-[11px] leading-relaxed shadow-none focus-visible:ring-0"
                aria-label="Google Workspace BigQuery WIF setup output"
              />
            </div>
            {setupScriptError ? (
              <FormBanner tone="error" className="text-xs">
                {setupScriptError}
              </FormBanner>
            ) : null}
            <FormBanner tone="info" className="text-xs">
              This prepares least-privilege BigQuery access. After the commands
              complete, use the printed project, dataset, service account, and WIF
              provider values in Aperio.
            </FormBanner>
            <div className="rounded-lg border border-border bg-card/50 p-4">
              <div>
                <div className="text-sm font-semibold text-foreground">
                  Save in Aperio
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  After running the commands, save the connector values printed by
                  the script so Aperio can use them.
                </p>
              </div>
              <div className="mt-4 space-y-3">
                <Field label="Connector dataset ID" htmlFor={connectorDatasetId}>
                  <Input
                    id={connectorDatasetId}
                    value={connectorDatasetValue}
                    readOnly
                    className="font-mono text-xs"
                  />
                </Field>
                <Field label="Service account email" htmlFor={serviceAccountEmailId}>
                  <Input
                    id={serviceAccountEmailId}
                    value={serviceAccountEmail}
                    readOnly
                    placeholder="aperio-bq-reader@example.iam.gserviceaccount.com"
                    className="font-mono text-xs"
                  />
                </Field>
                <Field
                  label="Workload identity provider"
                  htmlFor={workloadIdentityProviderId}
                  hint="Paste the provider resource printed after the commands finish."
                  required
                >
                  <Input
                    id={workloadIdentityProviderId}
                    value={workloadIdentityProvider}
                    onChange={(event) =>
                      setWorkloadIdentityProvider(event.target.value)
                    }
                    placeholder="projects/123/locations/global/workloadIdentityPools/aperio-workloads/providers/aperio-oidc"
                    className="font-mono text-xs"
                  />
                </Field>
                {configLoading ? (
                  <FormBanner tone="info" className="text-xs">
                    Loading saved BigQuery settings…
                  </FormBanner>
                ) : null}
                {configError ? (
                  <FormBanner tone="error" className="text-xs">
                    {configError}
                  </FormBanner>
                ) : null}
                {configMessage ? (
                  <FormBanner tone="success" className="text-xs">
                    {configMessage}
                  </FormBanner>
                ) : null}
                {validationError ? (
                  <FormBanner tone="error" className="text-xs">
                    {validationError}
                  </FormBanner>
                ) : null}
                {validationMessage ? (
                  <FormBanner tone="success" className="text-xs">
                    {validationMessage}
                  </FormBanner>
                ) : null}
                <Button
                  type="button"
                  onClick={() => void saveBigQueryConfig()}
                  disabled={configSaving || Boolean(setupScriptError)}
                  className="w-full"
                >
                  {configSaving ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {configSaving ? "Saving…" : "Save BigQuery settings"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void validateBigQueryConfig()}
                  disabled={validating || !integrationId}
                  className="w-full"
                >
                  {validating ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <ListChecks className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {validating ? "Validating…" : "Validate saved BigQuery access"}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ConnectDialog({
  connector,
  onClose,
  onConnected
}: {
  connector: ConnectorDefinition | null;
  onClose: () => void;
  onConnected: () => Promise<void>;
}) {
  const displayNameId = useId();
  const externalAccountId = useId();
  const [displayName, setDisplayName] = useState("");
  const [externalAccount, setExternalAccount] = useState("");
  const [mode, setMode] = useState<IntegrationMode>("READ_ONLY");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [oauthClient, setOauthClient] = useState<IntegrationOAuthClient | null>(null);
  const [oauthClientLoading, setOauthClientLoading] = useState(false);
  const [showOauthSetup, setShowOauthSetup] = useState(false);

  const isGoogleWorkspace = connector?.provider === "GOOGLE_WORKSPACE";

  useEffect(() => {
    if (connector) {
      // Reset form state whenever a new connector is selected so credential
      // values from one provider cannot bleed into another provider's dialog.
      setDisplayName(`${connector.name} workspace`);
      setExternalAccount("");
      setMode("READ_ONLY");
      setFieldValues({});
      setError("");
      setOauthClient(null);
      setShowOauthSetup(false);
    }
  }, [connector]);

  useEffect(() => {
    if (!connector || !isGoogleWorkspace) return;
    let cancelled = false;
    setOauthClientLoading(true);
    fetchIntegrationOAuthClient("GOOGLE_WORKSPACE")
      .then(({ data }) => {
        if (cancelled) return;
        setOauthClient(data);
        setShowOauthSetup(data.source === "");
      })
      .catch(() => {
        if (cancelled) return;
        setOauthClient({
          provider: "GOOGLE_WORKSPACE",
          clientId: "",
          redirectUri: "",
          defaultRedirectUri: "",
          configured: false,
          source: "",
          updatedAt: null
        });
        setShowOauthSetup(true);
      })
      .finally(() => {
        if (!cancelled) setOauthClientLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [connector, isGoogleWorkspace]);

  if (!connector) {
    return null;
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!connector) return;

    if (isGoogleWorkspace) {
      // Google Workspace captures the workspace domain and refresh token through
      // OAuth callback state, so manual credential fields are deliberately hidden.
      if (!oauthClient || oauthClient.source === "") {
        setShowOauthSetup(true);
        setError(
          "Add your Google Cloud OAuth client credentials below before continuing."
        );
        return;
      }
      setSaving(true);
      setError("");
      try {
        const response = await startGoogleWorkspaceOAuth(mode);
        if (typeof window !== "undefined") {
          window.location.assign(response.data.url);
        }
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Unable to start Google OAuth"
        );
        setSaving(false);
      }
      return;
    }

    const credentials = {
      // Connector catalog entries may name the primary secret accessToken or
      // token. Normalize both field names into the API payload.
      accessToken: fieldValues.accessToken ?? fieldValues.token ?? "",
      refreshToken: fieldValues.refreshToken,
      webhookSecret: fieldValues.webhookSecret
    };

    setSaving(true);
    setError("");
    try {
      const payload: ConnectIntegrationPayload = {
        provider: connector.provider,
        displayName: displayName.trim(),
        externalAccountId: externalAccount.trim(),
        mode,
        credentials
      };
      // Manual connectors post only after local normalization; server-side
      // validation/encryption remains authoritative.
      await connectIntegration(payload);
      await onConnected();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open={Boolean(connector)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Connect {connector.name}</DialogTitle>
          <DialogDescription>
            {isGoogleWorkspace
              ? "You'll be redirected to Google to sign in as a super admin and authorize Aperio. The workspace domain and tokens are captured automatically."
              : "Tokens are encrypted with AES-256-GCM before being stored."}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {isGoogleWorkspace ? null : (
            <>
              <Field label="Display name" htmlFor={displayNameId} required>
                <Input
                  id={displayNameId}
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                  required
                />
              </Field>
              <Field
                label="External account ID"
                htmlFor={externalAccountId}
                hint="Tenant or workspace identifier from the SaaS app."
                required
              >
                <Input
                  id={externalAccountId}
                  value={externalAccount}
                  onChange={(event) => setExternalAccount(event.target.value)}
                  required
                />
              </Field>
            </>
          )}
          <Field label="Mode" hint="You can upgrade modes later.">
            <div className="flex gap-2">
              {(["READ_ONLY", "REMEDIATION"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setMode(option)}
                  className={`flex-1 rounded-md border px-3 py-2 text-xs font-medium transition-colors ${
                    mode === option
                      ? "border-foreground bg-foreground text-background"
                      : "border-border text-muted-foreground hover:bg-muted"
                  }`}
                >
                  {option === "READ_ONLY" ? "Read-only" : "Read + remediate"}
                </button>
              ))}
            </div>
          </Field>

          {isGoogleWorkspace ? (
            <GoogleOAuthClientPanel
              loading={oauthClientLoading}
              client={oauthClient}
              showSetup={showOauthSetup}
              onChange={(next) => {
                setOauthClient(next);
                setShowOauthSetup(next.source === "");
              }}
              onRequestEdit={() => setShowOauthSetup(true)}
              onCancelEdit={() => setShowOauthSetup(false)}
              onError={setError}
            />
          ) : null}

          {isGoogleWorkspace
            ? null
            : connector.fields.map((field) => (
                <Field
                  key={field.key}
                  label={field.label}
                  hint={field.helper}
                  required={field.required}
                >
                  <Input
                    type={field.type === "password" ? "password" : "text"}
                    placeholder={field.placeholder}
                    value={fieldValues[field.key] ?? ""}
                    onChange={(event) =>
                      setFieldValues((prev) => ({
                        ...prev,
                        [field.key]: event.target.value
                      }))
                    }
                    required={field.required}
                  />
                </Field>
              ))}

          <FormBanner tone="error">{error}</FormBanner>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={saving}
              loadingText={
                isGoogleWorkspace ? "Redirecting…" : "Connecting…"
              }
              disabled={
                isGoogleWorkspace &&
                (oauthClientLoading ||
                  !oauthClient ||
                  oauthClient.source === "" ||
                  showOauthSetup)
              }
            >
              <CheckCircle2 className="h-4 w-4" />
              {isGoogleWorkspace ? "Continue with Google" : "Connect"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GoogleOAuthClientPanel({
  loading,
  client,
  showSetup,
  onChange,
  onRequestEdit,
  onCancelEdit,
  onError
}: {
  loading: boolean;
  client: IntegrationOAuthClient | null;
  showSetup: boolean;
  onChange: (next: IntegrationOAuthClient) => void;
  onRequestEdit: () => void;
  onCancelEdit: () => void;
  onError: (message: string) => void;
}) {
  const clientIdInputId = useId();
  const clientSecretInputId = useId();
  const redirectInputId = useId();
  const [clientIdInput, setClientIdInput] = useState("");
  const [clientSecretInput, setClientSecretInput] = useState("");
  const [redirectInput, setRedirectInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    if (!client) return;
    if (client.source === "tenant") {
      setClientIdInput(client.clientId);
      setRedirectInput(client.redirectUri || client.defaultRedirectUri);
    } else {
      // env or unconfigured: start the setup form blank so admins don't
      // accidentally save the operator-wide values as their tenant secret.
      setClientIdInput("");
      setRedirectInput(client.defaultRedirectUri);
    }
    setClientSecretInput("");
  }, [client]);

  if (loading) {
    return (
      <div className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
        Loading Google OAuth client configuration…
      </div>
    );
  }

  if (!client) return null;

  const isTenantConfigured = client.source === "tenant";

  async function handleSave() {
    if (!clientIdInput.trim() || !clientSecretInput.trim() || !redirectInput.trim()) {
      onError("Client ID, client secret, and redirect URI are required.");
      return;
    }
    setSaving(true);
    try {
      const { data } = await saveIntegrationOAuthClient({
        provider: "GOOGLE_WORKSPACE",
        clientId: clientIdInput.trim(),
        clientSecret: clientSecretInput.trim(),
        redirectUri: redirectInput.trim()
      });
      onChange(data);
      onError("");
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Unable to save Google OAuth client credentials"
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleClear() {
    setClearing(true);
    try {
      const { data } = await clearIntegrationOAuthClient("GOOGLE_WORKSPACE");
      // onChange flips back into summary mode when the response still has a
      // usable source (e.g. env fallback). When neither tenant nor env is set
      // it shows the setup form.
      onChange(data);
      setClientIdInput("");
      setClientSecretInput("");
      setRedirectInput(data.defaultRedirectUri);
      onError("");
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Unable to clear Google OAuth client credentials"
      );
    } finally {
      setClearing(false);
    }
  }

  if (client.source !== "" && !showSetup) {
    return (
      <div className="flex items-start justify-between gap-3 rounded-md border border-border bg-muted/30 p-3 text-xs">
        <div className="space-y-0.5">
          <div className="font-medium text-foreground">
            {isTenantConfigured
              ? "Using your Google Cloud OAuth app"
              : "Using the operator-configured Google OAuth app"}
          </div>
          <div className="text-muted-foreground">Client ID: {client.clientId}</div>
          <div className="text-muted-foreground">
            Redirect URI: {client.redirectUri}
          </div>
          {!isTenantConfigured ? (
            <div className="text-muted-foreground">
              These credentials come from the Aperio deployment&apos;s
              environment variables. You can override them for this workspace
              by registering your own OAuth app.
            </div>
          ) : null}
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onRequestEdit}
        >
          {isTenantConfigured ? "Edit" : "Use your own app"}
        </Button>
      </div>
    );
  }

  function handlePanelKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    // The credential editor is nested inside the outer connect form. Without
    // this guard, pressing Enter in a field would submit the outer form and
    // start OAuth with the old saved credentials before the edits are saved.
    if (event.key !== "Enter" || event.shiftKey) return;
    const target = event.target as HTMLElement | null;
    if (target?.tagName !== "INPUT") return;
    event.preventDefault();
    event.stopPropagation();
    if (!saving) {
      void handleSave();
    }
  }

  return (
    <div
      className="space-y-3 rounded-md border border-dashed border-border bg-muted/20 p-3 text-xs"
      onKeyDown={handlePanelKeyDown}
    >
      <div className="space-y-1">
        <div className="text-sm font-medium text-foreground">
          Google Cloud OAuth client
        </div>
        <p className="text-muted-foreground">
          One-time setup per workspace. In Google Cloud Console open APIs &amp; Services
          → Credentials, create an OAuth client ID (type: Web application), add the
          redirect URI below to "Authorized redirect URIs", then paste the client ID
          and secret here.
        </p>
      </div>
      {/*
        The editor lives inside the outer connect <form>, so we deliberately
        skip the native `required` attribute on these inputs. handleSave runs
        the equivalent presence check before calling the RPC, which avoids
        HTML5 validation bubbles firing on a blank credential secret when the
        user submits the outer form to start OAuth with existing credentials.
      */}
      <Field label="Client ID" htmlFor={clientIdInputId} required>
        <Input
          id={clientIdInputId}
          value={clientIdInput}
          onChange={(event) => setClientIdInput(event.target.value)}
          placeholder="...apps.googleusercontent.com"
          aria-required="true"
        />
      </Field>
      <Field label="Client secret" htmlFor={clientSecretInputId} required>
        <Input
          id={clientSecretInputId}
          type="password"
          value={clientSecretInput}
          onChange={(event) => setClientSecretInput(event.target.value)}
          placeholder={isTenantConfigured ? "Re-enter the client secret to update" : ""}
          aria-required="true"
        />
      </Field>
      <Field
        label="Authorized redirect URI"
        htmlFor={redirectInputId}
        hint="Must match the value configured in Google Cloud Console exactly."
        required
      >
        <Input
          id={redirectInputId}
          value={redirectInput}
          onChange={(event) => setRedirectInput(event.target.value)}
          aria-required="true"
        />
      </Field>
      <div className="flex flex-wrap justify-end gap-2">
        {isTenantConfigured ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleClear}
            loading={clearing}
            loadingText="Removing…"
          >
            Remove credentials
          </Button>
        ) : null}
        {client.source !== "" ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onCancelEdit}
          >
            Cancel
          </Button>
        ) : null}
        <Button
          type="button"
          size="sm"
          onClick={handleSave}
          loading={saving}
          loadingText="Saving…"
        >
          Save credentials
        </Button>
      </div>
    </div>
  );
}
