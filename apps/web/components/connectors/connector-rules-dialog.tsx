"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import {
  createCustomRule,
  deleteCustomRule,
  fetchConnectorRules,
  updateCustomRule,
  updateIntegrationChecks,
  type CheckDisableInput,
  type ConnectorBuiltInRule,
  type ConnectorCustomRule,
  type ConnectorRulesResponse,
  type CustomRuleInput
} from "../../lib/api";
import { providerLabel } from "../../lib/format";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../ui/dialog";
import { Field, FormBanner, Input } from "../ui/form";
import { Skeleton } from "../ui/skeleton";
import { Switch } from "../ui/switch";
import { useToast } from "../ui/toast";

type Props = {
  integrationId: string | null;
  integrationLabel: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

type CustomDraft = {
  name: string;
  severity: CustomRuleInput["severity"];
  eventType: string;
  subjectField: string;
  predicateText: string;
  enabled: boolean;
};

const EMPTY_DRAFT: CustomDraft = {
  name: "",
  severity: "MEDIUM",
  eventType: "",
  subjectField: "",
  predicateText: "{}",
  enabled: true
};

const DISABLE_WINDOW_DEFAULT_DAYS = 14;

function normalizeDisableExpiry(input: string): string | null {
  const raw = input.trim();
  if (!raw) return null;
  const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
  if (dateOnly) {
    const year = Number(dateOnly[1]);
    const month = Number(dateOnly[2]) - 1;
    const day = Number(dateOnly[3]);
    const parsed = new Date(Date.UTC(year, month, day, 23, 59, 59));
    if (
      parsed.getUTCFullYear() !== year ||
      parsed.getUTCMonth() !== month ||
      parsed.getUTCDate() !== day
    ) {
      return null;
    }
    return parsed.toISOString();
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

function collectDisableInput(ruleTitle: string): CheckDisableInput | null {
  const reason = window.prompt(`Reason for disabling "${ruleTitle}"`, "");
  if (reason === null) return null;
  if (!reason.trim()) {
    throw new Error("A disable reason is required.");
  }
  const defaultExpiry = new Date(
    Date.now() + DISABLE_WINDOW_DEFAULT_DAYS * 24 * 60 * 60 * 1000
  )
    .toISOString()
    .slice(0, 10);
  const expiresInput = window.prompt(
    "Disable until (YYYY-MM-DD or RFC3339 timestamp)",
    defaultExpiry
  );
  if (expiresInput === null) return null;
  const expiresAt = normalizeDisableExpiry(expiresInput);
  if (!expiresAt) {
    throw new Error("Disable expiry must be YYYY-MM-DD or RFC3339.");
  }
  return { reason: reason.trim(), expiresAt };
}

export function ConnectorRulesDialog({
  integrationId,
  integrationLabel,
  open,
  onOpenChange
}: Props) {
  const { toast } = useToast();
  const [data, setData] = useState<ConnectorRulesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [savingRuleId, setSavingRuleId] = useState<string | null>(null);
  const [draft, setDraft] = useState<CustomDraft>(EMPTY_DRAFT);
  const [draftError, setDraftError] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!integrationId) return;
    setLoading(true);
    setError("");
    try {
      const result = await fetchConnectorRules(integrationId);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load rules");
    } finally {
      setLoading(false);
    }
  }, [integrationId]);

  useEffect(() => {
    if (open && integrationId) {
      void load();
    }
    if (!open) {
      setData(null);
      setDraft(EMPTY_DRAFT);
      setDraftError("");
      setError("");
    }
  }, [open, integrationId, load]);

  const toggleBuiltIn = useCallback(
    async (rule: ConnectorBuiltInRule, nextEnabled: boolean) => {
      if (!integrationId) return;
      // Re-fetch the canonical rules right before computing the next
      // disabled set. Without this, two rapid clicks on different switches
      // would each read the same stale `disabledIds` baseline and the
      // second updateIntegrationChecks would overwrite the first — silently
      // re-enabling a rule the operator had just disabled. Pairing the
      // refetch with savingRuleId locking ALL
      // toggles below closes the race from both directions.
      setSavingRuleId(rule.id);
      try {
        const fresh = await fetchConnectorRules(integrationId);
        const next = new Set<string>();
        fresh.builtIn.forEach((r: ConnectorBuiltInRule) => {
          if (!r.enabled) next.add(r.id);
        });
        if (nextEnabled) {
          next.delete(rule.id);
        } else {
          next.add(rule.id);
        }
        let disableInput: CheckDisableInput | undefined;
        if (!nextEnabled) {
          const collected = collectDisableInput(rule.title);
          if (!collected) {
            return;
          }
          disableInput = collected;
        }
        await updateIntegrationChecks(integrationId, Array.from(next), disableInput);
        toast({
          tone: "success",
          title: nextEnabled ? "Rule enabled" : "Rule disabled",
          description: nextEnabled
            ? `${rule.title} is now scoring incoming events.`
            : `${rule.title} disabled until re-enabled or expiry. Existing findings remain for audit history.`
        });
        await load();
      } catch (err) {
        toast({
          tone: "error",
          title: "Failed to update rule",
          description: err instanceof Error ? err.message : "Try again"
        });
      } finally {
        setSavingRuleId(null);
      }
    },
    [integrationId, load, toast]
  );

  const submitDraft = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!integrationId) return;
      setDraftError("");
      const name = draft.name.trim();
      const eventType = draft.eventType.trim().toUpperCase();
      if (!name) {
        setDraftError("Name is required.");
        return;
      }
      if (!eventType) {
        setDraftError("Event type is required (e.g. EXTERNAL_SHARING_ENABLED).");
        return;
      }
      let predicate: unknown = {};
      const predicateText = draft.predicateText.trim() || "{}";
      try {
        predicate = JSON.parse(predicateText);
      } catch {
        setDraftError("Predicate must be valid JSON. Use {} to match every event of this type.");
        return;
      }
      setCreating(true);
      try {
        await createCustomRule(integrationId, {
          name,
          severity: draft.severity,
          eventType,
          subjectField: draft.subjectField.trim(),
          predicate,
          enabled: draft.enabled
        });
        toast({
          tone: "success",
          title: "Custom rule created",
          description: `${name} will fire on the next matching event.`
        });
        setDraft(EMPTY_DRAFT);
        await load();
      } catch (err) {
        setDraftError(err instanceof Error ? err.message : "Failed to create rule");
      } finally {
        setCreating(false);
      }
    },
    [draft, integrationId, load, toast]
  );

  const toggleCustom = useCallback(
    async (rule: ConnectorCustomRule, nextEnabled: boolean) => {
      if (!integrationId) return;
      setSavingRuleId(rule.id);
      try {
        await updateCustomRule(integrationId, rule.id, {
          name: rule.name,
          severity: rule.severity as CustomRuleInput["severity"],
          eventType: rule.eventType,
          subjectField: rule.subjectField,
          predicate: rule.predicate ?? {},
          enabled: nextEnabled
        });
        toast({
          tone: "success",
          title: nextEnabled ? "Custom rule enabled" : "Custom rule disabled"
        });
        await load();
      } catch (err) {
        toast({
          tone: "error",
          title: "Failed to toggle custom rule",
          description: err instanceof Error ? err.message : "Try again"
        });
      } finally {
        setSavingRuleId(null);
      }
    },
    [integrationId, load, toast]
  );

  const removeCustom = useCallback(
    async (rule: ConnectorCustomRule) => {
      if (!integrationId) return;
      if (!confirm(`Delete custom rule "${rule.name}"?`)) return;
      setSavingRuleId(rule.id);
      try {
        await deleteCustomRule(integrationId, rule.id);
        toast({ tone: "success", title: "Custom rule deleted" });
        await load();
      } catch (err) {
        toast({
          tone: "error",
          title: "Failed to delete custom rule",
          description: err instanceof Error ? err.message : "Try again"
        });
      } finally {
        setSavingRuleId(null);
      }
    },
    [integrationId, load, toast]
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Finding rules: {integrationLabel}</DialogTitle>
          <DialogDescription>
            Toggle built-in rules and add custom rules over the raw event payload. Disabling a
            built-in rule suppresses future detections for this integration.
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : error ? (
          <FormBanner tone="error">{error}</FormBanner>
        ) : data ? (
          <div className="max-h-[60vh] space-y-6 overflow-y-auto">
            <section>
              <h3 className="mb-2 text-sm font-semibold text-foreground">
                Built-in rules
                <span className="ml-2 text-xs font-normal text-muted-foreground">
                  {providerLabel(data.provider)} · {data.builtIn.length} rules
                </span>
              </h3>
              <ul className="space-y-2">
                {data.builtIn.length === 0 ? (
                  <li className="text-sm text-muted-foreground">
                    No built-in rules registered for this provider yet.
                  </li>
                ) : (
                  data.builtIn.map((rule: ConnectorBuiltInRule) => (
                    <li
                      key={rule.id}
                      className="flex items-start gap-3 rounded border border-border bg-background p-3"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground">{rule.title}</span>
                          <Badge variant="outline">{rule.severity}</Badge>
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">{rule.description}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          Triggers on: {rule.eventTypes.join(", ")}
                        </p>
                      </div>
                      <Switch
                        checked={rule.enabled}
                        disabled={savingRuleId !== null}
                        onCheckedChange={(checked) => void toggleBuiltIn(rule, checked)}
                        aria-label={`Toggle ${rule.title}`}
                      />
                    </li>
                  ))
                )}
              </ul>
            </section>

            <section>
              <h3 className="mb-2 text-sm font-semibold text-foreground">
                Custom rules
                <span className="ml-2 text-xs font-normal text-muted-foreground">
                  {data.custom.length} defined
                </span>
              </h3>
              <ul className="space-y-2">
                {data.custom.length === 0 ? (
                  <li className="text-sm text-muted-foreground">
                    No custom rules yet. Add one below to surface custom alerts on operator-defined
                    conditions.
                  </li>
                ) : (
                  data.custom.map((rule: ConnectorCustomRule) => (
                    <li
                      key={rule.id}
                      className="flex items-start gap-3 rounded border border-border bg-background p-3"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground">{rule.name}</span>
                          <Badge variant="outline">{rule.severity}</Badge>
                          <Badge variant="secondary">{rule.eventType}</Badge>
                          {rule.subjectField ? (
                            <Badge variant="outline">subject: {rule.subjectField}</Badge>
                          ) : null}
                        </div>
                        <pre className="mt-2 max-h-24 overflow-auto rounded bg-muted p-2 text-[11px]">
                          {JSON.stringify(rule.predicate ?? {}, null, 2)}
                        </pre>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <Switch
                          checked={rule.enabled}
                          disabled={savingRuleId !== null}
                          onCheckedChange={(checked) => void toggleCustom(rule, checked)}
                          aria-label={`Toggle ${rule.name}`}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          disabled={savingRuleId !== null}
                          onClick={() => void removeCustom(rule)}
                          aria-label={`Delete ${rule.name}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </li>
                  ))
                )}
              </ul>
            </section>

            <section>
              <h3 className="mb-2 text-sm font-semibold text-foreground">Add custom rule</h3>
              <form className="space-y-3" onSubmit={submitDraft}>
                <Field label="Name">
                  <Input
                    value={draft.name}
                    onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                    placeholder="Vendor analytics OAuth grants from finance"
                    maxLength={160}
                    required
                  />
                </Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Severity">
                    <select
                      value={draft.severity}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          severity: event.target.value as CustomRuleInput["severity"]
                        })
                      }
                      className="h-9 w-full rounded border border-border bg-background px-2 text-sm"
                    >
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </Field>
                  <Field label="Event type">
                    <Input
                      value={draft.eventType}
                      onChange={(event) =>
                        setDraft({ ...draft, eventType: event.target.value.toUpperCase() })
                      }
                      placeholder="EXTERNAL_SHARING_ENABLED"
                      required
                    />
                  </Field>
                </div>
                <Field
                  label="Subject field (optional). Dot-pathed payload field used as the finding's subject and dedupe key. Leave blank to keep one finding per actor."
                >
                  <Input
                    value={draft.subjectField}
                    onChange={(event) =>
                      setDraft({ ...draft, subjectField: event.target.value })
                    }
                    placeholder="payload.parameters.target"
                    maxLength={200}
                  />
                </Field>
                <Field
                  label='Predicate (JSON). Use {} to match every event of the type above. AND/OR over: equals, not_equals, contains, exists, in.'
                >
                  <textarea
                    value={draft.predicateText}
                    onChange={(event) =>
                      setDraft({ ...draft, predicateText: event.target.value })
                    }
                    rows={6}
                    spellCheck={false}
                    className="block w-full rounded border border-border bg-background p-2 font-mono text-xs"
                  />
                </Field>
                {draftError && <FormBanner tone="error">{draftError}</FormBanner>}
                <div className="flex justify-end gap-2">
                  <Button type="submit" disabled={creating}>
                    <Plus className="mr-1 h-4 w-4" />
                    {creating ? "Saving…" : "Add rule"}
                  </Button>
                </div>
              </form>
            </section>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
