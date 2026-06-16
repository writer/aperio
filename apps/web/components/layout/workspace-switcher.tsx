"use client";

import * as React from "react";
import { Check, ChevronDown, Loader2 } from "lucide-react";
import { useAuth } from "../auth/auth-shell";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from "../ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from "../ui/dropdown-menu";
import { Field, Input } from "../ui/form";
import { useToast } from "../ui/toast";
import {
  fetchWorkspaces,
  switchWorkspace,
  type WorkspaceMembership
} from "../../lib/api";

export function WorkspaceSwitcher() {
  const { session, refreshSession } = useAuth();
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [workspaces, setWorkspaces] = React.useState<
    WorkspaceMembership[] | null
  >(null);
  const [loading, setLoading] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);
  const [switchingSlug, setSwitchingSlug] = React.useState<string | null>(null);
  const [pendingWorkspace, setPendingWorkspace] =
    React.useState<WorkspaceMembership | null>(null);
  const [switchPassword, setSwitchPassword] = React.useState("");
  const [switchTotpCode, setSwitchTotpCode] = React.useState("");
  const passwordId = React.useId();
  const totpId = React.useId();

  React.useEffect(() => {
    if (!open || workspaces !== null || errorMessage) return;
    let cancelled = false;
    setLoading(true);
    setErrorMessage(null);
    fetchWorkspaces()
      .then((response) => {
        if (cancelled) return;
        setWorkspaces(response.data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setWorkspaces(null);
        setErrorMessage(
          err instanceof Error ? err.message : "Unable to load tenants"
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, workspaces, errorMessage]);

  React.useEffect(() => {
    setWorkspaces(null);
  }, [session?.organization.id]);

  function openSwitchDialog(workspace: WorkspaceMembership) {
    if (workspace.current || switchingSlug) return;
    setOpen(false);
    setPendingWorkspace(workspace);
    setSwitchPassword("");
    setSwitchTotpCode("");
  }

  async function handleSwitchSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!pendingWorkspace || switchingSlug || switchPassword.trim() === "")
      return;
    const workspace = pendingWorkspace;
    setSwitchingSlug(workspace.slug);
    try {
      const response = await switchWorkspace({
        organizationSlug: workspace.slug,
        password: switchPassword,
        totpCode: switchTotpCode.trim() || undefined
      });
      setPendingWorkspace(null);
      setSwitchPassword("");
      setSwitchTotpCode("");
      setWorkspaces(null);
      if (typeof window !== "undefined") {
        window.location.assign("/");
        return;
      }
      await refreshSession();
      toast({
        title: `Switched to ${response.data.organization.name}`,
        tone: "success"
      });
    } catch (err) {
      toast({
        title: "Unable to switch tenant",
        description: err instanceof Error ? err.message : undefined,
        tone: "error"
      });
    } finally {
      setSwitchingSlug(null);
    }
  }

  function handleSwitchDialogOpenChange(next: boolean) {
    if (next || switchingSlug) return;
    setPendingWorkspace(null);
    setSwitchPassword("");
    setSwitchTotpCode("");
  }

  const currentName = session?.organization.name ?? "Tenant";

  function handleOpenChange(next: boolean) {
    if (next && errorMessage) {
      setWorkspaces(null);
      setErrorMessage(null);
    }
    setOpen(next);
  }

  return (
    <>
      <DropdownMenu open={open} onOpenChange={handleOpenChange}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            aria-label="Switch tenant"
            className="h-8 gap-2 border-foreground bg-foreground px-2.5 text-background shadow-sm hover:bg-foreground/90 hover:text-background"
          >
            <span className="flex min-w-0 flex-col items-start leading-tight">
              <span className="text-[9px] font-medium uppercase tracking-wider opacity-70">
                Tenant
              </span>
              <span className="max-w-[160px] truncate text-xs font-semibold">
                {currentName}
              </span>
            </span>
            <ChevronDown className="h-3.5 w-3.5 opacity-70" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Switch tenant
          </DropdownMenuLabel>
          {loading && workspaces === null ? (
            <div className="flex items-center gap-2 px-2 py-1.5 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
              Loading tenants...
            </div>
          ) : errorMessage ? (
            <div className="px-2 py-1.5 text-xs text-destructive">
              {errorMessage}
            </div>
          ) : workspaces && workspaces.length > 0 ? (
            <>
              {workspaces.map((workspace) => {
                const isCurrent = workspace.current;
                const isSwitching = switchingSlug === workspace.slug;
                return (
                  <DropdownMenuItem
                    key={workspace.id}
                    onSelect={(event) => {
                      event.preventDefault();
                      if (!isCurrent) openSwitchDialog(workspace);
                    }}
                    disabled={isCurrent || Boolean(switchingSlug)}
                    className="flex items-start gap-2"
                  >
                    <div className="mt-0.5 h-3.5 w-3.5 shrink-0">
                      {isSwitching ? (
                        <Loader2
                          className="h-3.5 w-3.5 animate-spin text-muted-foreground"
                          aria-hidden
                        />
                      ) : isCurrent ? (
                        <Check
                          className="h-3.5 w-3.5 text-signal"
                          aria-hidden
                        />
                      ) : null}
                    </div>
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate text-sm text-foreground">
                        {workspace.name}
                      </span>
                      <span className="truncate font-mono text-[11px] text-muted-foreground">
                        {workspace.slug} · {workspace.role.toLowerCase()}
                      </span>
                    </div>
                  </DropdownMenuItem>
                );
              })}
            </>
          ) : (
            <div className="px-2 py-1.5 text-xs text-muted-foreground">
              No tenants returned.
            </div>
          )}
          <DropdownMenuSeparator />
          <div className="px-2 py-1 text-[11px] text-muted-foreground">
            Principal{" "}
            {session?.authContext.principal ?? session?.user.email ?? "-"}
          </div>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog
        open={pendingWorkspace !== null}
        onOpenChange={handleSwitchDialogOpenChange}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Switch tenant</DialogTitle>
            <DialogDescription>
              Re-enter credentials for{" "}
              {pendingWorkspace?.name ?? "the target tenant"} before binding
              this session to that tenant.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSwitchSubmit} className="space-y-4">
            <Field label="Password" htmlFor={passwordId} required>
              <Input
                id={passwordId}
                type="password"
                autoComplete="current-password"
                value={switchPassword}
                onChange={(event) => setSwitchPassword(event.target.value)}
                required
              />
            </Field>
            <Field
              label="MFA code"
              htmlFor={totpId}
              hint="Only required if the target tenant has MFA enabled."
            >
              <Input
                id={totpId}
                inputMode="numeric"
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                value={switchTotpCode}
                onChange={(event) =>
                  setSwitchTotpCode(
                    event.target.value.replace(/\D/g, "").slice(0, 6)
                  )
                }
              />
            </Field>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleSwitchDialogOpenChange(false)}
                disabled={Boolean(switchingSlug)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={Boolean(switchingSlug)}>
                {switchingSlug ? "Switching…" : "Switch"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
