"use client";

import Link from "next/link";
import { KeyRound, LogOut, User } from "lucide-react";
import { useAuth } from "../auth/auth-shell";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from "../ui/dropdown-menu";
import { cn } from "../../lib/utils";

function initialsOf(input?: string | null) {
  if (!input) return "?";
  const parts = input.trim().split(/\s+/);
  const first = parts[0]?.[0] ?? "";
  const second = parts[1]?.[0] ?? "";
  return (first + second).toUpperCase() || "?";
}

function compactScope(scope: string) {
  return scope.replace(/^cerebro\./, "").replaceAll(".", " / ");
}

type AccountMenuProps = {
  align?: "start" | "end";
  showLabel?: boolean;
};

export function AccountMenu({
  align = "end",
  showLabel = false
}: AccountMenuProps) {
  const { session, logout } = useAuth();
  const accountLabel =
    session?.user.displayName ?? session?.user.email ?? "Account";
  const authContext = session?.authContext;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size={showLabel ? "sm" : "icon"}
          aria-label="Account menu"
          className={cn(
            showLabel
              ? "w-full justify-start gap-2 px-2"
              : "h-8 w-8 rounded-full p-0"
          )}
        >
          <Avatar className={showLabel ? "h-6 w-6" : "h-7 w-7"}>
            <AvatarFallback className="text-[10px]">
              {initialsOf(
                session?.user.displayName ?? session?.user.email ?? null
              )}
            </AvatarFallback>
          </Avatar>
          {showLabel ? (
            <span className="min-w-0 flex-1 truncate text-left text-sm text-foreground">
              {accountLabel}
            </span>
          ) : null}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align={align} className="w-72">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col">
            <span className="truncate text-sm text-foreground">
              {accountLabel}
            </span>
            {session?.user.email &&
            session.user.email !== accountLabel ? (
              <span className="truncate text-xs text-muted-foreground">
                {session.user.email}
              </span>
            ) : null}
            {session?.user.role ? (
              <span className="mt-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {session.user.role}
              </span>
            ) : null}
            {authContext?.tenantSlug ? (
              <span className="mt-1 truncate font-mono text-[10px] text-muted-foreground">
                tenant:{authContext.tenantSlug}
              </span>
            ) : null}
          </div>
        </DropdownMenuLabel>
        {authContext ? (
          <>
            <DropdownMenuSeparator />
            <div className="px-2 py-2">
              <div className="mb-2 flex items-center gap-2 text-xs font-medium text-foreground">
                <KeyRound className="h-3.5 w-3.5 text-signal" aria-hidden />
                Cerebro auth context
              </div>
              <dl className="space-y-1 text-[11px] leading-relaxed">
                <div className="grid grid-cols-[68px_minmax(0,1fr)] gap-2">
                  <dt className="text-muted-foreground">Principal</dt>
                  <dd className="truncate font-mono text-foreground">
                    {authContext.principal || "unknown"}
                  </dd>
                </div>
                <div className="grid grid-cols-[68px_minmax(0,1fr)] gap-2">
                  <dt className="text-muted-foreground">Tenant</dt>
                  <dd className="truncate font-mono text-foreground">
                    {authContext.tenantId || authContext.tenantSlug || "unknown"}
                  </dd>
                </div>
                <div className="grid grid-cols-[68px_minmax(0,1fr)] gap-2">
                  <dt className="text-muted-foreground">Transport</dt>
                  <dd className="truncate font-mono text-foreground">
                    {authContext.tokenTransport}
                  </dd>
                </div>
              </dl>
              <div className="mt-2 flex flex-wrap gap-1">
                {authContext.cerebroScopes.map((scope) => (
                  <span
                    key={scope}
                    title={scope}
                    className="max-w-full truncate rounded border border-border/70 bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                  >
                    {compactScope(scope)}
                  </span>
                ))}
              </div>
            </div>
          </>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/settings">
            <User className="h-4 w-4" aria-hidden />
            Personal settings
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => logout()}>
          <LogOut className="h-4 w-4" aria-hidden />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
