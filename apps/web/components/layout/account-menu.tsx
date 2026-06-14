"use client";

import Link from "next/link";
import { LogOut, User } from "lucide-react";
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
      <DropdownMenuContent align={align} className="w-60">
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
          </div>
        </DropdownMenuLabel>
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
