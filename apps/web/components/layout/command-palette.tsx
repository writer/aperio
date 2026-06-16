"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import {
  Activity,
  Boxes,
  Building2,
  Cable,
  LayoutDashboard,
  Plug,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  UserCog
} from "lucide-react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { cn } from "../../lib/utils";
import { fetchFindings, fetchIntegrations } from "../../lib/api";
import type { Finding, IntegrationConnection } from "../../lib/api";
import { providerLabel } from "../../lib/format";

type CommandContextValue = {
  open: boolean;
  setOpen: (next: boolean) => void;
  toggle: () => void;
};

const CommandContext = React.createContext<CommandContextValue | null>(null);

type StaticItem = {
  id: string;
  label: string;
  hint?: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  group: "Navigate" | "Security" | "Settings";
};

const STATIC_ITEMS: StaticItem[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
    group: "Navigate"
  },
  {
    id: "incidents",
    label: "SaaS incidents",
    href: "/incidents",
    icon: ShieldAlert,
    group: "Security"
  },
  {
    id: "findings-list",
    label: "All findings",
    href: "/findings",
    icon: ShieldAlert,
    group: "Navigate"
  },
  {
    id: "apps",
    label: "Connected apps",
    href: "/apps",
    icon: Boxes,
    group: "Navigate"
  },
  {
    id: "connectors",
    label: "Connectors",
    href: "/connectors",
    icon: Plug,
    group: "Navigate"
  },
  {
    id: "siem",
    label: "SIEM connectors",
    href: "/siem-connectors",
    icon: Cable,
    group: "Navigate"
  },
  {
    id: "security",
    label: "Security graph",
    href: "/security",
    icon: ShieldCheck,
    group: "Security"
  },
  {
    id: "privileged",
    label: "Privileged identities",
    href: "/security/privileged-identities",
    icon: UserCog,
    group: "Security"
  },
  {
    id: "shadow-it",
    label: "Shadow IT",
    href: "/shadow-it",
    icon: Boxes,
    group: "Security"
  },
  {
    id: "settings-personal",
    label: "Personal settings",
    href: "/settings",
    icon: Settings,
    group: "Settings"
  },
  {
    id: "settings-org",
    label: "Organization settings",
    href: "/settings/organization",
    icon: Building2,
    group: "Settings"
  }
];

export function CommandPaletteProvider({
  children
}: {
  children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(false);
  const toggle = React.useCallback(() => setOpen((prev) => !prev), []);

  React.useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const isK = event.key === "k" || event.key === "K";
      if (isK && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        toggle();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);

  const value = React.useMemo<CommandContextValue>(
    () => ({ open, setOpen, toggle }),
    [open, toggle]
  );

  return (
    <CommandContext.Provider value={value}>
      {children}
      <CommandPalette open={open} onOpenChange={setOpen} />
    </CommandContext.Provider>
  );
}

export function useCommandPalette() {
  const ctx = React.useContext(CommandContext);
  if (!ctx) {
    return {
      open: false,
      setOpen: () => undefined,
      toggle: () => undefined
    } satisfies CommandContextValue;
  }
  return ctx;
}

function CommandPalette({
  open,
  onOpenChange
}: {
  open: boolean;
  onOpenChange: (next: boolean) => void;
}) {
  const router = useRouter();
  const [query, setQuery] = React.useState("");
  const [integrations, setIntegrations] = React.useState<
    IntegrationConnection[]
  >([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loadingDynamic, setLoadingDynamic] = React.useState(false);
  const [dynamicError, setDynamicError] = React.useState(false);
  const loadedRef = React.useRef(false);

  React.useEffect(() => {
    if (!open) {
      setQuery("");
      return;
    }
    if (loadedRef.current) return;
    loadedRef.current = true;
    setLoadingDynamic(true);
    setDynamicError(false);
    Promise.allSettled([
      fetchIntegrations(),
      fetchFindings({ status: "OPEN", limit: 12 })
    ])
      .then(([i, f]) => {
        if (i.status === "fulfilled") setIntegrations(i.value.data);
        if (f.status === "fulfilled") setFindings(f.value.data);
        if (i.status === "rejected" && f.status === "rejected") {
          setDynamicError(true);
        }
      })
      .finally(() => setLoadingDynamic(false));
  }, [open]);

  const go = React.useCallback(
    (href: string) => {
      onOpenChange(false);
      router.push(href);
    },
    [onOpenChange, router]
  );

  const grouped = React.useMemo(() => {
    const groups = new Map<string, StaticItem[]>();
    for (const item of STATIC_ITEMS) {
      const list = groups.get(item.group) ?? [];
      list.push(item);
      groups.set(item.group, list);
    }
    return groups;
  }, []);

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay
          className={cn(
            "fixed inset-0 z-50 bg-background/70 backdrop-blur-md transition-opacity duration-200",
            "data-[state=closed]:opacity-0 data-[state=open]:opacity-100"
          )}
        />
        <DialogPrimitive.Content
          className={cn(
            "fixed left-1/2 top-[18%] z-50 w-full max-w-xl -translate-x-1/2 px-4",
            "transition-all duration-200 ease-out",
            "data-[state=closed]:scale-95 data-[state=closed]:opacity-0 data-[state=open]:scale-100 data-[state=open]:opacity-100"
          )}
          aria-label="Command palette"
        >
          <DialogPrimitive.Title className="sr-only">
            Command palette
          </DialogPrimitive.Title>
          <Command
            label="Command palette"
            className="overflow-hidden rounded-xl border border-border/80 bg-popover shadow-2xl"
            shouldFilter
          >
            <div className="flex items-center gap-2 border-b border-border/60 px-4">
              <Search
                className="h-4 w-4 text-muted-foreground"
                aria-hidden
              />
              <Command.Input
                value={query}
                onValueChange={setQuery}
                placeholder="Search routes, apps, findings…"
                className="flex h-12 w-full bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
                autoFocus
              />
              <kbd className="hidden h-5 items-center rounded border border-border/80 bg-background px-1.5 font-mono text-[10px] text-muted-foreground sm:inline-flex">
                ESC
              </kbd>
            </div>
            <Command.List className="max-h-[60vh] overflow-y-auto p-2">
              <Command.Empty className="px-4 py-6 text-center text-sm text-muted-foreground">
                {dynamicError
                  ? "Unable to load dynamic results."
                  : "No matches."}
              </Command.Empty>

              {Array.from(grouped.entries()).map(([group, items]) => (
                <Command.Group
                  key={group}
                  heading={group}
                  className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground"
                >
                  {items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <CommandItem
                        key={item.id}
                        value={`${item.group} ${item.label}`}
                        onSelect={() => go(item.href)}
                      >
                        <Icon
                          className="h-4 w-4 text-muted-foreground"
                          aria-hidden
                        />
                        <span>{item.label}</span>
                      </CommandItem>
                    );
                  })}
                </Command.Group>
              ))}

              {integrations.length > 0 ? (
                <Command.Group
                  heading="Apps"
                  className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground"
                >
                  {integrations.slice(0, 8).map((integration) => (
                    <CommandItem
                      key={integration.id}
                      value={`app ${integration.displayName} ${providerLabel(
                        integration.provider
                      )}`}
                      onSelect={() => go(`/apps/${integration.id}`)}
                    >
                      <Plug
                        className="h-4 w-4 text-muted-foreground"
                        aria-hidden
                      />
                      <span className="flex-1 truncate">
                        {integration.displayName}
                      </span>
                      <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                        {providerLabel(integration.provider)}
                      </span>
                    </CommandItem>
                  ))}
                </Command.Group>
              ) : null}

              {findings.length > 0 ? (
                <Command.Group
                  heading="Open findings"
                  className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground"
                >
                  {findings.slice(0, 8).map((finding) => (
                    <CommandItem
                      key={finding.id}
                      value={`finding ${finding.title} ${finding.integration.displayName}`}
                      onSelect={() => go(`/findings/${finding.id}`)}
                    >
                      <ShieldAlert
                        className="h-4 w-4 text-muted-foreground"
                        aria-hidden
                      />
                      <span className="flex-1 truncate">{finding.title}</span>
                      <span
                        className={cn(
                          "font-mono text-[10px] uppercase tracking-wider",
                          finding.severity === "CRITICAL"
                            ? "text-critical"
                            : finding.severity === "HIGH"
                              ? "text-destructive"
                              : finding.severity === "MEDIUM"
                                ? "text-warning"
                                : "text-muted-foreground"
                        )}
                      >
                        {finding.severity}
                      </span>
                    </CommandItem>
                  ))}
                </Command.Group>
              ) : null}

              {loadingDynamic ? (
                <div className="flex items-center gap-2 px-2 py-2 text-xs text-muted-foreground">
                  <Activity className="h-3.5 w-3.5 animate-pulse" aria-hidden />
                  Loading apps and findings…
                </div>
              ) : null}
            </Command.List>
            <div className="flex items-center justify-between border-t border-border/60 px-3 py-2 text-[11px] text-muted-foreground">
              <span className="flex items-center gap-3">
                <KbdHint label="Navigate" keys={["↑", "↓"]} />
                <KbdHint label="Select" keys={["↵"]} />
              </span>
              <span className="font-mono">Aperio command bar</span>
            </div>
          </Command>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

function KbdHint({ label, keys }: { label: string; keys: string[] }) {
  return (
    <span className="flex items-center gap-1">
      {keys.map((k) => (
        <kbd
          key={k}
          className="inline-flex h-4 min-w-[16px] items-center justify-center rounded border border-border/80 bg-background px-1 font-mono text-[10px]"
        >
          {k}
        </kbd>
      ))}
      <span>{label}</span>
    </span>
  );
}

const CommandItem = React.forwardRef<
  React.ElementRef<typeof Command.Item>,
  React.ComponentPropsWithoutRef<typeof Command.Item>
>(({ className, children, ...props }, ref) => (
  <Command.Item
    ref={ref}
    className={cn(
      "flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-foreground",
      "aria-selected:bg-muted aria-selected:text-foreground",
      "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className
    )}
    {...props}
  >
    {children}
  </Command.Item>
));
CommandItem.displayName = "CommandItem";
