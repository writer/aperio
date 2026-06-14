"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Search } from "lucide-react";
import { Button } from "../ui/button";
import { cn } from "../../lib/utils";
import { BrandLockup } from "./brand-mark";
import { MobileNav } from "./mobile-nav";
import { useCommandPalette } from "./command-palette";
import { WorkspaceSwitcher } from "./workspace-switcher";
import { AccountMenu } from "./account-menu";

type NavLeaf = { href: string; label: string };
type NavFolder = { label: string; children: NavNode[] };
type NavNode = NavLeaf | NavFolder;

const isFolder = (node: NavNode): node is NavFolder =>
  (node as NavFolder).children !== undefined;

export const NAV_TREE: NavNode[] = [
  {
    label: "Dashboard",
    children: [
      { href: "/", label: "Overview" },
      { href: "/compliance", label: "Compliance" }
    ]
  },
  {
    label: "Issues",
    children: [
      { href: "/findings", label: "Findings" },
      { href: "/shadow-it", label: "Shadow IT" },
      { href: "/security", label: "Security Graph" }
    ]
  },
  {
    label: "Reports",
    children: [
      { href: "/admin/reports", label: "Executive Report" },
      { href: "/admin/system-logs", label: "System Logs" }
    ]
  },
  {
    label: "Settings",
    children: [
      { href: "/connectors", label: "Connectors" },
      { href: "/siem-connectors", label: "SIEM" },
      { href: "/settings/organization", label: "Org Settings" }
    ]
  }
];

function flattenLeaves(nodes: NavNode[]): NavLeaf[] {
  const out: NavLeaf[] = [];
  for (const node of nodes) {
    if (isFolder(node)) {
      out.push(...flattenLeaves(node.children));
    } else {
      out.push(node);
    }
  }
  return out;
}

export const NAV_LINKS: NavLeaf[] = flattenLeaves(NAV_TREE);

function isPathActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

function folderContainsActive(folder: NavFolder, pathname: string): boolean {
  return folder.children.some((child) =>
    isFolder(child)
      ? folderContainsActive(child, pathname)
      : isPathActive(pathname, child.href)
  );
}

function NavTreeView({
  nodes,
  pathname,
  depth = 0
}: {
  nodes: NavNode[];
  pathname: string;
  depth?: number;
}) {
  return (
    <ul className="flex flex-col gap-0.5">
      {nodes.map((node) =>
        isFolder(node) ? (
          <NavFolderItem
            key={node.label}
            folder={node}
            pathname={pathname}
            depth={depth}
          />
        ) : (
          <li key={node.href}>
            <NavLeafLink leaf={node} pathname={pathname} depth={depth} />
          </li>
        )
      )}
    </ul>
  );
}

function NavFolderItem({
  folder,
  pathname,
  depth
}: {
  folder: NavFolder;
  pathname: string;
  depth: number;
}) {
  const containsActive = folderContainsActive(folder, pathname);
  const [open, setOpen] = React.useState<boolean>(true);

  // Auto-open whenever the active route lives inside the folder so that
  // navigating into a deep page does not leave its branch collapsed.
  React.useEffect(() => {
    if (containsActive) setOpen(true);
  }, [containsActive]);

  const isTopLevel = depth === 0;

  return (
    <li>
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        className={cn(
          "flex w-full items-center gap-2 rounded-md px-3 text-left transition-colors",
          isTopLevel
            ? "py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground"
            : "py-1.5 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
        )}
        style={{ paddingLeft: `${0.75 + depth * 0.75}rem` }}
      >
        <ChevronRight
          aria-hidden
          className={cn(
            "h-3 w-3 shrink-0 transition-transform",
            open ? "rotate-90" : "rotate-0"
          )}
        />
        <span className="flex-1 truncate">{folder.label}</span>
      </button>
      {open ? (
        <div className="mt-0.5">
          <NavTreeView
            nodes={folder.children}
            pathname={pathname}
            depth={depth + 1}
          />
        </div>
      ) : null}
    </li>
  );
}

function NavLeafLink({
  leaf,
  pathname,
  depth
}: {
  leaf: NavLeaf;
  pathname: string;
  depth: number;
}) {
  const active = isPathActive(pathname, leaf.href);
  return (
    <Link
      href={leaf.href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "relative flex items-center rounded-md py-1.5 pr-3 text-sm font-medium transition-colors",
        active
          ? "bg-muted text-foreground"
          : "text-muted-foreground hover:bg-muted hover:text-foreground"
      )}
      style={{ paddingLeft: `${0.75 + depth * 0.75 + 0.75}rem` }}
    >
      {leaf.label}
      {active ? (
        <span
          aria-hidden
          className="absolute inset-y-1.5 left-0 w-[2px] rounded-full bg-signal"
        />
      ) : null}
    </Link>
  );
}

export function TopNav() {
  const pathname = usePathname();
  const palette = useCommandPalette();

  return (
    <>
      <aside
        aria-label="Primary"
        className="sticky top-0 z-40 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 md:flex"
      >
        <div className="flex h-14 items-center border-b border-border/80 px-4">
          <Link
            href="/"
            aria-label="Aperio home"
            className="rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <BrandLockup size="sm" />
          </Link>
        </div>
        <nav
          aria-label="Primary navigation"
          className="flex flex-1 flex-col gap-1 overflow-y-auto p-3"
        >
          <NavTreeView nodes={NAV_TREE} pathname={pathname} />
        </nav>
        <div className="flex flex-col gap-2 border-t border-border/80 p-3">
          <button
            type="button"
            onClick={() => palette.setOpen(true)}
            aria-label="Open command palette"
            className="flex h-8 items-center gap-2 rounded-md border border-border/80 bg-card/60 px-2.5 text-xs text-muted-foreground transition-colors hover:border-border hover:text-foreground"
          >
            <Search className="h-3.5 w-3.5" aria-hidden />
            <span className="flex-1 text-left">Quick jump…</span>
            <kbd className="inline-flex h-5 items-center gap-0.5 rounded border border-border/80 bg-background px-1.5 font-mono text-[10px] text-muted-foreground">
              <span className="text-sm leading-none">⌘</span>K
            </kbd>
          </button>
        </div>
      </aside>

      <header className="sticky top-0 z-40 flex h-14 items-center gap-2 border-b border-border/80 bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/65 md:hidden">
        <MobileNav links={NAV_LINKS} />
        <Link
          href="/"
          aria-label="Aperio home"
          className="rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          <BrandLockup size="sm" />
        </Link>
        <div className="ml-auto flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Search"
            className="h-8 w-8"
            onClick={() => palette.setOpen(true)}
          >
            <Search className="h-4 w-4" aria-hidden />
          </Button>
          <WorkspaceSwitcher />
          <AccountMenu align="end" />
        </div>
      </header>
    </>
  );
}
