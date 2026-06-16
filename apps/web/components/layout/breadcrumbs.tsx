"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";
import { cn } from "../../lib/utils";

type CrumbSpec = {
  label: string;
  href?: string;
};

const SEGMENT_LABELS: Record<string, string> = {
  apps: "Apps",
  connectors: "Connectors",
  findings: "Findings",
  incidents: "Incidents",
  security: "Security",
  "shadow-it": "Shadow IT",
  "oauth-apps": "OAuth Apps",
  "siem-connectors": "SIEM",
  settings: "Settings",
  organization: "Organization",
  "privileged-identities": "Privileged identities",
  admin: "Admin"
};

function labelFor(segment: string): string {
  if (SEGMENT_LABELS[segment]) return SEGMENT_LABELS[segment];
  if (segment.length > 16) return `${segment.slice(0, 8)}…${segment.slice(-4)}`;
  return segment;
}

export function Breadcrumbs({
  overrides = {},
  className
}: {
  overrides?: Record<string, CrumbSpec>;
  className?: string;
}) {
  const pathname = usePathname();
  const segments = pathname.split("/").filter(Boolean);

  if (segments.length === 0) return null;

  const crumbs: CrumbSpec[] = segments.map((segment, index) => {
    const href = "/" + segments.slice(0, index + 1).join("/");
    const override = overrides[segment] ?? overrides[href];
    return {
      label: override?.label ?? labelFor(segment),
      href: index === segments.length - 1 ? undefined : (override?.href ?? href)
    };
  });

  return (
    <nav
      aria-label="Breadcrumb"
      className={cn(
        "flex items-center gap-1 text-xs text-muted-foreground",
        className
      )}
    >
      <ol className="flex flex-wrap items-center gap-1">
        <li>
          <Link
            href="/"
            className="inline-flex items-center gap-1 rounded-sm px-1 py-0.5 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Dashboard"
          >
            <Home className="h-3.5 w-3.5" aria-hidden />
          </Link>
        </li>
        {crumbs.map((crumb, idx) => (
          <li key={`${crumb.label}-${idx}`} className="flex items-center gap-1">
            <ChevronRight
              className="h-3 w-3 text-muted-foreground/60"
              aria-hidden
            />
            {crumb.href ? (
              <Link
                href={crumb.href}
                className="rounded-sm px-1 py-0.5 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {crumb.label}
              </Link>
            ) : (
              <span className="px-1 py-0.5 font-medium text-foreground">
                {crumb.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
