"use client";

import { AccountMenu } from "./account-menu";
import { ThemeToggle } from "./theme-toggle";
import { WorkspaceSwitcher } from "./workspace-switcher";

// TopBar sits at the top of the main content area on desktop and pins the
// workspace switcher and account silhouette to the upper-right corner.
// Mobile renders the same controls inline in the hamburger header (see
// `top-nav.tsx`) so this component is desktop-only.
export function TopBar() {
  return (
    <header className="sticky top-0 z-30 hidden h-14 items-center justify-end gap-2 border-b border-border/80 bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/65 md:flex">
      <WorkspaceSwitcher />
      <ThemeToggle />
      <AccountMenu align="end" />
    </header>
  );
}
