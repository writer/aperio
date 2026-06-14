import * as React from "react";
import { TopNav } from "./top-nav";
import { TopBar } from "./top-bar";
import { CommandPaletteProvider } from "./command-palette";
import { ShellBreadcrumbs } from "./shell-breadcrumbs";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <CommandPaletteProvider>
      <div className="flex min-h-screen flex-col md:flex-row">
        <TopNav />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 sm:py-8">
            <ShellBreadcrumbs />
            {children}
          </main>
        </div>
      </div>
    </CommandPaletteProvider>
  );
}
