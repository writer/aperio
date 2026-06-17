import * as React from "react";
import { ArrowUpRight, Cpu, Radar, ShieldCheck } from "lucide-react";
import {
  CEREBRO_AUTH_INSIGHTS,
  CEREBRO_AUTH_PILLARS,
  CEREBRO_MCP_RESOURCE
} from "../../lib/cerebro-auth";
import { BrandLockup, BrandMark } from "../layout/brand-mark";

const PILLARS = [
  { icon: Radar, label: CEREBRO_AUTH_PILLARS[0] },
  { icon: ShieldCheck, label: CEREBRO_AUTH_PILLARS[1] },
  { icon: Cpu, label: CEREBRO_AUTH_PILLARS[2] }
];

export function AuthLayout({
  title,
  description,
  children,
  footer,
  showSessionMessaging = false
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  showSessionMessaging?: boolean;
}) {
  return (
    <main className="relative grid min-h-screen bg-background lg:grid-cols-[1fr_minmax(0,520px)] lg:gap-0">
      <BrandPanel showSessionMessaging={showSessionMessaging} />
      <section className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-6 py-10 lg:py-12">
        <div
          aria-hidden
          className="surface-grid pointer-events-none absolute inset-0 opacity-30 lg:hidden [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]"
        />
        <div className="relative w-full max-w-md animate-fade-in-up">
          <div className="mb-6 flex justify-center lg:hidden">
            <BrandLockup />
          </div>
          <div className="surface-grain relative overflow-hidden rounded-xl border border-border/80 bg-card/95 p-7 shadow-[0_30px_80px_-40px_rgba(0,0,0,0.55)] backdrop-blur-sm">
            <div className="mb-6">
              <p className="text-[11px] font-medium uppercase tracking-[0.2em] text-signal">
                Tenant-scoped access
              </p>
              <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-foreground">
                {title}
              </h1>
              {description ? (
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  {description}
                </p>
              ) : null}
              {showSessionMessaging ? (
                <dl className="mt-3 grid gap-1.5 text-[11px] lg:hidden">
                  {CEREBRO_AUTH_INSIGHTS.map((insight) => (
                    <div
                      key={insight.label}
                      className="flex items-center justify-between border-t border-border/70 pt-1.5 first:border-t-0 first:pt-0"
                    >
                      <dt className="text-muted-foreground">{insight.label}</dt>
                      <dd className="font-mono text-foreground">
                        {insight.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : null}
            </div>
            {children}
          </div>
          {footer ? (
            <div className="mt-5 text-center text-sm text-muted-foreground">
              {footer}
            </div>
          ) : null}
        </div>
      </section>
    </main>
  );
}

function BrandPanel({
  showSessionMessaging
}: {
  showSessionMessaging: boolean;
}) {
  return (
    <aside
      aria-hidden
      className="relative hidden overflow-hidden border-r border-border/80 bg-card text-foreground lg:flex lg:flex-col lg:justify-between lg:p-10"
    >
      <div className="surface-grid absolute inset-0 opacity-40 [mask-image:linear-gradient(to_bottom,black_30%,transparent_95%)]" />
      <div className="surface-grain absolute inset-0" />
      <div className="pointer-events-none absolute -left-32 top-1/2 h-[520px] w-[520px] -translate-y-1/2 rounded-full bg-signal/20 blur-3xl" />
      <div className="pointer-events-none absolute -right-24 -top-24 h-[360px] w-[360px] rounded-full bg-critical/15 blur-3xl" />

      <div className="relative flex items-center gap-2">
        <BrandLockup />
      </div>

      <div className="relative max-w-md space-y-7">
        <span className="inline-flex items-center gap-2 rounded-full border border-signal/40 bg-signal/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.2em] text-signal">
          <span
            className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal"
          />
          Cerebro auth model
        </span>
        <h2 className="text-balance text-3xl font-semibold leading-[1.15] tracking-tight text-foreground sm:text-4xl">
          A tenant-bound console on your{" "}
          <span className="text-signal">SaaS attack surface.</span>
        </h2>
        {showSessionMessaging ? (
          <>
            <p className="max-w-sm text-sm leading-relaxed text-muted-foreground">
              Aperio signs users into a human workspace session, then carries
              Cerebro resource, tenant, principal, group, and scope context
              through the app.
            </p>

            <ul className="grid grid-cols-1 gap-2.5">
              {PILLARS.map(({ icon: Icon, label }) => (
                <li
                  key={label}
                  className="flex items-center gap-2.5 rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm text-muted-foreground backdrop-blur-sm"
                >
                  <Icon className="h-4 w-4 text-signal" aria-hidden />
                  <span className="text-foreground/90">{label}</span>
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </div>

      {showSessionMessaging ? (
        <div className="relative">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-[11px] font-medium uppercase tracking-[0.2em] text-muted-foreground">
              Session contract
            </p>
            <ArrowUpRight
              className="h-3.5 w-3.5 text-muted-foreground"
              aria-hidden
            />
          </div>
          <dl className="grid grid-cols-1 gap-2">
            {CEREBRO_AUTH_INSIGHTS.map((insight) => (
              <div
                key={insight.label}
                className="flex items-center justify-between rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm backdrop-blur-sm"
              >
                <dt className="flex items-center gap-2 text-muted-foreground">
                  <span
                    className={
                      insight.tone === "critical"
                        ? "h-1.5 w-1.5 rounded-full bg-critical critical-pulse"
                        : insight.tone === "signal"
                          ? "h-1.5 w-1.5 rounded-full bg-signal"
                          : "h-1.5 w-1.5 rounded-full bg-muted-foreground/60"
                    }
                  />
                  {insight.label}
                </dt>
                <dd className="font-mono text-sm text-foreground tabular-nums">
                  {insight.value}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-4 max-w-sm text-xs text-muted-foreground">
            Sign-in keeps human workspace access separate from Cerebro service
            credentials and {CEREBRO_MCP_RESOURCE} capability tokens.
          </p>
        </div>
      ) : null}

      <BrandMark
        aria-hidden
        className="pointer-events-none absolute -bottom-12 -right-12 h-64 w-64 text-foreground/5"
      />
    </aside>
  );
}
