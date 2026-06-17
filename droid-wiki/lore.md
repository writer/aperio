# Lore

Aperio has evolved from a tenant-scoped SSPM prototype into a SaaS Detection & Response platform on Cerebro, with Go-owned API, worker, and MCP runtimes and a Next.js console plus Prisma/Postgres state.

The original product layer (connectors, findings, dashboard metrics, admin settings, SIEM destinations, remediation) is still the substrate the SaaS D&R surface builds on. Those workflows now enter through `internal/bootstrap` and the web console in `apps/web`.

The SaaS D&R layer adds incidents (`saas_incidents`), Cerebro-grounded context, a replayable timeline, and response actions with separation of duties (propose / approve / execute) on top of that substrate.

The detection layer lives mostly in `internal/ingestionworker`, where queued SaaS events become findings, OAuth app grants, assets, and SIEM delivery rows. The SIEM layer lives in `internal/siemdispatcher` and `packages/shared/src/siem.ts`.

The latest orchestration layer is the A2A/MCP model. `packages/shared/src/a2a.ts`, `internal/mcpbroker`, the Go compatibility handlers, and the `Agent*` tables in Prisma let agents create tasks, exchange messages, and propose human-approved actions.

Aperio's backend runtime ownership is Go-first: the API, ingestion worker, SIEM dispatcher, and MCP broker run from `cmd/` and `internal/`. The remaining Node/TypeScript code is intentional: the Next.js frontend, generated contracts, tests, scripts, Prisma, and npm tooling.
