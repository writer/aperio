# Overview

Aperio is a multi-tenant SaaS Detection & Response prototype on top of Cerebro. It combines Go runtimes for the API, ingestion worker, SIEM dispatcher, and stdio MCP broker with a Next.js console and Prisma-backed Postgres storage.

Key runtime pieces:

- `cmd/aperio/main.go` starts the Go API on `APERIO_CONNECT_ADDR`.
- `internal/bootstrap` owns API wiring, auth/session handling, CORS, readiness, typed RPCs, and the `/api/v1/*` compatibility dispatch used by the web console.
- `apps/web` contains the Next.js operator console.
- `internal/ingestionworker` evaluates queued SaaS events and writes findings/assets.
- `internal/siemdispatcher` drains SIEM delivery rows.
- `internal/mcpbroker` exposes agent and SIEM workflows over stdio JSON-RPC.

```text
aperio/
├── cmd/aperio/       Go API entrypoint
├── internal/         Go API bootstrap plus worker/MCP packages
├── apps/web/         Next.js console
├── cmd/mcp-broker/   Go stdio MCP broker
├── cmd/ingestion-worker/ and cmd/siem-dispatcher/
│                    Go background workers
├── workers/          TypeScript validation helpers
├── packages/         Prisma, shared schemas, security, Connect client
├── proto/            protobuf contracts
└── gen/              generated Go and TypeScript contract code
```

Typical data flow:

1. A tenant connects a SaaS app through the web console and Go API compatibility endpoints.
2. Provider events are queued in Postgres for `internal/ingestionworker`.
3. The worker evaluates detections, creates findings/assets, and enqueues SIEM deliveries.
4. `internal/siemdispatcher` ships canonical envelopes to configured SIEM destinations.
5. Agent clients use `internal/mcpbroker` for task/proposal workflows against the same Prisma-backed data model.
