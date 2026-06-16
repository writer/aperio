# Aperio

**SaaS Detection & Response on top of Cerebro.**

Aperio is an open-source SaaS Detection & Response platform. It connects to your SaaS estate, fires Cerebro-grounded SaaS detections, opens human-owned incidents with a replayable timeline, runs human-gated response actions with separation of duties, and forwards every lifecycle event to the SIEM you already operate. The current `main` branch ships a Go/ConnectRPC API backed by Prisma/Postgres data, a Next.js operator console, an stdio MCP broker, an ingestion worker, an optional NATS JetStream event bus, and a durable SIEM dispatcher with adapters for Splunk HEC, Panther, Panopticon, Elasticsearch, Datadog Logs, generic webhooks, and JSON Lines files.

In practical terms, Aperio ingests connector events, evaluates SaaS detection rules, opens and dedupes incidents enriched with Cerebro graph and claim context, gates response actions behind two-person approval, and fans canonical `aperio.finding.v1` envelopes out to your SIEM destinations.

![Node](https://img.shields.io/badge/Node-20%2B-green?style=flat&logo=node.js) ![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat&logo=next.js) ![Prisma](https://img.shields.io/badge/Prisma-5-2D3748?style=flat&logo=prisma) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

---

## Current capabilities

- **Connector catalog** — built-in support for GitHub, Slack, Google Workspace, Okta, 1Password, Microsoft 365, and Atlassian (Jira & Confluence), with encrypted credential storage (AES-256-GCM) and per-check toggles.
- **SaaS detections** — public-repo detection (GitHub), MFA-disabled detection (Slack), and a deep Google Workspace pack covering external sharing, admin posture (super-admin 2SV, recovery emails), Gmail auto-forwarding / delegates / send-as, and the domain-wide-delegation allow-list.
- **Shadow IT** — per-user `users.tokens.list` scan that catalogs every third-party OAuth app users have authorized, with graduated risk scoring (CRITICAL/HIGH/MEDIUM/LOW) calibrated against Google scope sensitivity.
- **Findings lifecycle** — auto-resolution on next sync when the underlying signal disappears, evidence persistence, severity scoring, dedupe by stable key, and risk exceptions with compensating controls.
- **SIEM fanout** — durable outbox with adapters for Splunk HEC, Panther, Panopticon, Elasticsearch, Datadog Logs, generic webhooks, and JSON Lines file sinks. Canonical envelope `aperio.finding.v1`.
- **Event contracts** — protobuf-backed Aperio lifecycle envelopes wrapped in Cerebro-compatible `EventEnvelope` messages, with optional NATS JetStream publishing for ingestion, finding lifecycle, and claim fanout events.
- **Remediation** — real handlers for Okta (suspend, reset MFA) and Slack (revoke OAuth app); the rest are stubbed and pluggable.
- **Operator console** — Next.js app with dashboard, findings, apps, shadow IT, security graph, connectors, SIEM destinations, and admin pages. Full-text command palette, role-aware navigation, MFA enrollment.
- **Agents and MCP** — tenant-scoped agent runtime that creates `AgentProposal` rows requiring human approval before any provider-side write executes. An stdio MCP broker mirrors core task and SIEM actions over JSON-RPC for MCP-native clients.
- **Multi-tenant by default** — every entity is scoped to an `Organization`. Tenant isolation is enforced at the route, repository, and integration layer, with cross-tenant test coverage in `internal/bootstrap/tenant_isolation_test.go`.

---

## Architecture

```
            Operator console (Next.js)        MCP clients (stdio)
                       |                              |
                       v                              v
              Go/ConnectRPC API                 MCP broker
             (cmd/aperio, internal)     (cmd/mcp-broker, internal/mcpbroker)
                       |
        +-----------------------------+
        |              |              |
        v              v              v
   Connectors    Detection      SIEM dispatcher
  (GitHub,      rules +         (outbox worker)
   Slack,       findings              |
   Google,      lifecycle             v
   Okta,         |              Splunk / Panther /
   1Pass,        v              Panopticon / Elastic /
   M365,    Postgres           Datadog / Webhook / JSONL
   Atlassian)  (state)
                  |
                  v
          Optional NATS JetStream
       (Cerebro-compatible events)
```

The Go API is the single source of truth for connector, finding, admin, auth, and SIEM workflows. The ingestion worker pulls audit-log events into the same Postgres state store. The SIEM dispatcher reads the `SiemDelivery` outbox and ships each finding to every enabled destination with retry/backoff. When `APERIO_EVENT_BUS=nats`, Go and worker processes also publish validated protobuf lifecycle events to JetStream; otherwise publishing is a safe no-op. Credentials are encrypted at rest with AES-256-GCM via `packages/security`.

---

## Quick start

### Prerequisites

- Node.js 20+ (the repo targets the active LTS line).
- Go 1.25+ (for the ConnectRPC API in `cmd/aperio`).
- Docker (for local Postgres and NATS via `docker-compose.yml`) or any reachable Postgres 15+.
- npm 10+ (ships with Node 20).
- GNU Make (preinstalled on macOS and most Linux distros) to use the `make` targets below.

### First run

The fastest path uses the Makefile; run `make help` to see every target.

```bash
git clone https://github.com/writer/Aperio.git
cd Aperio
make setup                          # .env, deps, Postgres, migrations, and seed data
make dev                            # Go API on :4100 + Next.js console on :3000
```

`DATABASE_URL` in `.env` is the single source of truth for the local Postgres port: `make` publishes the docker-compose database on the port embedded there and hands the Go server a pgx-compatible DSN automatically (Prisma's `?schema=public` is stripped and `sslmode=disable` is added for local connections).

Prefer to run each step yourself? The manual flow is equivalent:

```bash
git clone https://github.com/writer/Aperio.git
cd Aperio

docker compose up -d                # local Postgres on :5432
npm install
cp .env.example .env                # fill in local secrets before sharing
npm run db:generate
npx prisma migrate dev --schema packages/db/prisma/schema.prisma

# create your local .env (see Configuration below for the full reference)
cat > .env <<EOF
DATABASE_URL="postgresql://aperio:aperio@localhost:5432/aperio?schema=public"
APERIO_ENCRYPTION_KEY="base64:$(openssl rand -base64 32)"
APERIO_AUTH_SECRET="$(openssl rand -hex 32)"
APERIO_WEB_ORIGIN="http://localhost:3000"
NEXT_PUBLIC_CONNECT_API_BASE_URL="http://localhost:4100"
EOF

# start the API and the web console in two shells
npm run dev:connect                 # http://localhost:4100
npm run dev:web                     # http://localhost:3000
```

The first time you sign in, run the seed script to provision a demo organization, owner user, and example findings:

```bash
npx tsx scripts/seed.ts
```

### Background workers

Long-running pipelines run as separate processes. The event bus is optional; set `APERIO_EVENT_BUS=nats` to publish protobuf envelopes to the local NATS service started by `npm run dev`.

The default worker and MCP commands are Go-owned. Worker commands load local `.env` settings and derive a pgx-safe Postgres DSN with `scripts/dev-config.mjs go-database-url`, so Prisma-only query parameters are not passed to Go database clients.

```bash
npm run worker:ingestion -- -once -limit 1  # Go ingestion worker
npm run worker:siem -- -once -limit 1       # Go SIEM dispatcher
npm run mcp:broker                         # Go stdio MCP broker for agent clients
```

Remaining TypeScript is limited to the Next.js frontend, generated clients/contracts, tests, Prisma, and local tooling.

---

## Choose your path

| Goal | Start here | Notes |
| --- | --- | --- |
| Run the API only | `npm run dev:connect` | Go/ConnectRPC server on `:4100`; serves native RPCs, compatibility calls, and OAuth callbacks. |
| Run the operator console | `npm run dev:web` | Next.js dev server on `:3000`; expects the API at `NEXT_PUBLIC_CONNECT_API_BASE_URL`. |
| Seed demo data | `npx tsx scripts/seed.ts` | Idempotent; creates Aperio Demo Security org + owner/admin/analyst users. |
| Connect Google Workspace | `/connectors` → Google Workspace | Uses OAuth; needs `GOOGLE_WORKSPACE_*` env vars. |
| Connect other providers | `/connectors` → pick provider | GitHub, Slack, Okta, 1Password, M365, Atlassian use scoped tokens or service accounts. |
| Wire up a SIEM | `/connectors` → SIEM destinations | Splunk HEC, Panther, Panopticon, Elasticsearch, Datadog Logs, generic webhook, JSONL sink. |
| Audit shadow IT | `/shadow-it` | Lists every third-party OAuth app users have granted, with per-user drilldown. |
| Author detection rules | `internal/ingestionworker` | Go rules produce findings and SIEM deliveries from queued ingestion events. |
| Inspect the schema | `packages/db/prisma/schema.prisma` | Single Prisma schema for all entities. |
| Run all checks | `npm run verify` | Aggregate gate for generation, typecheck, guardrails, tests, build, smokes, production audit, and leak check. |

---

## Configuration

Aperio reads runtime configuration from environment variables. Create a `.env` file at the repository root (it is gitignored).

### Core variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | Postgres connection string consumed by Prisma | required |
| `APERIO_ENCRYPTION_KEY` | base64-encoded 32-byte key used for AES-256-GCM credential encryption | required |
| `APERIO_AUTH_SECRET` | HMAC secret for session cookies and email tokens | required |
| `APERIO_WEB_ORIGIN` | canonical origin for the Next.js console; used for CORS and OAuth redirects | `http://localhost:3000` |
| `NEXT_PUBLIC_CONNECT_API_BASE_URL` | base URL the web app uses to call the Go/ConnectRPC API | `http://localhost:4100` |
| `APERIO_SESSION_TTL_HOURS` | absolute session lifetime | `12` |
| `APERIO_SESSION_IDLE_MINUTES` | idle session timeout | `120` |
| `APERIO_MFA_ISSUER` | TOTP issuer label shown in authenticator apps | `Aperio` |
| `APERIO_EVENT_BUS` | optional event publisher backend; set to `nats` to enable JetStream fanout | unset / noop |
| `APERIO_NATS_URL` | NATS server URL used when event bus publishing is enabled | `nats://127.0.0.1:4222` |
| `APERIO_NATS_STREAM` | JetStream stream for Cerebro-compatible event envelopes | `CEREBRO_EVENTS` |

### Cerebro integration

When `CEREBRO_BASE_URL`, a credential, and `CEREBRO_TENANT_ID` are configured,
the Go service ensures Aperio's Cerebro source runtime at startup. Leave these
unset for local-only development without Cerebro.

| Variable | Purpose | Default |
| --- | --- | --- |
| `CEREBRO_BASE_URL` | Hosted Cerebro API origin, for example `https://cerebro.example.com` | unset |
| `CEREBRO_API_KEY` | Tenant-scoped Cerebro API key sent as `Authorization: Bearer` | unset |
| `CEREBRO_TOKEN` | Backward-compatible fallback when `CEREBRO_API_KEY` is not set | unset |
| `CEREBRO_TENANT_ID` | Tenant id sent as `X-Cerebro-Tenant` and stored on the source runtime | unset |
| `CEREBRO_SOURCE_RUNTIME_ID` | Source runtime id Aperio ensures in Cerebro | `writer-aperio-saas-dr` |
| `CEREBRO_SOURCE_ID` | Cerebro source id for the Aperio SaaS DR runtime | `aperio_saas_dr` |
| `CEREBRO_HTTP_TIMEOUT_SECONDS` | Timeout for startup runtime ensure and Cerebro HTTP calls | `15` |

### Email

| Variable | Purpose | Default |
| --- | --- | --- |
| `APERIO_EMAIL_PROVIDER` | currently supports `resend` | unset (transactional email disabled) |
| `APERIO_RESEND_API_KEY` | Resend API key | unset |
| `APERIO_EMAIL_FROM` | RFC 5322 `From:` header | unset |

### Google Workspace OAuth

| Variable | Purpose |
| --- | --- |
| `GOOGLE_WORKSPACE_CLIENT_ID` | Google OAuth client ID (`...apps.googleusercontent.com`) |
| `GOOGLE_WORKSPACE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_WORKSPACE_REDIRECT_URI` | OAuth callback (defaults to `${API}/api/v1/integrations/google-workspace/oauth/callback`) |
| `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_CLIENT_EMAIL` | optional; used for DWD-impersonated Gmail forwarding scans |
| `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY` | PEM private key for the same service account |

### Backups (optional)

| Variable | Purpose | Default |
| --- | --- | --- |
| `APERIO_BACKUP_STORAGE_URL` | destination URL (e.g. `s3://bucket/path`) | unset |
| `APERIO_BACKUP_SCHEDULE` | cron expression | `0 */6 * * *` |
| `APERIO_BACKUP_RETENTION_DAYS` | retention horizon | `30` |

### Generating secrets

```bash
# 32-byte AES key, base64-encoded
echo -n "base64:$(openssl rand -base64 32)"

# 64-char hex auth secret
openssl rand -hex 32
```

---

## Built-in connectors

| Provider | Auth model | What it detects today |
| --- | --- | --- |
| GitHub | PAT or GitHub App | Public repositories in the org |
| Slack | User OAuth token (`xoxp-`) | Workspace 2FA enforcement disabled |
| Google Workspace | OAuth + optional service account | External sharing, super-admin 2SV, recovery emails, Gmail auto-forwarding / delegates / send-as, domain-wide delegations, shadow-IT OAuth grants |
| Okta | OIDC API Services (private-key JWT) | Connection only; rule pack pending |
| 1Password | SCIM bridge bearer token | Connection only; rule pack pending |
| Microsoft 365 | Graph API delegated/app token | Connection only; rule pack pending |
| Atlassian (Jira & Confluence) | OAuth + audit-log read | Connection only; rule pack pending |

---

## SIEM destinations

The SIEM dispatcher writes a canonical `aperio.finding.v1` envelope and adapts it to each destination:

| Destination | Transport | Authentication |
| --- | --- | --- |
| Splunk HEC | HTTPS POST | HEC token |
| Panther | HTTPS POST | API token |
| Panopticon | HTTPS POST | API key |
| Elasticsearch | HTTPS POST `_bulk` | basic / API key |
| Datadog Logs | HTTPS POST | DD API key |
| Generic Webhook | HTTPS POST | HMAC signature header |
| JSON Lines File | local filesystem write | none |

Each delivery row is durable, retried with exponential backoff, and de-duplicated by finding ID + destination ID.

---

## Scripts

Every workflow below is also wrapped by the Makefile — run `make help` for the full list (`make dev`, `make verify`, `make test`, `make migrate`, and more). The underlying npm scripts remain available:

```bash
npm run dev:connect            # Go ConnectRPC API on :4100
npm run dev:web                # Next.js console on :3000
npm run worker:ingestion       # Go ingestion worker
npm run worker:siem            # Go SIEM dispatcher worker
npm run mcp:broker             # Go stdio MCP broker
npm run build:web              # production Next.js build
npm run proto:lint             # Buf lint for protobuf contracts
npm run proto:check            # lint, regenerate, and verify generated code is current
npm run test:go                # Go unit tests for ConnectRPC service
npm run typecheck              # tsc --noEmit
npm run test:api               # node --test (tsx loader)
npm run verify                 # aggregate final gate: generate, typecheck, guardrails, tests, build, smokes, audit, leak check
npm run db:generate            # prisma generate
npm run db:validate            # prisma validate
npm run backup:check           # backup-readiness preflight
npm run audit:prod             # npm audit --omit=dev
```

Use the full preflight before opening a PR:

```bash
npm run verify
```

Production deployments should pair Aperio's process-local route limits with edge or load-balancer rate limiting. Ingestion and SIEM delivery both use database-backed queues so accepted events and outbound deliveries survive API restarts.

---

## Go / ConnectRPC backend

Aperio's API runtime is Go/ConnectRPC. Native RPCs serve first-class read paths, and the `CallApi` compatibility RPC preserves the existing `/api/v1/*` web contract while remaining REST-shaped workflows are promoted into typed RPCs.

| Surface | Purpose |
| --- | --- |
| `cmd/aperio/main.go` | Go process entrypoint, listening on `APERIO_CONNECT_ADDR` (`:4100` locally) |
| `internal/bootstrap` | ConnectRPC handler wiring, CORS, cookie-session auth, compatibility dispatch, dashboard metrics query |
| `proto/aperio/v1/api.proto` | Stable service contract for `AperioService` |
| `gen/aperio/v1` | Generated Go protobuf and ConnectRPC handlers |
| `packages/connect/src` | Generated TypeScript contracts plus browser Connect client |

The web app talks to the Go API through `NEXT_PUBLIC_CONNECT_API_BASE_URL`, for example:

```bash
DATABASE_URL=postgresql://aperio:aperio@localhost:5432/aperio npm run dev:connect
NEXT_PUBLIC_CONNECT_API_BASE_URL=http://localhost:4100 npm run dev:web
```

Authentication uses the `aperio_session` HttpOnly cookie and the `user_sessions` table. The Go service validates the cookie token hash directly in Postgres and only reflects the configured `APERIO_WEB_ORIGIN` for credentialed browser calls.

Protobuf contracts follow Cerebro-style Buf conventions:

```bash
npm run proto:lint
npm run proto:check
npm run test:go
```

Event contracts live in `proto/aperio/contracts/v1/events.proto` and are encoded from `packages/shared/src/protobuf-contracts.ts` and `internal/bootstrap/event_bus.go`. Producers validate required envelope attributes before publishing so consumers can filter by schema, kind, tenant, finding, delivery, or job id without decoding every payload.

---

## HTTP API surface

Native Go-backed RPCs live under ConnectRPC procedure paths such as `/aperio.v1.AperioService/GetDashboardMetrics`. The web console still uses REST-shaped `/api/v1/*` compatibility paths through the `CallApi` RPC while those workflows move to typed RPCs. Key compatibility groups:

| Prefix | Purpose |
| --- | --- |
| `/auth/*` | Session login, signup, password reset, MFA enrollment |
| `/admin/*` | Organization settings, users, roles, audit log |
| `/integrations/*` | Connector lifecycle, OAuth start/callback, force-sync, per-check toggles |
| `/findings/*` | List, filter, view, resolve, suppress, export |
| `/remediations/*` | Propose, approve, execute provider-side fixes |
| `/dashboard/*` | Aggregated metrics, trend lines, top assets |
| `/security/*` | Security graph and posture overview |
| `/shadow-it/*` | OAuth apps inventory and per-app user drilldown |
| `/siem/*` | SIEM destinations CRUD and delivery introspection |
| `/agents/*` | Agent tasks, messages, and proposals (human-approval gated) |

The Go MCP broker (`cmd/mcp-broker` and `internal/mcpbroker`) exposes a JSON-RPC superset of the task and SIEM surfaces for agent clients.

---

## Repository layout

```
aperio/
├── apps/
│   └── web/                # Next.js operator console
├── cmd/aperio/             # Go ConnectRPC server entrypoint
├── cmd/ingestion-worker/   # Go ingestion worker entrypoint
├── cmd/mcp-broker/         # Go stdio MCP broker entrypoint
├── cmd/siem-dispatcher/    # Go SIEM dispatcher entrypoint
├── gen/                    # Generated Go protobuf/ConnectRPC code
├── internal/               # Go service config and bootstrap packages
├── packages/
│   ├── connect/            # TypeScript ConnectRPC client and generated contracts
│   ├── db/                 # Prisma schema and client
│   ├── security/           # AES-256-GCM helpers and password hashing
│   └── shared/             # Zod schemas, connector catalog, SIEM catalog
├── proto/                  # ConnectRPC API + Cerebro-compatible event contracts
├── workers/                # TypeScript validation helpers only
├── scripts/                # dev orchestration, seed, and operational scripts
├── tests/                  # node --test suites
├── droid-wiki/             # generated architecture and reference docs
└── docker-compose.yml      # local Postgres
```

---

## Documentation

The `droid-wiki/` directory contains generated documentation. Useful entry points:

| Document | Notes |
| --- | --- |
| [Overview](droid-wiki/overview/index.md) | High-level introduction and repo map |
| [Architecture](droid-wiki/overview/architecture.md) | Layered architecture description |
| [Getting started](droid-wiki/overview/getting-started.md) | Local setup walkthrough |
| [Glossary](droid-wiki/overview/glossary.md) | Domain terms used across the codebase |
| [Apps](droid-wiki/apps/index.md) | API, web, MCP entry points |
| [Features](droid-wiki/features/index.md) | Connectors, findings, SIEM, admin, agents |
| [Packages](droid-wiki/packages/index.md) | `db`, `shared`, `security` package guides |
| [API](droid-wiki/api/index.md) | Route reference |
| [Security](droid-wiki/security.md) | Threat model and security controls |
| [Reference](droid-wiki/reference/index.md) | Configuration, data models, dependencies |
| [How to contribute](droid-wiki/how-to-contribute/index.md) | Workflow, testing, debugging, conventions |

---

## Stack

| Component | Technology |
| --- | --- |
| Language | TypeScript 5.7, Go 1.25 |
| Runtime | Node.js 20+, Go `net/http` |
| API server | Go `net/http` + ConnectRPC |
| Web console | Next.js 16 + React 18 + Tailwind |
| ORM | Prisma 5 |
| Database | PostgreSQL 15+ |
| Background workers | Go ingestion worker + Go SIEM dispatcher with database-backed queues/outbox |
| Contracts | Protobuf + Buf + generated Go/TypeScript clients + Cerebro event envelopes |
| Event bus | Optional NATS JetStream (`APERIO_EVENT_BUS=nats`) |
| Validation | Zod |
| MCP transport | stdio JSON-RPC |
| Auth | Cookie sessions, TOTP MFA, RBAC |
| Crypto | AES-256-GCM (`packages/security`) |
| Connector catalog | GitHub, Slack, Google Workspace, Okta, 1Password, Microsoft 365, Atlassian |
| SIEM adapters | Splunk HEC, Panther, Panopticon, Elasticsearch, Datadog Logs, generic webhook, JSONL |
| Testing | `node --test` via `tsx`, plus `prisma validate` and `tsc --noEmit` |

---

## License

MIT — see [LICENSE](LICENSE).
