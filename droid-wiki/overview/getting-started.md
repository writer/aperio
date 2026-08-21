# Getting started

## Prerequisites

- Node.js 20+ and npm 10+
- Go 1.26.6 (the version pinned in `go.mod` and CI)
- Docker or another reachable Postgres 15+

## Environment

Copy the example file and fill in secrets:

```bash
cp .env.example .env
```

Important local values:

- `DATABASE_URL`
- `APERIO_ENCRYPTION_KEY`
- `APERIO_AUTH_SECRET`
- `APERIO_WEB_ORIGIN=http://localhost:3000`
- `APERIO_CONNECT_ADDR=:4100`
- `NEXT_PUBLIC_CONNECT_API_BASE_URL=http://localhost:4100`

## First run

```bash
docker compose up -d
npm install
npm run db:generate
npx prisma migrate dev --schema packages/db/prisma/schema.prisma
npx tsx scripts/seed.ts
```

Start runtime processes in separate shells:

```bash
npm run dev:connect
npm run dev:web
npm run worker:ingestion
npm run worker:siem
npm run mcp:broker
```

The Go API listens on `http://localhost:4100`, and the web console listens on `http://localhost:3000`. The ingestion worker, SIEM dispatcher, and stdio MCP broker commands are Go-owned defaults; they load local `.env` values and derive a pgx-safe Postgres DSN from `DATABASE_URL` before starting.

## Health checks

- API health: `http://localhost:4100/healthz`
- API readiness: `http://localhost:4100/readyz`
- Web app: `http://localhost:3000`

## Validation

Use targeted checks while iterating, then run the aggregate verifier before a PR or release:

```bash
npm run verify
```

That preflight includes generated-client drift checks, TypeScript typecheck, migration guardrails, API/contract tests, Prisma validation, Go tests, DB-backed Go tests, Go/protobuf linting, web build, bounded Go worker and SIEM smokes, E2E smoke, production audit, and leak check.

Common targeted checks:

```bash
npm run guardrails:migration
npm run typecheck
npm run test:api
npm run test:go
npm run db:validate
npm run build:web
```
