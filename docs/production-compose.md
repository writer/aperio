# Production Compose deployment

The production bundle runs the complete Aperio process set:

- Postgres for durable state;
- NATS JetStream for optional lifecycle fanout;
- a one-shot Prisma migration service;
- the Go API;
- the Next.js operator console;
- the Go ingestion worker;
- the Go SIEM dispatcher.

The bundle is in [`deploy/compose/compose.production.yml`](../deploy/compose/compose.production.yml). It uses a signed GHCR image; it does not build source code on the host.

## Install

```bash
cp .env.production.example .env.production
# Edit .env.production and replace every replace-me value.
docker login ghcr.io
docker compose --env-file .env.production -f deploy/compose/compose.production.yml pull
docker compose --env-file .env.production -f deploy/compose/compose.production.yml up -d
docker compose --env-file .env.production -f deploy/compose/compose.production.yml ps
```

The migration service must complete before the API and workers start. Check it directly when an upgrade is blocked:

```bash
docker compose --env-file .env.production -f deploy/compose/compose.production.yml logs migrate
```

Open the configured `APERIO_WEB_ORIGIN`. The API health endpoints are `/healthz` and `/readyz`. Do not expose Postgres or NATS to the public network.

## Day-two operation

```bash
docker compose --env-file .env.production -f deploy/compose/compose.production.yml ps
docker compose --env-file .env.production -f deploy/compose/compose.production.yml logs --tail=200 api web ingestion-worker siem-dispatcher
docker compose --env-file .env.production -f deploy/compose/compose.production.yml exec api node -e "fetch('http://127.0.0.1:4100/readyz').then(async (r) => { console.log(await r.text()); process.exit(r.ok ? 0 : 1); }).catch((error) => { console.error(error); process.exit(1); })"
```

Use an external reverse proxy for TLS, browser rate limits, and a stable public origin. Keep the browser origin and API origin consistent with the OAuth callback configuration.
