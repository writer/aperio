# Upgrade procedure

Every release is an immutable source tag and a signed container image. Set `APERIO_IMAGE_REF` to the release digest whenever possible; otherwise use the release tag and record its resolved digest.

## Before the change

1. Read the release entry in [`CHANGELOG.md`](../CHANGELOG.md).
2. Verify the image signature and record its digest.
3. Run `npm run backup:check` and take a fresh Postgres backup.
4. Confirm `/readyz` is healthy and note queue and SIEM delivery counts.

## Apply the release

```bash
export APERIO_IMAGE_REF=ghcr.io/writer/aperio@sha256:REPLACE_WITH_RELEASE_RECEIPT_DIGEST
docker compose --env-file .env.production -f deploy/compose/compose.production.yml pull
docker compose --env-file .env.production -f deploy/compose/compose.production.yml up -d
docker compose --env-file .env.production -f deploy/compose/compose.production.yml ps
```

Compose runs the migration service before starting the API and workers. If the migration exits nonzero, keep the current services running, inspect the migration log, and resolve the forward migration issue before retrying. Do not delete the Postgres volume.

## Verify the user path

```bash
docker compose --env-file .env.production -f deploy/compose/compose.production.yml exec api node -e "fetch('http://127.0.0.1:4100/healthz').then(async (r) => { console.log(await r.text()); process.exit(r.ok ? 0 : 1); }).catch((error) => { console.error(error); process.exit(1); })"
docker compose --env-file .env.production -f deploy/compose/compose.production.yml exec api node -e "fetch('http://127.0.0.1:4100/readyz').then(async (r) => { console.log(await r.text()); process.exit(r.ok ? 0 : 1); }).catch((error) => { console.error(error); process.exit(1); })"
docker compose --env-file .env.production -f deploy/compose/compose.production.yml logs --tail=200 api web ingestion-worker siem-dispatcher
```

Sign in through the configured web origin, open the findings list, inspect one incident timeline, and confirm a known SIEM destination reports delivery activity. Record the release tag, digest, migration result, health response, and operator-path result.

## Failure handling

Keep the database and volumes intact. Capture the migration and service logs, the exact image digest, and `/readyz` output. Continue forward with a fixed image or migration after the cause is understood; do not remove data to force startup.
