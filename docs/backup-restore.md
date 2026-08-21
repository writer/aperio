# Backup and restore

Aperio stores connector state, findings, incidents, approvals, SIEM deliveries, and encrypted credentials in Postgres. Back up Postgres; the NATS volume is a replay buffer, not the system of record.

## Configure

Set these values in the operator environment:

- `APERIO_BACKUP_STORAGE_URL` — an encrypted, access-controlled destination;
- `APERIO_BACKUP_SCHEDULE` — the scheduler expression used by your platform;
- `APERIO_BACKUP_RETENTION_DAYS` — at least 7, with a longer period for incident response needs.

Run the readiness check against the same database URL used by the API:

```bash
npm run backup:check
```

The check verifies database reachability and the presence of `pg_dump` and `pg_restore`. It does not upload a backup or replace an external scheduler.

## Create a backup

Stop writes only if your backup platform requires it. A consistent Postgres dump can run while Aperio is serving traffic:

```bash
pg_dump --format=custom --no-owner --no-acl "$DATABASE_URL" \
  --file "aperio-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Encrypt the dump before it leaves the host, upload it to the configured retention store, and record the image digest and database migration level beside the artifact. Do not put the dump in the repository or a public bucket.

## Restore drill

Restore into a new, isolated Postgres database first:

```bash
createdb aperio_restore_check
pg_restore --clean --if-exists --no-owner --no-acl \
  --dbname "$RESTORE_DATABASE_URL" aperio-YYYYMMDDTHHMMSSZ.dump
```

Point a maintenance Compose stack at the restored database, run `docker compose ... up migrate`, and check `/readyz`. Verify a seeded finding, incident timeline, approval record, and SIEM delivery row before declaring the drill successful. Keep the original database untouched until the restored user path is verified.
