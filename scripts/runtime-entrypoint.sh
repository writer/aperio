#!/usr/bin/env bash
set -euo pipefail

mode="${1:-web}"
shift || true

run_migrations() {
  if [ "${APERIO_RUN_MIGRATIONS:-false}" = "true" ]; then
    npx prisma migrate deploy --schema packages/db/prisma/schema.prisma
  fi
}

case "${mode}" in
  api)
    run_migrations
    exec /usr/local/bin/aperio "$@"
    ;;
  web)
    exec npx next start apps/web -p "${PORT:-3000}" "$@"
    ;;
  ingestion-worker)
    exec /usr/local/bin/ingestion-worker "$@"
    ;;
  siem-dispatcher)
    exec /usr/local/bin/siem-dispatcher "$@"
    ;;
  google-workspace-poller|google-workspace-bigquery-sync|google-workspace-directory-sync|google-workspace-oauth-sync)
    exec "/usr/local/bin/${mode}" "$@"
    ;;
  *)
    exec "$mode" "$@"
    ;;
esac
