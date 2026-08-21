# Changelog

All notable changes to Aperio are recorded here. Release entries are tied to a signed image tag and its digest.

## [Unreleased]

## [0.1.0] - 2026-08-21

- Added tenant-scoped, hashed API tokens with read, write, and admin scopes,
  expiry, revocation, last-used state, and audit records.
- Added `aperioctl` commands for health checks, findings, connectors, sync,
  SIEM destinations, and API-token lifecycle operations.
- Added durable connector-sync and rule-run receipts plus authenticated
  operator health for connector freshness, ingestion queues, SIEM delivery,
  and recent rule execution.
- Added a Prometheus endpoint that is disabled until a dedicated scrape token
  is configured and does not expose tenant or resource labels.
- Added a strict CEL/YAML detection engine with versioned rules for GitHub
  public repositories, Slack MFA and external shared channels, and Google
  Workspace external sharing.
- Added tenant rule disablement, severity overrides, scoped auto-resolution,
  an in-memory backtest API, and an explicit connector support matrix.
- Added a locally-owned review preflight that checks workflow action pinning and reports required validation commands.
- Removed vendor-backed review and code-writing workflows from the public repository.
- Added a production Compose bundle with Postgres, NATS, API, web, ingestion, SIEM, and migration services.
- Added release, upgrade, backup, security, and contributor documentation.
- Updated the Node dependency lock and Go modules to patched release lines.
