# Contributing to Aperio

## Before you start

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Use a private report for security issues; do not put exploit details in an issue or pull request.

For code changes, open an issue when the behavior or data contract is unclear. Keep a pull request focused on one user-visible outcome. Do not commit `.env`, provider credentials, generated build output, or production data.

## Local setup

Requirements:

- Node.js 20 and npm 10 or newer;
- Go 1.26.6;
- Docker Compose v2;
- GNU Make.

```bash
cp .env.example .env
make setup
make dev
```

Use `.env.production.example` only as a template for the self-hosted production bundle. Never commit `.env.production`.

## Validation

Run the narrowest relevant checks while iterating, then run the full verifier before opening a pull request:

```bash
npm run typecheck
npm run test:api
go test ./...
npm run db:validate
npm run audit:prod
npm run leak:check
npm run verify
```

Changes to a workflow must keep third-party actions pinned to a full commit SHA. The locally-owned review preflight checks this rule and records the required follow-up checks; it does not call an external code-writing or review service.

Until the repository branch-protection settings are migrated, the local workflow emits the existing `Droid Review Preflight` and `Droid Review Required` check names. They are compatibility contexts only: both jobs execute repository-owned, read-only validation and no longer invoke the retired vendor automation. Do not rename these jobs without a coordinated branch-protection update.

Changes to protobuf definitions require generated Go and TypeScript clients to be current:

```bash
npm run proto:check
```

Changes to Prisma schema or migrations require a migration test against Postgres. Do not edit generated Prisma client output by hand.

## Pull requests

Describe the behavior change, data or migration impact, and the commands you ran. Include screenshots for operator-console changes and a redacted request/response example for API changes. Call out any connector scope or remediation behavior changes.

Keep commits small and use an imperative subject, for example `fix: preserve SIEM delivery retry state`. A maintainer will decide the required review and merge sequence; do not add reviewers or bypass repository protection.
