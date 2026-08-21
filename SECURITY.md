# Security policy

## Supported versions

The `main` branch is the supported development line. The latest `0.1.x` release is supported for security fixes while the next patch release is prepared.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use a private GitHub Security Advisory for `writer/aperio`, or email `security@writer.com` with:

- the affected commit, release, or image digest;
- a concise description of the impact and attacker prerequisites;
- reproduction steps or a minimal proof of concept;
- any proposed mitigation.

Please do not include credentials, customer data, or unredacted production logs. Encrypt sensitive attachments with a key supplied in the private response.

We will acknowledge a report within five business days. We will coordinate a fix, affected-version assessment, and disclosure date with the reporter. Timelines depend on exploitability and the availability of a safe patch.

## Deployment safety

- Treat connector credentials, session secrets, encryption keys, and SIEM tokens as secrets.
- Run `npm run audit:prod`, `go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...`, and `npm run leak:check` before publishing an image.
- Verify the release image signature and digest before deploying it.
- Keep Postgres backups encrypted and test a restore before relying on them.
- Keep `APERIO_ALLOW_INSECURE_DEMO_AUTH`, `APERIO_EXPOSE_AUTH_LINKS`, and `APERIO_ALLOW_PREVIEW_CONNECTORS` disabled outside local development.

## Scope

This policy covers the Aperio source tree, its release image, and the bundled self-hosted deployment files. Provider-side configuration, credentials, and private deployment environments are outside this repository; report issues in those systems to their owning team.
