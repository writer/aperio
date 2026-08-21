# Release procedure

## Release inputs

The release workflow accepts a semantic version tag such as `v0.1.0`. It validates the source, runs the production dependency and Go vulnerability gates, builds the multi-process image, publishes an SBOM and provenance attestation, and signs the image digest with Cosign.

The public repository owns source validation and image publication. Deployment configuration and credentials remain outside this repository.

## Prepare

```bash
npm ci
npm run db:validate
npm run typecheck
npm run audit:prod
go test ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...
npm run leak:check
```

Update [`CHANGELOG.md`](../CHANGELOG.md), confirm the image tag in [`.env.production.example`](../.env.production.example) when applicable, and verify the exact commit to tag.

## Publish

```bash
git tag -a v0.1.0 -m "Aperio v0.1.0"
git push origin v0.1.0
```

The workflow publishes `ghcr.io/writer/aperio:v0.1.0` and uploads a `release-receipt` artifact containing the image tag, immutable digest, source commit, and signing result. Download that artifact and record the digest before deployment:

```bash
cosign verify ghcr.io/writer/aperio:v0.1.0
docker buildx imagetools inspect ghcr.io/writer/aperio:v0.1.0
```

The public workflow does not dispatch into a private environment. The operator-owned deployment process must use the receipt digest, apply it through the private deployment system or the production Compose bundle, and retain the resulting deployment and user-path checks with the release record. For Compose, set `APERIO_IMAGE_TAG` to the published tag and capture `docker compose ... ps` plus the `/readyz` response after the migration service completes.

Do not copy credentials into release notes, issue comments, workflow logs, or Compose files.
