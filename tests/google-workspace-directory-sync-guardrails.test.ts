import { readFileSync } from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(rel: string) {
  return readFileSync(path.join(repoRoot, rel), "utf8");
}

// Until this PR, saas_identities was populated only by scripts/seed.ts; live
// Google Workspace tenants always saw 0 privileged identities / 0 active
// accounts / 0% MFA coverage on the Security Graph and the report. These
// guardrails pin that the directory-sync producer remains wired end-to-end
// (binary + npm script + Makefile + dev.mjs auto-start) so future refactors
// cannot silently regress the identity surface back to empty.

test("google-workspace-directory-sync binary upserts saas_identities", () => {
  const sync = readRepoFile("internal/googleworkspacedirectorysync/sync.go");
  assert.match(
    sync,
    /INSERT INTO saas_identities[\s\S]*?ON CONFLICT \(organization_id, provider, external_id\)/,
    "upsert must be keyed on (organization_id, provider, external_id) to converge across renames"
  );
  assert.match(
    sync,
    /'GOOGLE_WORKSPACE'::"SaaSProvider"/,
    "provider must be cast to the SaaSProvider enum so Postgres accepts the insert"
  );
  assert.match(
    sync,
    /admin\.googleapis\.com\/admin\/directory\/v1\/users/,
    "must call the Directory API users endpoint"
  );
  assert.match(
    sync,
    /customer=my_customer/,
    "must scope to my_customer so the request implicitly targets the tenant the access token belongs to"
  );
});

test("dead-letter fix: MapEventType returns empty for unknown events", () => {
  const eventType = readRepoFile("internal/googleworkspacepoller/event_type.go");
  // The fix is a single return-path change; pin the absence of the old
  // uppercased-passthrough so a careless edit cannot re-introduce the
  // 84%-dead-letter regression.
  assert.doesNotMatch(
    eventType,
    /return\s+strings\.ToUpper\(eventName\)/,
    "MapEventType must NOT uppercase-passthrough unknown events; they belong nowhere on the ingestion queue"
  );
  const poller = readRepoFile("internal/googleworkspacepoller/poller.go");
  assert.match(
    poller,
    /if\s+mapped\s*==\s*""\s*\{\s*[\s\S]*?return\s+nil\s*\}/,
    "enqueueEvent must skip the insert when MapEventType returned an empty string"
  );
});

// Cross-package contract: every non-empty value MapEventType can ever return
// must be in the worker's GOOGLE_WORKSPACE allowlist. Otherwise the producer
// silently leaks events that the consumer immediately dead-letters — the
// exact regression a reviewer caught with token/revoke -> OAUTH_TOKEN_REVOKED
// in the original PR (OAUTH_TOKEN_REVOKED was returned by the mapper but
// missing from supportedIngestionEventTypes, so every revoke was instantly
// DEAD_LETTER as unsupported work). Adding a new return value here without
// a matching allowlist + evaluator must fail this test.
test("every MapEventType return is in the worker's GOOGLE_WORKSPACE allowlist", () => {
  const eventType = readRepoFile("internal/googleworkspacepoller/event_type.go");
  const literalReturns = Array.from(eventType.matchAll(/return\s+"([A-Z_]+)"/g))
    .map((m) => m[1])
    .filter((s) => s.length > 0);
  assert.ok(literalReturns.length > 0, "expected at least one literal return in MapEventType");
  const worker = readRepoFile("internal/ingestionworker/worker.go");
  const gwBlock = worker.match(/"GOOGLE_WORKSPACE":\s*\{([\s\S]*?)\}/);
  assert.ok(gwBlock, "could not locate the GOOGLE_WORKSPACE allowlist block in worker.go");
  const allowlist = new Set(
    Array.from(gwBlock![1].matchAll(/"([A-Z_]+)"/g)).map((m) => m[1])
  );
  for (const code of literalReturns) {
    assert.ok(
      allowlist.has(code),
      `MapEventType returns ${code} but the worker's GOOGLE_WORKSPACE allowlist does not include it; this would dead-letter every matching event. Add it to supportedIngestionEventTypes and ship an evaluator, or drop the mapping case.`
    );
  }
});

test("directory sync wired into package.json and Makefile", () => {
  const pkg = JSON.parse(readRepoFile("package.json"));
  assert.ok(pkg.scripts["worker:google-directory"], "package.json must expose worker:google-directory");
  assert.ok(pkg.scripts["worker:google-directory:go"], "package.json must expose the :go alias");
  assert.match(
    pkg.scripts["worker:google-directory"],
    /go run \.\/cmd\/google-workspace-directory-sync/,
    "worker:google-directory must run the Go binary"
  );
  const makefile = readRepoFile("Makefile");
  assert.match(
    makefile,
    /^worker-google-directory:\s+require-env/m,
    "Makefile must expose a worker-google-directory target"
  );
  assert.match(
    makefile,
    /^worker-google-directory-go:\s+worker-google-directory/m,
    "Makefile must expose the worker-google-directory-go alias"
  );
});

test("directory sync auto-started by dev.mjs", () => {
  const dev = readRepoFile("scripts/dev.mjs");
  assert.match(
    dev,
    /startWorker\("google-directory",\s*"\.\/cmd\/google-workspace-directory-sync"\)/,
    "scripts/dev.mjs must auto-start the directory sync alongside the other workers"
  );
});

test("source sync wake paths preserve one-shot and error visibility", () => {
  for (const file of [
    "cmd/google-workspace-bigquery-sync/main.go",
    "cmd/google-workspace-directory-sync/main.go",
    "cmd/google-workspace-oauth-sync/main.go"
  ]) {
    const source = readRepoFile(file);
    assert.match(source, /openWakeListener\(ctx, cfg\.DatabaseURL\)/, `${file} must listen before -once ticks`);
    assert.match(source, /drainWakeNotifications\(ctx, listener,/, `${file} must drain wake notifications in -once mode`);
    assert.match(source, /var active atomic\.Int64/, `${file} must keep draining while wake-triggered work is active`);
    assert.match(source, /notificationPollInterval/, `${file} must poll for additional once-mode wake notifications`);
    assert.match(source, /listenerFailed := false/, `${file} must track listener failures separately from active wake work`);
    assert.match(
      source,
      /if time\.Now\(\)\.After\(deadline\) \{[\s\S]*?if active\.Load\(\) > 0 \{[\s\S]*?wake drain budget elapsed[\s\S]*?listenerFailed = true[\s\S]*?continue/,
      `${file} must wait for active wake work instead of canceling it when the once-mode drain budget elapses`
    );
    assert.match(
      source,
      /if listenerFailed && active\.Load\(\) == 0[\s\S]*?return/,
      `${file} must not exit after listener failure until active wake work finishes`
    );
    assert.match(
      source,
      /if active\.Load\(\) > 0 \{[\s\S]*?-once wake drain stopped listening[\s\S]*?listenerFailed = true/,
      `${file} must keep once-mode alive when WaitForNotification fails while wake work is active`
    );
    assert.match(
      source,
      /waitErr := waitCtx\.Err\(\)[\s\S]*?stopWaiting\(\)[\s\S]*?if waitErr != nil/,
      `${file} must inspect the wait timeout before canceling the timeout context`
    );
  }
  for (const file of [
    "internal/googleworkspacedirectorysync/sync.go",
    "internal/googleworkspaceoauthsync/sync.go"
  ]) {
    const source = readRepoFile(file);
    assert.match(
      source,
      /func \(s \*Sync\) WakeIntegration[\s\S]*?s\.recordError\(ctx, integ\.ID, err\)/,
      `${file} must persist wake-triggered failures to last_error`
    );
    assert.doesNotMatch(
      source,
      /ON CONFLICT \(integration_id\) DO UPDATE SET\s+last_synced_at = EXCLUDED\.last_synced_at,\s+last_error/s,
      `${file} must not advance last_synced_at on failed full sweeps`
    );
  }
});

test("source sync cursor state preserves queued backfills and BigQuery queue attribution", () => {
  const reports = readRepoFile("internal/googleworkspacepoller/poller.go");
  const bigquery = readRepoFile("internal/googleworkspacepoller/bigquery.go");
  const status = readRepoFile("internal/bootstrap/sync_status.go");

  assert.match(reports, /syncstate\.BackfillQueuedPrefix\+"%"/);
  assert.match(
    reports,
    /WHERE COALESCE\(google_workspace_sync_cursors\.last_error, ''\) NOT LIKE \$6[\s\S]*?last_event_time = \$7[\s\S]*?last_unique_qualifier = \$8/,
    "Reports cursor writes must not clear a queued backfill from an overlapping stale sweep"
  );
  assert.match(
    reports,
    /func \(p \*Poller\) recordApplicationSetupErrors[\s\S]*?expected, err := p\.loadCursor\(ctx, integrationID, app\)[\s\S]*?p\.recordError\(ctx, integrationID, app, expected, setupErr\)/,
    "Reports setup failures must load each stream cursor before recording errors so queued backfills can be replaced by the real failure"
  );
  assert.match(bigquery, /syncstate\.BackfillQueuedPrefix\+"%"/);
  assert.match(
    bigquery,
    /WHERE COALESCE\(google_workspace_bigquery_sync_cursors\.last_error, ''\) NOT LIKE \$7[\s\S]*?last_event_time = \$8[\s\S]*?last_row_hash = \$9/,
    "BigQuery cursor writes must not clear a queued backfill from an overlapping stale sweep"
  );
  assert.match(
    bigquery,
    /func \(p \*BigQueryPoller\) recordBigQueryErrors[\s\S]*?expected, loadErr := p\.loadBigQueryCursor\(ctx, integrationID, recordType\)[\s\S]*?p\.recordBigQueryError\(ctx, integrationID, recordType, expected, err\)/,
    "BigQuery setup failures must load each stream cursor before recording errors so queued backfills can be replaced by the real failure"
  );
  assert.match(status, /queueSource := "google\.bigquery\." \+ recordType/);
  assert.match(bigquery, /googleBigQueryQueueSource\(application\)/);
  assert.match(reports, /googleReportsQueueSource\(application\)/);
});

test("source sync all waits for Directory before waking OAuth", () => {
  const status = readRepoFile("internal/bootstrap/sync_status.go");
  const allCase = status.match(/case "all":[\s\S]*?return channels, nil/);
  assert.ok(allCase, "syncWakeChannelsForSource must keep an explicit all-source branch");
  assert.doesNotMatch(
    allCase![0],
    /GoogleWorkspaceOAuthSyncWakeChannel/,
    "Sync all must not wake OAuth in parallel with Directory; OAuth depends on freshly refreshed saas_identities"
  );
  assert.match(
    status,
    /kind == "all" && channel == GoogleWorkspaceDirectorySyncWakeChannel[\s\S]*?syncwake\.Encode\(integ\.ID, syncwake\.ModeOAuthAfterDirectorySync\)/,
    "Sync all must tag the Directory wake so the Directory worker chains OAuth only after identities refresh"
  );
  assert.match(
    status,
    /kind == sourceGoogleOAuth[\s\S]*?googleWorkspaceIdentitiesSeeded\(ctx, integ\.ID\)[\s\S]*?connect\.CodeFailedPrecondition/,
    "Direct OAuth source sync must be rejected until Directory has seeded saas_identities"
  );
  assert.match(
    status,
    /newSyncState\(sourceGoogleOAuth, "grants", "OAuth app grants", "", queueCounts\{\}, identitiesSeeded, false\)/,
    "OAuth source row must stay disabled until Google Workspace identities exist"
  );

  const directoryCmd = readRepoFile("cmd/google-workspace-directory-sync/main.go");
  assert.match(
    directoryCmd,
    /syncwake\.Decode\(notification\.Payload\)/,
    "Directory wake listener must decode the source-sync mode payload"
  );
  assert.match(
    directoryCmd,
    /worker\.WakeIntegration\(ctx, integrationID\)[\s\S]*?mode != syncwake\.ModeOAuthAfterDirectorySync[\s\S]*?notifyOAuthAfterDirectorySync\(ctx, notifyDB, integrationID\)/,
    "Directory worker must notify OAuth only after the Directory refresh succeeds"
  );
  assert.match(
    directoryCmd,
    /SELECT pg_notify\(\$1, \$2\)[\s\S]*?bootstrap\.GoogleWorkspaceOAuthSyncWakeChannel/,
    "Directory worker must use the OAuth wake channel for the chained follow-up"
  );
});

test("directory sync owned in migration matrix", () => {
  const matrix = JSON.parse(readRepoFile("tests/fixtures/migration-ownership/migration-matrix.json"));
  const entry = matrix.entries.find((e: { id: string }) => e.id === "cmd-google-workspace-directory-sync-go-default");
  assert.ok(entry, "migration matrix must declare ownership for the directory sync");
  for (const cover of [
    "repo-file:cmd/google-workspace-directory-sync/*.go",
    "repo-file:internal/googleworkspacedirectorysync/*.go",
    "package-script:worker:google-directory",
    "make-target:worker-google-directory"
  ]) {
    assert.ok(
      entry.covers.includes(cover),
      `matrix entry must cover ${cover} so new repo files do not slip out of ownership`
    );
  }
});
