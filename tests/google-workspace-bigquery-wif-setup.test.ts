import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildGoogleWorkspaceBigQueryWifSetupScript,
  validateGoogleWorkspaceBigQueryWifSetupInput
} from "../packages/shared/src/google-workspace-bigquery-wif";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readRepoFile(relativePath: string) {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

test("package does not expose a standalone Google Workspace BigQuery WIF setup command", () => {
  const pkg = JSON.parse(readRepoFile("package.json")) as {
    scripts: Record<string, string>;
  };

  assert.equal(pkg.scripts["setup:gws-bigquery-wif"], undefined);
});

test("connectors UI exposes clean BigQuery WIF setup wizard", () => {
  const source = readRepoFile("apps/web/components/connectors/connectors-page.tsx");

  assert.match(source, /GoogleWorkspaceBigQuerySetupDialog/);
  assert.match(source, />\s*BigQuery\s*</);
  assert.match(source, /Google Workspace BigQuery intelligence/);
  assert.match(source, /Workload Identity Federation/);
  assert.match(source, /No service-account keys are stored in\s+Aperio/);
  assert.match(source, /Authorized views/);
  assert.match(source, /Data-owner BigQuery project/);
  assert.match(source, /Workload Identity trust/);
  assert.match(source, /Commands to run/);
  assert.match(source, /Save in Aperio/);
  assert.match(source, /fetchGoogleWorkspaceBigQueryConfig/);
  assert.match(source, /updateGoogleWorkspaceBigQueryConfig/);
  assert.match(source, /setupScriptError/);
  assert.match(source, /setProjectId\(""\)/);
  assert.match(source, /integrationId/);
  assert.match(source, /buildGoogleWorkspaceBigQueryWifSetupScript/);
  assert.match(source, /googleWorkspaceBigQueryWifDefaults/);
  assert.doesNotMatch(source, /WriterInternal|WriterColab/);
});

test("shared WIF setup generator emits least-privilege BigQuery commands", () => {
  const script = buildGoogleWorkspaceBigQueryWifSetupScript({
    projectId: "example-project",
    rawDatasetId: "workspace_logs",
    location: "US",
    oidcIssuerUri: "https://issuer.example.com",
    oidcAudience: "aperio",
    principalSubject: "repo:example/aperio:ref:refs/heads/main",
    accessMode: "dataset"
  });

  assert.match(script, /gcloud iam workload-identity-pools create/);
  assert.match(script, /gcloud iam workload-identity-pools providers create-oidc/);
  assert.match(script, /providers update-oidc/);
  assert.match(script, /remove-iam-policy-binding/);
  assert.match(script, /roles\/iam\.workloadIdentityUser/);
  assert.match(script, /roles\/bigquery\.jobUser/);
  assert.match(script, /roles\/bigquery\.dataViewer/);
  assert.match(script, /Raw dataset mode never creates/);
  assert.match(script, /RAW_TABLE_COUNT/);
  assert.match(script, /bq query[\s\S]*--dry_run/);
  assert.match(script, /INFORMATION_SCHEMA\.TABLES/);
  assert.doesNotMatch(script, /mk --dataset "\$PROJECT_ID:\$READ_DATASET"/);
  assert.doesNotMatch(script, /bq update --source/);
  assert.doesNotMatch(script, /writer/i);
  assert.doesNotMatch(script, /WriterInternal|WriterColab/);
});

test("shared WIF setup generator supports authorized-view read datasets", () => {
  const script = buildGoogleWorkspaceBigQueryWifSetupScript({
    projectId: "example-project",
    rawDatasetId: "raw_workspace_logs",
    readDatasetId: "aperio_workspace_views",
    accessMode: "views",
    location: "EU",
    oidcIssuerUri: "https://issuer.example.com",
    oidcAudience: "aperio",
    principalAttribute: "repository",
    principalValue: "example/aperio"
  });

  assert.match(script, /WORKSPACE_LOG_DATASET='raw_workspace_logs'/);
  assert.match(script, /READ_DATASET='aperio_workspace_views'/);
  assert.match(script, /authorized view/i);
  assert.match(script, /SELECT \*/);
  assert.match(script, /bq mk --project_id="\$PROJECT_ID" --use_legacy_sql=false --view/);
  assert.match(script, /bq update --source "\$DATASET_ACCESS_JSON"/);
  assert.match(script, /"view": \{/);
  assert.match(
    script,
    /principalSet:\/\/iam\.googleapis\.com\/projects\/\$\{PROJECT_NUMBER\}\/locations\/global\/workloadIdentityPools\/\$\{POOL_ID\}\/attribute\.repository\/\$\{PRINCIPAL_VALUE\}/
  );
});

test("Google Workspace BigQuery config has API and storage surfaces", () => {
  const proto = readRepoFile("proto/aperio/v1/api.proto");
  const webApi = readRepoFile("apps/web/lib/api.ts");
  const schema = readRepoFile("packages/db/prisma/schema.prisma");
  const migration = readRepoFile(
    "packages/db/prisma/migrations/20260614100000_google_workspace_bigquery_config/migration.sql"
  );
  const app = readRepoFile("internal/bootstrap/app.go");
  const compat = readRepoFile("internal/bootstrap/compat_api.go");

  assert.match(proto, /GetGoogleWorkspaceBigQueryConfig/);
  assert.match(proto, /UpdateGoogleWorkspaceBigQueryConfig/);
  assert.match(webApi, /fetchGoogleWorkspaceBigQueryConfig/);
  assert.match(webApi, /updateGoogleWorkspaceBigQueryConfig/);
  assert.match(schema, /googleWorkspaceBigQueryProjectId/);
  assert.match(schema, /googleWorkspaceBigQueryWifProvider/);
  assert.match(migration, /google_workspace_bigquery_project_id/);
  assert.match(migration, /google_workspace_bigquery_wif_provider/);
  assert.match(app, /GetGoogleWorkspaceBigQueryConfig/);
  assert.match(app, /UpdateGoogleWorkspaceBigQueryConfig/);
  assert.match(compat, /compatUpdateGoogleWorkspaceBigQueryConfig/);
  assert.match(compat, /validateGoogleWorkspaceBigQueryConfig/);
});

test("shared WIF setup generator validates required trust inputs", () => {
  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        location: "US",
        accessMode: "dataset",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio"
      }),
    /principalSubject/
  );

  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        location: "US",
        accessMode: "views",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio",
        principalSubject: "subject"
      }),
    /readDatasetId/
  );

  assert.throws(
    () =>
      validateGoogleWorkspaceBigQueryWifSetupInput({
        projectId: "example-project",
        rawDatasetId: "workspace_logs",
        readDatasetId: "workspace_logs",
        location: "US",
        accessMode: "views",
        oidcIssuerUri: "https://issuer.example.com",
        oidcAudience: "aperio",
        principalSubject: "subject"
      }),
    /different from rawDatasetId/
  );
});
