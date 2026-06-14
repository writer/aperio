import {
  terraformAttribute,
  terraformBlock,
  terraformExpression,
  terraformOutput,
  terraformResource,
  terraformString,
  terraformValue,
  terraformVariable
} from "./terraform";

export type GoogleWorkspaceBigQueryWifAccessMode = "dataset" | "views";
export type GoogleWorkspaceBigQueryWifOutputMode = "bash" | "terraform";

export type GoogleWorkspaceBigQueryWifSetupInput = {
  projectId: string;
  rawDatasetId: string;
  readDatasetId?: string;
  location: string;
  serviceAccountName?: string;
  poolId?: string;
  providerId?: string;
  oidcIssuerUri: string;
  oidcAudience: string;
  principalSubject?: string;
  principalAttribute?: string;
  principalValue?: string;
  providerAttributeCondition?: string;
  accessMode?: GoogleWorkspaceBigQueryWifAccessMode;
  outputMode?: GoogleWorkspaceBigQueryWifOutputMode;
};

export const googleWorkspaceBigQueryWifDefaults = {
  serviceAccountName: "aperio-bq-reader",
  poolId: "aperio-workloads",
  providerId: "aperio-oidc",
  accessMode: "views" satisfies GoogleWorkspaceBigQueryWifAccessMode,
  rawDatasetId: "workspace_logs",
  readDatasetId: "aperio_workspace_views",
  location: "US",
  oidcAudience: "aperio",
  outputMode: "bash" satisfies GoogleWorkspaceBigQueryWifOutputMode
} as const;

const principalAttributePattern = /^[a-z][a-z0-9_]{0,99}$/;

export function validateGoogleWorkspaceBigQueryWifSetupInput(
  input: GoogleWorkspaceBigQueryWifSetupInput
) {
  const accessMode = input.accessMode ?? googleWorkspaceBigQueryWifDefaults.accessMode;
  const outputMode = input.outputMode ?? googleWorkspaceBigQueryWifDefaults.outputMode;
  const required: Array<keyof GoogleWorkspaceBigQueryWifSetupInput> = [
    "projectId",
    "rawDatasetId",
    "location",
    "oidcIssuerUri",
    "oidcAudience"
  ];
  for (const key of required) {
    if (!input[key]?.trim()) {
      throw new Error(`Missing required ${key}`);
    }
  }
  if (accessMode !== "dataset" && accessMode !== "views") {
    throw new Error("accessMode must be dataset or views");
  }
  if (outputMode !== "bash" && outputMode !== "terraform") {
    throw new Error("outputMode must be bash or terraform");
  }
  if (
    input.principalAttribute?.trim() &&
    !principalAttributePattern.test(input.principalAttribute.trim())
  ) {
    throw new Error("principalAttribute must start with a lowercase letter and contain only lowercase letters, numbers, or underscores");
  }
  if (accessMode === "views" && !input.readDatasetId?.trim()) {
    throw new Error("readDatasetId is required when accessMode is views");
  }
  if (
    accessMode === "views" &&
    input.readDatasetId?.trim() === input.rawDatasetId.trim()
  ) {
    throw new Error("readDatasetId must be different from rawDatasetId for views");
  }
  if (
    !input.principalSubject?.trim() &&
    !(input.principalAttribute?.trim() && input.principalValue?.trim())
  ) {
    throw new Error(
      "Provide either principalSubject or both principalAttribute and principalValue"
    );
  }
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function wifMemberExpression(input: RequiredWifSetupInput) {
  if (input.principalAttribute && input.principalValue) {
    return `principalSet://iam.googleapis.com/projects/\${PROJECT_NUMBER}/locations/global/workloadIdentityPools/\${POOL_ID}/attribute.${input.principalAttribute}/\${PRINCIPAL_VALUE}`;
  }
  return "principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/subject/${PRINCIPAL_SUBJECT}";
}

function authorizedViewCommands(input: RequiredWifSetupInput) {
  if (input.accessMode !== "views") return "";

  return `
# Mirror each raw Workspace export table as an authorized view in $READ_DATASET,
# then authorize those views on $WORKSPACE_LOG_DATASET. Aperio receives
# dataViewer only on $READ_DATASET. The generated views include _PARTITIONTIME
# for efficient incremental scans; edit VIEW_SQL below before running if you
# want a narrower column set.
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

RAW_TABLE_IDS_FILE="$TMP_DIR/raw-table-ids.txt"
AUTHORIZED_VIEW_IDS_FILE="$TMP_DIR/authorized-view-ids.txt"
DATASET_ACCESS_JSON="$TMP_DIR/workspace-log-dataset-access.json"

bq show --project_id="$PROJECT_ID" "$PROJECT_ID:$WORKSPACE_LOG_DATASET" >/dev/null

bq --project_id="$PROJECT_ID" --location="$LOCATION" ls --max_results="$BQ_TABLE_LIST_MAX_RESULTS" --format=prettyjson "$PROJECT_ID:$WORKSPACE_LOG_DATASET" | \\
  python3 -c 'import json, sys
tables = json.load(sys.stdin)
for table in tables:
    table_id = table.get("tableReference", {}).get("tableId", "")
    table_type = table.get("type", "TABLE")
    if table_id and table_type == "TABLE":
        print(table_id)
' > "$RAW_TABLE_IDS_FILE"

if [[ ! -s "$RAW_TABLE_IDS_FILE" ]]; then
  echo "No base tables found in $PROJECT_ID:$WORKSPACE_LOG_DATASET; create the Google Workspace BigQuery export first." >&2
  exit 1
fi
RAW_TABLE_COUNT="$(wc -l < "$RAW_TABLE_IDS_FILE" | tr -d '[:space:]')"
if [[ "$RAW_TABLE_COUNT" == "$BQ_TABLE_LIST_MAX_RESULTS" ]]; then
  echo "Found $BQ_TABLE_LIST_MAX_RESULTS raw tables, which may mean bq ls truncated the export table list. Increase BQ_TABLE_LIST_MAX_RESULTS and rerun." >&2
  exit 1
fi

: > "$AUTHORIZED_VIEW_IDS_FILE"
while IFS= read -r TABLE_ID; do
  VIEW_ID="$(printf '%s' "aperio_$TABLE_ID" | tr -c 'A-Za-z0-9_' '_')"
  VIEW_SQL="SELECT t.*, t._PARTITIONTIME AS aperio_partition_time FROM \\\`$PROJECT_ID.$WORKSPACE_LOG_DATASET.$TABLE_ID\\\` AS t"
  if bq show --project_id="$PROJECT_ID" "$PROJECT_ID:$READ_DATASET.$VIEW_ID" >/dev/null 2>&1; then
    bq update --project_id="$PROJECT_ID" --use_legacy_sql=false --view "$VIEW_SQL" "$PROJECT_ID:$READ_DATASET.$VIEW_ID"
  else
    bq mk --project_id="$PROJECT_ID" --use_legacy_sql=false --view "$VIEW_SQL" "$PROJECT_ID:$READ_DATASET.$VIEW_ID"
  fi
  printf '%s\\n' "$VIEW_ID" >> "$AUTHORIZED_VIEW_IDS_FILE"
done < "$RAW_TABLE_IDS_FILE"

bq show --format=prettyjson "$PROJECT_ID:$WORKSPACE_LOG_DATASET" > "$DATASET_ACCESS_JSON"
python3 - "$DATASET_ACCESS_JSON" "$PROJECT_ID" "$READ_DATASET" "$AUTHORIZED_VIEW_IDS_FILE" <<'PY'
import json
import sys

dataset_path, project_id, read_dataset, view_ids_path = sys.argv[1:]
with open(view_ids_path, encoding="utf-8") as handle:
    view_ids = [line.strip() for line in handle if line.strip()]
with open(dataset_path, encoding="utf-8") as handle:
    dataset = json.load(handle)

access = dataset.get("access", [])
existing = {
    (
        entry.get("view", {}).get("projectId"),
        entry.get("view", {}).get("datasetId"),
        entry.get("view", {}).get("tableId"),
    )
    for entry in access
    if "view" in entry
}
for view_id in view_ids:
    key = (project_id, read_dataset, view_id)
    if key not in existing:
        access.append(
            {
                "view": {
                    "projectId": project_id,
                    "datasetId": read_dataset,
                    "tableId": view_id,
                }
            }
        )

with open(dataset_path, "w", encoding="utf-8") as handle:
    json.dump({"access": access}, handle, indent=2)
    handle.write("\\n")
PY
bq update --source "$DATASET_ACCESS_JSON" "$PROJECT_ID:$WORKSPACE_LOG_DATASET"
`;
}

function datasetModeValidationCommands(input: RequiredWifSetupInput) {
  if (input.accessMode !== "dataset") return "";

  return `
# Raw dataset mode never creates the Workspace export dataset. It must already
# exist and contain exported Workspace tables.
bq show --project_id="$PROJECT_ID" "$PROJECT_ID:$WORKSPACE_LOG_DATASET" >/dev/null
RAW_TABLE_COUNT="$(bq --project_id="$PROJECT_ID" --location="$LOCATION" ls --max_results="$BQ_TABLE_LIST_MAX_RESULTS" --format=prettyjson "$PROJECT_ID:$WORKSPACE_LOG_DATASET" | \\
  python3 -c 'import json, sys
tables = json.load(sys.stdin)
print(sum(1 for table in tables if table.get("type", "TABLE") == "TABLE"))
')"
if [[ "$RAW_TABLE_COUNT" == "0" ]]; then
  echo "No base tables found in $PROJECT_ID:$WORKSPACE_LOG_DATASET; create the Google Workspace BigQuery export first." >&2
  exit 1
fi
`;
}

function readDatasetSetupCommands(input: RequiredWifSetupInput) {
  if (input.accessMode === "views") {
    return `bq --location="$LOCATION" mk --dataset "$PROJECT_ID:$READ_DATASET" >/dev/null 2>&1 || true
${authorizedViewCommands(input)}`;
  }
  return datasetModeValidationCommands(input);
}

type RequiredWifSetupInput = Required<
  Pick<
    GoogleWorkspaceBigQueryWifSetupInput,
    | "projectId"
    | "rawDatasetId"
    | "readDatasetId"
    | "location"
    | "serviceAccountName"
    | "poolId"
    | "providerId"
    | "oidcIssuerUri"
    | "oidcAudience"
    | "accessMode"
    | "outputMode"
  >
> &
  Pick<
    GoogleWorkspaceBigQueryWifSetupInput,
    | "principalSubject"
    | "principalAttribute"
    | "principalValue"
    | "providerAttributeCondition"
  >;

function withDefaults(input: GoogleWorkspaceBigQueryWifSetupInput): RequiredWifSetupInput {
  const next = {
    ...input,
    rawDatasetId:
      input.rawDatasetId || googleWorkspaceBigQueryWifDefaults.rawDatasetId,
    readDatasetId:
      input.readDatasetId || googleWorkspaceBigQueryWifDefaults.readDatasetId,
    location: input.location || googleWorkspaceBigQueryWifDefaults.location,
    serviceAccountName:
      input.serviceAccountName ||
      googleWorkspaceBigQueryWifDefaults.serviceAccountName,
    poolId: input.poolId || googleWorkspaceBigQueryWifDefaults.poolId,
    providerId: input.providerId || googleWorkspaceBigQueryWifDefaults.providerId,
    oidcAudience:
      input.oidcAudience || googleWorkspaceBigQueryWifDefaults.oidcAudience,
    accessMode: (input.accessMode ||
      googleWorkspaceBigQueryWifDefaults.accessMode) as GoogleWorkspaceBigQueryWifAccessMode,
    outputMode: (input.outputMode ||
      googleWorkspaceBigQueryWifDefaults.outputMode) as GoogleWorkspaceBigQueryWifOutputMode
  };
  validateGoogleWorkspaceBigQueryWifSetupInput(next);
  return next as RequiredWifSetupInput;
}

export function buildGoogleWorkspaceBigQueryWifSetupScript(
  rawInput: GoogleWorkspaceBigQueryWifSetupInput
) {
  const input = withDefaults(rawInput);
  if (input.outputMode === "terraform") {
    return buildGoogleWorkspaceBigQueryWifTerraform(input);
  }
  const readDataset =
    input.accessMode === "views" ? input.readDatasetId : input.rawDatasetId;
  const attributeMapping = input.principalAttribute
    ? `google.subject=assertion.sub,attribute.${input.principalAttribute}=assertion.${input.principalAttribute},attribute.audience=assertion.aud`
    : "google.subject=assertion.sub,attribute.audience=assertion.aud";
  const readDatasetSetup = readDatasetSetupCommands(input);

  return `#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID=${shellQuote(input.projectId)}
WORKSPACE_LOG_DATASET=${shellQuote(input.rawDatasetId)}
READ_DATASET=${shellQuote(readDataset)}
LOCATION=${shellQuote(input.location)}
SERVICE_ACCOUNT_NAME=${shellQuote(input.serviceAccountName)}
POOL_ID=${shellQuote(input.poolId)}
PROVIDER_ID=${shellQuote(input.providerId)}
OIDC_ISSUER_URI=${shellQuote(input.oidcIssuerUri)}
OIDC_AUDIENCE=${shellQuote(input.oidcAudience)}
PRINCIPAL_SUBJECT=${shellQuote(input.principalSubject ?? "")}
PRINCIPAL_VALUE=${shellQuote(input.principalValue ?? "")}
PROVIDER_ATTRIBUTE_CONDITION=${shellQuote(input.providerAttributeCondition ?? "")}
BQ_TABLE_LIST_MAX_RESULTS="\${BQ_TABLE_LIST_MAX_RESULTS:-10000}"

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")"
SERVICE_ACCOUNT_EMAIL="$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"
WIF_MEMBER="${wifMemberExpression(input)}"

gcloud services enable iamcredentials.googleapis.com sts.googleapis.com bigquery.googleapis.com --project "$PROJECT_ID"

gcloud iam service-accounts describe "$SERVICE_ACCOUNT_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1 || \\
  gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" \\
    --project "$PROJECT_ID" \\
    --display-name "Aperio BigQuery reader"

gcloud iam workload-identity-pools describe "$POOL_ID" --project "$PROJECT_ID" --location global >/dev/null 2>&1 || \\
  gcloud iam workload-identity-pools create "$POOL_ID" \\
    --project "$PROJECT_ID" \\
    --location global \\
    --display-name "Aperio workloads"

if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \\
  --project "$PROJECT_ID" \\
  --location global \\
  --workload-identity-pool "$POOL_ID" >/dev/null 2>&1; then
  if [[ -n "$PROVIDER_ATTRIBUTE_CONDITION" ]]; then
    gcloud iam workload-identity-pools providers update-oidc "$PROVIDER_ID" \\
      --project "$PROJECT_ID" \\
      --location global \\
      --workload-identity-pool "$POOL_ID" \\
      --issuer-uri "$OIDC_ISSUER_URI" \\
      --attribute-mapping ${shellQuote(attributeMapping)} \\
      --allowed-audiences "$OIDC_AUDIENCE" \\
      --attribute-condition "$PROVIDER_ATTRIBUTE_CONDITION"
  else
    gcloud iam workload-identity-pools providers update-oidc "$PROVIDER_ID" \\
      --project "$PROJECT_ID" \\
      --location global \\
      --workload-identity-pool "$POOL_ID" \\
      --issuer-uri "$OIDC_ISSUER_URI" \\
      --attribute-mapping ${shellQuote(attributeMapping)} \\
      --allowed-audiences "$OIDC_AUDIENCE"
  fi
else
  if [[ -n "$PROVIDER_ATTRIBUTE_CONDITION" ]]; then
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \\
      --project "$PROJECT_ID" \\
      --location global \\
      --workload-identity-pool "$POOL_ID" \\
      --display-name "Aperio OIDC" \\
      --issuer-uri "$OIDC_ISSUER_URI" \\
      --attribute-mapping ${shellQuote(attributeMapping)} \\
      --allowed-audiences "$OIDC_AUDIENCE" \\
      --attribute-condition "$PROVIDER_ATTRIBUTE_CONDITION"
  else
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \\
      --project "$PROJECT_ID" \\
      --location global \\
      --workload-identity-pool "$POOL_ID" \\
      --display-name "Aperio OIDC" \\
      --issuer-uri "$OIDC_ISSUER_URI" \\
      --attribute-mapping ${shellQuote(attributeMapping)} \\
      --allowed-audiences "$OIDC_AUDIENCE"
  fi
fi

WIF_POLICY_JSON="$(mktemp)"
gcloud iam service-accounts get-iam-policy "$SERVICE_ACCOUNT_EMAIL" \\
  --project "$PROJECT_ID" \\
  --format=json > "$WIF_POLICY_JSON"
python3 - "$WIF_POLICY_JSON" "$PROJECT_NUMBER" "$POOL_ID" "$WIF_MEMBER" <<'PY' | while IFS= read -r OBSOLETE_WIF_MEMBER; do
import json
import sys

policy_path, project_number, pool_id, current_member = sys.argv[1:]
prefixes = (
    f"principal://iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/",
    f"principalSet://iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/",
)
with open(policy_path, encoding="utf-8") as handle:
    policy = json.load(handle)
for binding in policy.get("bindings", []):
    if binding.get("role") != "roles/iam.workloadIdentityUser":
        continue
    for member in binding.get("members", []):
        if member != current_member and member.startswith(prefixes):
            print(member)
PY
  gcloud iam service-accounts remove-iam-policy-binding "$SERVICE_ACCOUNT_EMAIL" \\
    --project "$PROJECT_ID" \\
    --role roles/iam.workloadIdentityUser \\
    --member "$OBSOLETE_WIF_MEMBER" \\
    --quiet >/dev/null || true
done
rm -f "$WIF_POLICY_JSON"

gcloud iam service-accounts add-iam-policy-binding "$SERVICE_ACCOUNT_EMAIL" \\
  --project "$PROJECT_ID" \\
  --role roles/iam.workloadIdentityUser \\
  --member "$WIF_MEMBER"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \\
  --member "serviceAccount:$SERVICE_ACCOUNT_EMAIL" \\
  --role roles/bigquery.jobUser

${readDatasetSetup}
bq add-iam-policy-binding \\
  --member "serviceAccount:$SERVICE_ACCOUNT_EMAIL" \\
  --role roles/bigquery.dataViewer \\
  "$PROJECT_ID:$READ_DATASET"

bq query --project_id="$PROJECT_ID" --location="$LOCATION" --use_legacy_sql=false --dry_run \\
  "SELECT table_name FROM \\\`$PROJECT_ID.$READ_DATASET.INFORMATION_SCHEMA.TABLES\\\` LIMIT 1"

cat <<EOF
Aperio BigQuery WIF setup commands completed.

Save these values in the Aperio Google Workspace BigQuery connector:
  Project ID: $PROJECT_ID
  Dataset ID: $READ_DATASET
  Location: $LOCATION
  Service account: $SERVICE_ACCOUNT_EMAIL
  Workload identity provider: projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID
EOF
`;
}

function buildGoogleWorkspaceBigQueryWifTerraform(input: RequiredWifSetupInput) {
  const readDataset =
    input.accessMode === "views" ? input.readDatasetId : input.rawDatasetId;
  const attributeMapping: Record<string, string> = input.principalAttribute
    ? {
        "google.subject": "assertion.sub",
        [`attribute.${input.principalAttribute}`]: `assertion.${input.principalAttribute}`,
        "attribute.audience": "assertion.aud"
      }
    : {
        "google.subject": "assertion.sub",
        "attribute.audience": "assertion.aud"
      };
  const wifMember = input.principalAttribute
    ? `"principalSet://iam.googleapis.com/projects/\${data.google_project.workspace.number}/locations/global/workloadIdentityPools/\${google_iam_workload_identity_pool.aperio.workload_identity_pool_id}/attribute.${input.principalAttribute}/\${var.principal_value}"`
    : `"principal://iam.googleapis.com/projects/\${data.google_project.workspace.number}/locations/global/workloadIdentityPools/\${google_iam_workload_identity_pool.aperio.workload_identity_pool_id}/subject/\${var.principal_subject}"`;
  const attributeCondition = input.providerAttributeCondition?.trim()
    ? `\n${terraformAttribute("attribute_condition", input.providerAttributeCondition.trim())}`
    : "";
  const readDatasetResources =
    input.accessMode === "views"
      ? [
          terraformVariable(
            "raw_table_ids",
            [
              terraformAttribute(
                "description",
                'Raw Workspace export tables to mirror as authorized views, for example ["activity", "usage"].'
              ),
              terraformAttribute("type", terraformExpression("set(string)")),
              terraformAttribute("default", ["activity"])
            ].join("\n")
          ),
          terraformResource(
            "google_bigquery_dataset",
            "read_views",
            [
              terraformAttribute("project", terraformExpression("var.project_id")),
              terraformAttribute("dataset_id", terraformExpression("var.read_dataset_id")),
              terraformAttribute("friendly_name", "Aperio Workspace authorized views"),
              terraformAttribute("location", terraformExpression("var.location")),
              terraformAttribute("delete_contents_on_destroy", false)
            ].join("\n")
          ),
          terraformResource(
            "google_bigquery_table",
            "authorized_view",
            [
              terraformAttribute("for_each", terraformExpression("var.raw_table_ids")),
              terraformAttribute("project", terraformExpression("var.project_id")),
              terraformAttribute("dataset_id", terraformExpression("google_bigquery_dataset.read_views.dataset_id")),
              terraformAttribute("table_id", terraformExpression('"aperio_${each.value}"')),
              terraformBlock(
                "view",
                [],
                [
                  terraformAttribute(
                    "query",
                    terraformExpression(
                      'format("SELECT t.*, t._PARTITIONTIME AS aperio_partition_time FROM `%s.%s.%s` AS t", var.project_id, var.raw_dataset_id, each.value)'
                    )
                  ),
                  terraformAttribute("use_legacy_sql", false)
                ].join("\n")
              )
            ].join("\n")
          ),
          terraformResource(
            "google_bigquery_dataset_access",
            "authorized_view",
            [
              terraformAttribute("for_each", terraformExpression("google_bigquery_table.authorized_view")),
              terraformAttribute("project", terraformExpression("var.project_id")),
              terraformAttribute("dataset_id", terraformExpression("var.raw_dataset_id")),
              terraformBlock(
                "view",
                [],
                [
                  terraformAttribute("project_id", terraformExpression("var.project_id")),
                  terraformAttribute("dataset_id", terraformExpression("var.read_dataset_id")),
                  terraformAttribute("table_id", terraformExpression("each.value.table_id"))
                ].join("\n")
              )
            ].join("\n")
          )
        ].join("\n")
      : "";
  const readDatasetReference =
    input.accessMode === "views" ? "google_bigquery_dataset.read_views.dataset_id" : "var.raw_dataset_id";

  return `${terraformBlock(
    "terraform",
    [],
    `required_version = ">= 1.5.0"
${terraformBlock(
  "required_providers",
  [],
  terraformAttribute("google", {
    source: "hashicorp/google",
    version: ">= 5.0"
  })
)}`
)}

${terraformVariable(
  "project_id",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", input.projectId)].join("\n")
)}

${terraformVariable(
  "raw_dataset_id",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", input.rawDatasetId)].join("\n")
)}

${terraformVariable(
  "read_dataset_id",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", readDataset)].join("\n")
)}

${terraformVariable(
  "location",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", input.location)].join("\n")
)}

${terraformVariable(
  "principal_subject",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", input.principalSubject ?? "")].join("\n")
)}

${terraformVariable(
  "principal_value",
  [terraformAttribute("type", terraformExpression("string")), terraformAttribute("default", input.principalValue ?? "")].join("\n")
)}

${terraformBlock(
  "data",
  ["google_project", "workspace"],
  terraformAttribute("project_id", terraformExpression("var.project_id"))
)}

${terraformResource(
  "google_project_service",
  "required",
  [
    terraformAttribute(
      "for_each",
      terraformExpression(`toset(${terraformValue([
        "bigquery.googleapis.com",
        "iamcredentials.googleapis.com",
        "sts.googleapis.com"
      ])})`)
    ),
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute("service", terraformExpression("each.value")),
    terraformAttribute("disable_on_destroy", false)
  ].join("\n")
)}

${terraformResource(
  "google_service_account",
  "reader",
  [
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute("account_id", input.serviceAccountName),
    terraformAttribute("display_name", "Aperio BigQuery reader")
  ].join("\n")
)}

${terraformResource(
  "google_iam_workload_identity_pool",
  "aperio",
  [
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute("workload_identity_pool_id", input.poolId),
    terraformAttribute("display_name", "Aperio workloads")
  ].join("\n")
)}

${terraformResource(
  "google_iam_workload_identity_pool_provider",
  "aperio_oidc",
  [
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute(
      "workload_identity_pool_id",
      terraformExpression("google_iam_workload_identity_pool.aperio.workload_identity_pool_id")
    ),
    terraformAttribute("workload_identity_pool_provider_id", input.providerId),
    terraformAttribute("display_name", "Aperio OIDC"),
    terraformAttribute("attribute_mapping", attributeMapping) + attributeCondition,
    terraformBlock(
      "oidc",
      [],
      [
        terraformAttribute("issuer_uri", input.oidcIssuerUri),
        terraformAttribute("allowed_audiences", [input.oidcAudience])
      ].join("\n")
    )
  ].join("\n")
)}

${terraformBlock("locals", [], terraformAttribute("wif_member", terraformExpression(wifMember)))}

${terraformResource(
  "google_service_account_iam_member",
  "wif_user",
  [
    terraformAttribute("service_account_id", terraformExpression("google_service_account.reader.name")),
    terraformAttribute("role", "roles/iam.workloadIdentityUser"),
    terraformAttribute("member", terraformExpression("local.wif_member"))
  ].join("\n")
)}

${terraformResource(
  "google_project_iam_member",
  "job_user",
  [
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute("role", "roles/bigquery.jobUser"),
    terraformAttribute("member", terraformExpression('"serviceAccount:${google_service_account.reader.email}"'))
  ].join("\n")
)}

${readDatasetResources}
${terraformResource(
  "google_bigquery_dataset_iam_member",
  "reader_dataset_viewer",
  [
    terraformAttribute("project", terraformExpression("var.project_id")),
    terraformAttribute("dataset_id", terraformExpression(readDatasetReference)),
    terraformAttribute("role", "roles/bigquery.dataViewer"),
    terraformAttribute("member", terraformExpression('"serviceAccount:${google_service_account.reader.email}"'))
  ].join("\n")
)}

${terraformOutput(
  "aperio_bigquery_config",
  terraformAttribute("value", {
    project_id: terraformExpression("var.project_id"),
    raw_dataset_id: terraformExpression("var.raw_dataset_id"),
    dataset_id: terraformExpression("var.read_dataset_id"),
    location: terraformExpression("var.location"),
    service_account_email: terraformExpression("google_service_account.reader.email"),
    workload_identity_provider: terraformExpression(
      '"projects/${data.google_project.workspace.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.aperio.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.aperio_oidc.workload_identity_pool_provider_id}"'
    ),
    access_mode: input.accessMode
  })
)}
`;
}
