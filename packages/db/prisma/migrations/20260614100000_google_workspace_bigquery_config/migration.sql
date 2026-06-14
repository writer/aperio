ALTER TABLE "integration_connections"
    ADD COLUMN "google_workspace_bigquery_project_id" VARCHAR(255),
    ADD COLUMN "google_workspace_bigquery_raw_dataset_id" VARCHAR(255),
    ADD COLUMN "google_workspace_bigquery_dataset_id" VARCHAR(255),
    ADD COLUMN "google_workspace_bigquery_location" VARCHAR(64),
    ADD COLUMN "google_workspace_bigquery_service_account_email" VARCHAR(320),
    ADD COLUMN "google_workspace_bigquery_wif_provider" VARCHAR(500),
    ADD COLUMN "google_workspace_bigquery_access_mode" VARCHAR(32);
