CREATE TABLE "google_workspace_bigquery_sync_cursors" (
  "integration_id" TEXT NOT NULL,
  "record_type" VARCHAR(64) NOT NULL,
  "last_event_time" TIMESTAMP(3) NOT NULL,
  "last_row_hash" VARCHAR(64) NOT NULL DEFAULT '',
  "last_polled_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "last_row_count" INTEGER NOT NULL DEFAULT 0,
  "last_error" VARCHAR(500),

  CONSTRAINT "google_workspace_bigquery_sync_cursors_pkey" PRIMARY KEY ("integration_id", "record_type"),
  CONSTRAINT "google_workspace_bigquery_sync_cursors_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
