-- Durable connector and rule execution receipts. Both tables carry the
-- organization key so every operator query can enforce the tenant boundary.
CREATE TYPE "ConnectorSyncRunStatus" AS ENUM ('RUNNING', 'SUCCEEDED', 'FAILED');
CREATE TYPE "RuleRunStatus" AS ENUM ('RUNNING', 'SUCCEEDED', 'FAILED');

CREATE TABLE "connector_sync_runs" (
  "id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "provider" "SaaSProvider" NOT NULL,
  "source" VARCHAR(80) NOT NULL,
  "status" "ConnectorSyncRunStatus" NOT NULL DEFAULT 'RUNNING',
  "records_seen" INTEGER NOT NULL DEFAULT 0,
  "records_queued" INTEGER NOT NULL DEFAULT 0,
  "error_message" VARCHAR(500),
  "started_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completed_at" TIMESTAMP(3),
  "duration_ms" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "connector_sync_runs_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "rule_runs" (
  "id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "integration_id" TEXT NOT NULL,
  "ingestion_job_id" TEXT,
  "provider" "SaaSProvider" NOT NULL,
  "rule_key" VARCHAR(120) NOT NULL,
  "rule_version" VARCHAR(32) NOT NULL DEFAULT 'v1',
  "status" "RuleRunStatus" NOT NULL DEFAULT 'RUNNING',
  "rules_evaluated" INTEGER NOT NULL DEFAULT 0,
  "findings_count" INTEGER NOT NULL DEFAULT 0,
  "error_message" VARCHAR(500),
  "started_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completed_at" TIMESTAMP(3),
  "duration_ms" INTEGER,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "rule_runs_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "connector_sync_runs"
  ADD CONSTRAINT "connector_sync_runs_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "connector_sync_runs_integration_id_fkey"
  FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "rule_runs"
  ADD CONSTRAINT "rule_runs_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "rule_runs_integration_id_fkey"
  FOREIGN KEY ("integration_id") REFERENCES "integration_connections"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "connector_sync_runs_organization_id_started_at_idx"
  ON "connector_sync_runs"("organization_id", "started_at");
CREATE INDEX "connector_sync_runs_organization_id_integration_id_started_at_idx"
  ON "connector_sync_runs"("organization_id", "integration_id", "started_at");
CREATE INDEX "connector_sync_runs_organization_id_integration_id_source_started_at_idx"
  ON "connector_sync_runs"("organization_id", "integration_id", "source", "started_at");
CREATE INDEX "connector_sync_runs_integration_id_status_started_at_idx"
  ON "connector_sync_runs"("integration_id", "status", "started_at");
CREATE INDEX "rule_runs_organization_id_started_at_idx"
  ON "rule_runs"("organization_id", "started_at");
CREATE INDEX "rule_runs_organization_id_rule_key_started_at_idx"
  ON "rule_runs"("organization_id", "rule_key", "started_at");
CREATE INDEX "rule_runs_organization_id_ingestion_job_id_idx"
  ON "rule_runs"("organization_id", "ingestion_job_id");
