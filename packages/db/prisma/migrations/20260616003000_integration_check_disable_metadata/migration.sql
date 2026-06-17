ALTER TABLE "integration_connections"
  ADD COLUMN "disabled_check_metadata" JSONB NOT NULL DEFAULT '{}'::jsonb;
