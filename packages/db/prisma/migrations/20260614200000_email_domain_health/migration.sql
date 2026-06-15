CREATE TABLE "email_domain_health_checks" (
  "id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "domain" VARCHAR(255) NOT NULL,
  "provider_sources" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  "status" VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
  "score" INTEGER NOT NULL DEFAULT 0,
  "spf_status" VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
  "dkim_status" VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
  "dmarc_status" VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
  "issue_count" INTEGER NOT NULL DEFAULT 0,
  "failing_issue_count" INTEGER NOT NULL DEFAULT 0,
  "payload" JSONB NOT NULL DEFAULT '{}'::jsonb,
  "last_checked_at" TIMESTAMP(3) NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "email_domain_health_checks_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "email_domain_health_checks"
  ADD CONSTRAINT "email_domain_health_checks_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE UNIQUE INDEX "email_domain_health_checks_organization_id_domain_key"
  ON "email_domain_health_checks"("organization_id", "domain");

CREATE INDEX "email_domain_health_checks_org_status_score_idx"
  ON "email_domain_health_checks"("organization_id", "status", "score");

CREATE INDEX "email_domain_health_checks_org_last_checked_at_idx"
  ON "email_domain_health_checks"("organization_id", "last_checked_at");

CREATE TABLE "email_domain_health_runs" (
  "id" TEXT NOT NULL,
  "check_id" TEXT NOT NULL,
  "organization_id" TEXT NOT NULL,
  "domain" VARCHAR(255) NOT NULL,
  "status" VARCHAR(16) NOT NULL,
  "score" INTEGER NOT NULL,
  "issue_count" INTEGER NOT NULL,
  "payload" JSONB NOT NULL DEFAULT '{}'::jsonb,
  "checked_at" TIMESTAMP(3) NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "email_domain_health_runs_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "email_domain_health_runs"
  ADD CONSTRAINT "email_domain_health_runs_check_id_fkey"
  FOREIGN KEY ("check_id") REFERENCES "email_domain_health_checks"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "email_domain_health_runs"
  ADD CONSTRAINT "email_domain_health_runs_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "email_domain_health_runs_check_id_checked_at_idx"
  ON "email_domain_health_runs"("check_id", "checked_at");

CREATE INDEX "email_domain_health_runs_org_checked_at_idx"
  ON "email_domain_health_runs"("organization_id", "checked_at");
