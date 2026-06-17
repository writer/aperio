-- CreateEnum
CREATE TYPE "SaasIncidentStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED');

-- CreateEnum
CREATE TYPE "SaasIncidentTimelineKind" AS ENUM ('DETECTION', 'CEREBRO_CONTEXT', 'INVESTIGATION', 'RESPONSE_ACTION', 'STATUS_CHANGE', 'NOTE');

-- CreateEnum
CREATE TYPE "SaasResponseActionKind" AS ENUM ('REVOKE_OAUTH_GRANT', 'SUSPEND_USER', 'RESET_MFA', 'REVOKE_SESSION', 'REMOVE_EXTERNAL_SHARE', 'DISABLE_FORWARDING', 'REMOVE_ADMIN_ROLE', 'QUARANTINE_APP', 'OPEN_TICKET', 'NOTIFY_SECOPS');

-- CreateEnum
CREATE TYPE "SaasResponseActionStatus" AS ENUM ('PROPOSED', 'APPROVED', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED');

-- CreateTable
CREATE TABLE "saas_incidents" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "title" VARCHAR(220) NOT NULL,
    "summary" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "SaasIncidentStatus" NOT NULL DEFAULT 'OPEN',
    "confidence_score" INTEGER NOT NULL DEFAULT 50,
    "owner_team" VARCHAR(160),
    "assignee_user_id" TEXT,
    "first_detected_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_activity_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sla_due_at" TIMESTAMP(3),
    "resolved_at" TIMESTAMP(3),
    "cerebro_context" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "saas_incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "saas_incident_findings" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "incident_id" TEXT NOT NULL,
    "finding_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "saas_incident_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "saas_incident_timeline_events" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "incident_id" TEXT NOT NULL,
    "finding_id" TEXT,
    "response_action_id" TEXT,
    "kind" "SaasIncidentTimelineKind" NOT NULL,
    "title" VARCHAR(220) NOT NULL,
    "description" TEXT NOT NULL,
    "actor" VARCHAR(255),
    "source" VARCHAR(120) NOT NULL DEFAULT 'APERIO',
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "occurred_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "saas_incident_timeline_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "saas_response_actions" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "incident_id" TEXT NOT NULL,
    "finding_id" TEXT,
    "action" "SaasResponseActionKind" NOT NULL,
    "provider" "SaaSProvider",
    "target_type" VARCHAR(120) NOT NULL,
    "target_identifier" VARCHAR(255) NOT NULL,
    "status" "SaasResponseActionStatus" NOT NULL DEFAULT 'PROPOSED',
    "approval_required" BOOLEAN NOT NULL DEFAULT true,
    "rationale" TEXT NOT NULL,
    "approved_by_user_id" TEXT,
    "approved_at" TIMESTAMP(3),
    "executed_at" TIMESTAMP(3),
    "error_message" VARCHAR(1000),
    "result" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "saas_response_actions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "saas_incidents_organization_id_status_severity_idx" ON "saas_incidents"("organization_id", "status", "severity");

-- CreateIndex
CREATE INDEX "saas_incidents_organization_id_last_activity_at_idx" ON "saas_incidents"("organization_id", "last_activity_at");

-- CreateIndex
CREATE INDEX "saas_incidents_organization_id_assignee_user_id_idx" ON "saas_incidents"("organization_id", "assignee_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "saas_incident_findings_incident_id_finding_id_key" ON "saas_incident_findings"("incident_id", "finding_id");

-- CreateIndex
CREATE INDEX "saas_incident_findings_organization_id_incident_id_idx" ON "saas_incident_findings"("organization_id", "incident_id");

-- CreateIndex
CREATE INDEX "saas_incident_findings_organization_id_finding_id_idx" ON "saas_incident_findings"("organization_id", "finding_id");

-- CreateIndex
CREATE INDEX "saas_incident_timeline_events_organization_id_incident_id_occurred_at_idx" ON "saas_incident_timeline_events"("organization_id", "incident_id", "occurred_at");

-- CreateIndex
CREATE INDEX "saas_incident_timeline_events_organization_id_finding_id_idx" ON "saas_incident_timeline_events"("organization_id", "finding_id");

-- CreateIndex
CREATE INDEX "saas_incident_timeline_events_organization_id_response_action_id_idx" ON "saas_incident_timeline_events"("organization_id", "response_action_id");

-- CreateIndex
CREATE INDEX "saas_response_actions_organization_id_incident_id_status_idx" ON "saas_response_actions"("organization_id", "incident_id", "status");

-- CreateIndex
CREATE INDEX "saas_response_actions_organization_id_finding_id_idx" ON "saas_response_actions"("organization_id", "finding_id");

-- CreateIndex
CREATE INDEX "saas_response_actions_organization_id_status_created_at_idx" ON "saas_response_actions"("organization_id", "status", "created_at");

-- AddForeignKey
ALTER TABLE "saas_incidents" ADD CONSTRAINT "saas_incidents_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incidents" ADD CONSTRAINT "saas_incidents_assignee_user_id_fkey" FOREIGN KEY ("assignee_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_findings" ADD CONSTRAINT "saas_incident_findings_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_findings" ADD CONSTRAINT "saas_incident_findings_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "saas_incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_findings" ADD CONSTRAINT "saas_incident_findings_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "security_findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_timeline_events" ADD CONSTRAINT "saas_incident_timeline_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_timeline_events" ADD CONSTRAINT "saas_incident_timeline_events_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "saas_incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_timeline_events" ADD CONSTRAINT "saas_incident_timeline_events_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "security_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_timeline_events" ADD CONSTRAINT "saas_incident_timeline_events_response_action_id_fkey" FOREIGN KEY ("response_action_id") REFERENCES "saas_response_actions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "saas_incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "security_findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_approved_by_user_id_fkey" FOREIGN KEY ("approved_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
