-- AlterTable
ALTER TABLE "saas_response_actions" ADD COLUMN "proposed_by_user_id" TEXT;

-- AlterTable
ALTER TABLE "saas_response_actions" ADD COLUMN "executed_by_user_id" TEXT;

-- AlterTable
ALTER TABLE "saas_incident_findings" ADD COLUMN "linked_by_user_id" TEXT;

-- CreateIndex
CREATE INDEX "saas_response_actions_organization_id_proposed_by_user_id_idx" ON "saas_response_actions"("organization_id", "proposed_by_user_id");

-- CreateIndex
CREATE INDEX "saas_response_actions_organization_id_executed_by_user_id_idx" ON "saas_response_actions"("organization_id", "executed_by_user_id");

-- CreateIndex
CREATE INDEX "saas_incident_findings_organization_id_linked_by_user_id_idx" ON "saas_incident_findings"("organization_id", "linked_by_user_id");

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_proposed_by_user_id_fkey" FOREIGN KEY ("proposed_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_response_actions" ADD CONSTRAINT "saas_response_actions_executed_by_user_id_fkey" FOREIGN KEY ("executed_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "saas_incident_findings" ADD CONSTRAINT "saas_incident_findings_linked_by_user_id_fkey" FOREIGN KEY ("linked_by_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
