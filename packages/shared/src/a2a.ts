import { z } from "zod";

export const agentKindSchema = z.enum([
  "MCP_BROKER",
  "SSPM_SCANNER",
  "SIEM_DISPATCHER",
  "REMEDIATION_PLANNER",
  "HUMAN_REVIEW",
  "CUSTOM"
]);

export const agentStatusSchema = z.enum(["ACTIVE", "PAUSED", "ERROR"]);

export const agentTaskStatusSchema = z.enum([
  "QUEUED",
  "RUNNING",
  "WAITING_FOR_APPROVAL",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED"
]);

export const agentMessageRoleSchema = z.enum([
  "SYSTEM",
  "AGENT",
  "USER",
  "TOOL"
]);

export const agentProposalStatusSchema = z.enum([
  "PROPOSED",
  "APPROVED",
  "REJECTED",
  "EXECUTED",
  "FAILED"
]);

export const jsonRecordSchema = z.record(z.string(), z.unknown());

export const registerAgentSchema = z
  .object({
    key: z.string().trim().min(2).max(120),
    name: z.string().trim().min(2).max(160),
    kind: agentKindSchema.default("CUSTOM"),
    capabilities: z.array(z.string().trim().min(1).max(120)).default([]),
    endpointUrl: z.string().trim().url().max(500).optional(),
    mcpServerUrl: z.string().trim().url().max(500).optional(),
    status: agentStatusSchema.default("ACTIVE")
  })
  .strict();

export const createAgentTaskSchema = z
  .object({
    taskType: z.string().trim().min(2).max(120),
    title: z.string().trim().min(2).max(220),
    input: jsonRecordSchema.default({}),
    createdByAgentKey: z.string().trim().min(2).max(120).optional(),
    assignedAgentKey: z.string().trim().min(2).max(120).optional(),
    parentTaskId: z.string().trim().min(1).optional()
  })
  .strict();

export const updateAgentTaskSchema = z
  .object({
    status: agentTaskStatusSchema.optional(),
    output: jsonRecordSchema.optional(),
    error: z.string().trim().max(1000).optional(),
    assignedAgentKey: z.string().trim().min(2).max(120).optional()
  })
  .strict();

export const sendAgentMessageSchema = z
  .object({
    taskId: z.string().trim().min(1).optional(),
    fromAgentKey: z.string().trim().min(2).max(120).optional(),
    toAgentKey: z.string().trim().min(2).max(120).optional(),
    role: agentMessageRoleSchema.default("AGENT"),
    messageType: z.string().trim().min(2).max(120).default("a2a.message.v1"),
    correlationId: z.string().trim().min(1).max(160).optional(),
    content: jsonRecordSchema
  })
  .strict();

export const createAgentProposalSchema = z
  .object({
    taskId: z.string().trim().min(1).optional(),
    findingId: z.string().trim().min(1).optional(),
    proposedByAgentKey: z.string().trim().min(2).max(120).optional(),
    action: z.string().trim().min(2).max(160),
    rationale: z.string().trim().min(2).max(4000),
    payload: jsonRecordSchema
  })
  .strict();

export const decideAgentProposalSchema = z
  .object({
    decision: z.enum(["APPROVED", "REJECTED"]),
    note: z.string().trim().max(1000).optional()
  })
  .strict();

export const enqueueSiemPayloadSchema = z
  .object({
    kind: z.enum(["finding", "event", "audit_log"]).default("finding"),
    organizationId: z.string().trim().min(1),
    occurredAt: z.string().trim().datetime().optional(),
    record: jsonRecordSchema
  })
  .strict();

export type RegisterAgentInput = z.infer<typeof registerAgentSchema>;
export type CreateAgentTaskInput = z.infer<typeof createAgentTaskSchema>;
export type UpdateAgentTaskInput = z.infer<typeof updateAgentTaskSchema>;
export type SendAgentMessageInput = z.infer<typeof sendAgentMessageSchema>;
export type CreateAgentProposalInput = z.infer<
  typeof createAgentProposalSchema
>;
