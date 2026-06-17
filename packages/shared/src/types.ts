import { z } from "zod";

export const providers = [
  "GITHUB",
  "SLACK",
  "GOOGLE_WORKSPACE",
  "ONE_PASSWORD",
  "OKTA",
  "MICROSOFT_365",
  "ATLASSIAN",
  "SALESFORCE"
] as const;
export const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const findingStatuses = ["OPEN", "RESOLVED", "MUTED"] as const;

export const providerSchema = z.enum(providers);
export const severitySchema = z.enum(severities);
export const findingStatusSchema = z.enum(findingStatuses);

export const findingsQuerySchema = z.object({
  severity: severitySchema.optional(),
  status: findingStatusSchema.optional(),
  provider: providerSchema.optional(),
  integrationId: z.string().trim().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: z.string().min(1).optional()
});

export const resolveFindingSchema = z.object({
  status: z.enum(["RESOLVED", "MUTED"]).default("RESOLVED"),
  resolutionNote: z.string().trim().min(1).max(1000).optional()
});

export const ingestionPayloadSchema = z.object({
  integrationId: z.string().min(1),
  provider: providerSchema,
  eventType: z.string().trim().min(1).max(180),
  source: z.string().trim().min(1).max(180),
  actor: z.string().trim().max(255).optional(),
  occurredAt: z.string().datetime().optional(),
  payload: z.record(z.string(), z.unknown())
});

export type Provider = (typeof providers)[number];
export type Severity = (typeof severities)[number];
export type FindingStatus = (typeof findingStatuses)[number];
export type FindingsQuery = z.infer<typeof findingsQuerySchema>;
export type IngestionPayloadInput = z.infer<typeof ingestionPayloadSchema>;
