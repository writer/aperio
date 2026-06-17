export const CEREBRO_API_RESOURCE = "cerebro-api";
export const CEREBRO_MCP_RESOURCE = "cerebro-mcp";
export const CEREBRO_HUMAN_AUTH_MODE = "human_workspace_session";
export const CEREBRO_SESSION_TRANSPORT = "http_only_cookie";

export const CEREBRO_AUTH_INSIGHTS = [
  { label: "Resource", value: CEREBRO_API_RESOURCE, tone: "signal" },
  { label: "Tenant binding", value: "Required", tone: "critical" },
  { label: "Transport", value: "HttpOnly cookie", tone: "neutral" }
] as const;

export const CEREBRO_AUTH_PILLARS = [
  "Resource-bound sessions",
  "Tenant and principal claims",
  "Scoped Cerebro actions"
] as const;

export function formatCerebroScope(scope: string) {
  return scope.replace(/^cerebro\./, "").replaceAll(".", " / ");
}
