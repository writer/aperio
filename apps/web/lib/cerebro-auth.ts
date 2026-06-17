export const CEREBRO_API_RESOURCE = "cerebro-api";
export const CEREBRO_MCP_RESOURCE = "cerebro-mcp";
export const CEREBRO_HUMAN_AUTH_MODE = "human_workspace_session";
export const CEREBRO_SESSION_TRANSPORT = "http_only_cookie";
export const CEREBRO_MCP_RESOURCE_METADATA_PATH =
  "/.well-known/oauth-protected-resource/api/v1/mcp";
export const CEREBRO_OAUTH_AUTHORIZATION_SERVER_METADATA_PATH =
  "/.well-known/oauth-authorization-server";
export const CEREBRO_MCP_GRANT_TYPES = [
  "authorization_code",
  "refresh_token",
  "client_credentials"
] as const;
export const CEREBRO_MCP_BEARER_METHODS = ["header"] as const;

export function formatCerebroTransport(transport: string) {
  if (transport === CEREBRO_SESSION_TRANSPORT) {
    return "HttpOnly cookie";
  }
  return transport.replaceAll("_", " ");
}

export const CEREBRO_AUTH_INSIGHTS = [
  { label: "Resource", value: CEREBRO_API_RESOURCE, tone: "signal" },
  { label: "MCP resource", value: CEREBRO_MCP_RESOURCE, tone: "signal" },
  { label: "Tenant binding", value: "Required", tone: "critical" },
  {
    label: "Transport",
    value: formatCerebroTransport(CEREBRO_SESSION_TRANSPORT),
    tone: "neutral"
  }
] as const;

export const CEREBRO_AUTH_PILLARS = [
  "Resource-bound sessions",
  "Tenant and principal claims",
  "Scoped Cerebro actions"
] as const;

export function formatCerebroScope(scope: string) {
  return scope.replace(/^cerebro\./, "").replaceAll(".", " / ");
}
