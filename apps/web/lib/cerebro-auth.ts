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

export type CerebroAuthInsight = {
  label: string;
  value: string;
  tone: "critical" | "neutral" | "signal";
};

type CerebroProtectedResourceMetadata = {
  resource?: unknown;
  bearer_methods_supported?: unknown;
  scopes_supported?: unknown;
};

type CerebroAuthorizationServerMetadata = {
  issuer?: unknown;
  grant_types_supported?: unknown;
};

export function formatCerebroTransport(transport: string) {
  if (transport === CEREBRO_SESSION_TRANSPORT) {
    return "HttpOnly cookie";
  }
  return transport.replaceAll("_", " ");
}

export const CEREBRO_AUTH_INSIGHTS = [
  { label: "Resource", value: CEREBRO_API_RESOURCE, tone: "signal" },
  { label: "MCP resource", value: CEREBRO_MCP_RESOURCE, tone: "signal" },
  { label: "OAuth issuer", value: "Cerebro discovery", tone: "critical" },
  { label: "Grants", value: formatGrantTypes(CEREBRO_MCP_GRANT_TYPES), tone: "neutral" },
  { label: "Bearer", value: formatBearerMethods(CEREBRO_MCP_BEARER_METHODS), tone: "neutral" },
  {
    label: "Transport",
    value: formatCerebroTransport(CEREBRO_SESSION_TRANSPORT),
    tone: "neutral"
  }
] as const satisfies readonly CerebroAuthInsight[];

export const CEREBRO_AUTH_PILLARS = [
  "Resource-bound sessions",
  "Tenant and principal claims",
  "Scoped Cerebro actions"
] as const;

export function formatCerebroScope(scope: string) {
  return scope.replace(/^cerebro\./, "").replaceAll(".", " / ");
}

export async function loadCerebroAuthInsights(): Promise<
  readonly CerebroAuthInsight[]
> {
  const [resourceMetadata, authorizationMetadata] = await Promise.all([
    readDiscoveryJSON<CerebroProtectedResourceMetadata>(
      CEREBRO_MCP_RESOURCE_METADATA_PATH
    ),
    readDiscoveryJSON<CerebroAuthorizationServerMetadata>(
      CEREBRO_OAUTH_AUTHORIZATION_SERVER_METADATA_PATH
    )
  ]);

  if (!resourceMetadata && !authorizationMetadata) {
    return CEREBRO_AUTH_INSIGHTS;
  }

  const mcpResource = stringValue(
    resourceMetadata?.resource,
    CEREBRO_MCP_RESOURCE
  );
  const issuer = stringValue(
    authorizationMetadata?.issuer,
    "Cerebro discovery"
  );
  const grantTypes = stringList(
    authorizationMetadata?.grant_types_supported,
    CEREBRO_MCP_GRANT_TYPES
  );
  const bearerMethods = stringList(
    resourceMetadata?.bearer_methods_supported,
    CEREBRO_MCP_BEARER_METHODS
  );

  return [
    { label: "Resource", value: CEREBRO_API_RESOURCE, tone: "signal" },
    { label: "MCP resource", value: mcpResource, tone: "signal" },
    { label: "OAuth issuer", value: issuer, tone: "critical" },
    { label: "Grants", value: formatGrantTypes(grantTypes), tone: "neutral" },
    {
      label: "Bearer",
      value: formatBearerMethods(bearerMethods),
      tone: "neutral"
    },
    {
      label: "Transport",
      value: formatCerebroTransport(CEREBRO_SESSION_TRANSPORT),
      tone: "neutral"
    }
  ];
}

async function readDiscoveryJSON<T>(path: string): Promise<T | null> {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    const response = await fetch(path, {
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        Accept: "application/json"
      }
    });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

function stringValue(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function stringList(
  value: unknown,
  fallback: readonly string[]
): readonly string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const strings = value.filter(
    (item): item is string => typeof item === "string" && item.trim() !== ""
  );
  return strings.length ? strings : fallback;
}

function formatGrantTypes(grantTypes: readonly string[]) {
  return grantTypes
    .map((grantType) => {
      if (grantType === "authorization_code") return "Auth code";
      if (grantType === "refresh_token") return "Refresh";
      if (grantType === "client_credentials") return "Client creds";
      return grantType.replaceAll("_", " ");
    })
    .join(" / ");
}

function formatBearerMethods(methods: readonly string[]) {
  return methods
    .map((method) => {
      if (method === "header") return "HTTP header";
      return method.replaceAll("_", " ");
    })
    .join(" / ");
}
