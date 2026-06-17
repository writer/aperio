# API

Aperio's HTTP API is implemented in Go. Typed ConnectRPC methods are defined in `proto/aperio/v1/api.proto`, implemented in `internal/bootstrap`, and exposed by `cmd/aperio/main.go`.

The web console still uses some REST-shaped paths such as `/api/v1/integrations` and `/api/v1/siem`; these are not served by an Express app. They are tunneled through the `CallApi` ConnectRPC method and dispatched by `internal/bootstrap/compat_api.go` while the remaining workflows move to first-class RPCs.

## Native RPC surface

| Area | Contract / implementation |
| --- | --- |
| Health and readiness | `internal/bootstrap/app.go` |
| Dashboard metrics | `GetDashboardMetrics` |
| Findings reads | `ListFindings`, `GetFinding`, lifecycle events |
| Integrations reads | `ListIntegrations` |
| SIEM reads | `ListSiemDestinations` |
| Shadow IT reads | `ListShadowItOauthApps`, `ListShadowItOauthAppGrants` |
| Security reads | assets and overview RPCs |

## Compatibility groups

| Compatibility path | Purpose |
| --- | --- |
| `/api/v1/auth/*` | Signup, login, logout, password reset, MFA, workspace switching |
| `/api/v1/admin/*` | Organization settings, members, roles, audit log |
| `/api/v1/integrations/*` | Connector catalog, creation, checks, OAuth, force-sync |
| `/api/v1/findings/*` | Mutations and exports not yet promoted to typed RPCs |
| `/api/v1/security/*` | Security graph and asset compatibility responses |
| `/api/v1/shadow-it/*` | OAuth app inventory compatibility responses |
| `/api/v1/siem/*` | SIEM catalog, CRUD, and test dispatch compatibility |
| `/api/v1/agents/*` | Agent task/message/proposal compatibility workflows |

## MCP

`internal/mcpbroker` exposes a JSON-RPC tool surface for agent workflows and SIEM enqueue operations. It shares the Prisma schema and tenant data model with the Go API but is a separate stdio runtime.

## Where to change things

- Add or promote API contracts in `proto/aperio/v1/api.proto`.
- Implement Go handlers in `internal/bootstrap`.
- Update the browser Connect client in `packages/connect/src` and `apps/web/lib/api.ts`.
- Keep MCP-specific tools in `internal/mcpbroker`.
