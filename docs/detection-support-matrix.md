# Detection support matrix

This matrix describes the payload fields the current Go ingestion worker can
actually evaluate. A connector is not treated as rule-supported merely because
credentials can be stored; the provider must enqueue one of the listed event
types with the listed fields.

| Provider | Rule | Version | Event types | Required payload fields | Auto-resolution input | Default | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GitHub | `github.public_repository_created` | `1.0.0` | `PUBLIC_REPOSITORY_CREATED`, `REPOSITORY_PUBLICIZED` (aliases accepted) | `repository.full_name`; `repository.visibility` or `repository.private` | `REPOSITORY_PRIVATE`, `REPOSITORY_PRIVATEIZED`, or `REPOSITORY_VISIBILITY_CHANGED` with private visibility | On | Declarative YAML pack; the finding target is the repository and the dedupe subject is the same repository. |
| GitHub | `github.branch_protection_disabled` | `catalog` | `BRANCH_PROTECTION_DISABLED`, `BRANCH_PROTECTION_RULE_DELETED`, `BRANCH_PROTECTION_RULE_UPDATED` | repository name; branch/ref/rule pattern when available | Not currently automatic | On | Hardcoded compatibility rule. Updated rules fire only when the payload indicates weakened settings. |
| GitHub | `github.oauth_app_installed` | `catalog` | `OAUTH_APP_INSTALLED`, `GITHUB_APP_INSTALLED`, `ORG_OAUTH_APP_ACCESS_APPROVED` | app name or ID; scopes/permissions when available | Not currently automatic | On | Payloads with no scope list are retained for review; known low-risk scoped installs are skipped. |
| GitHub | `github.deploy_key_added` | `1.0.0` catalog | `DEPLOY_KEY_ADDED`, `DEPLOY_KEY_CREATED` (aliases accepted) | repository name; key title/name/ID; `key.write_enabled` when available | Not currently automatic | Off | Existing connector catalog exposes this opt-in check. Write-enabled keys escalate to HIGH; missing write metadata remains MEDIUM. |
| Slack | `slack.mfa_disabled` | `1.0.0` | `MFA_DISABLED`, `TWO_FACTOR_AUTH_DISABLED` (aliases accepted) | `user.email` or `user.id` | `MFA_ENABLED` or `TWO_FACTOR_AUTH_ENABLED` with the same user field | On | Declarative YAML pack. The clean event is never treated as a disablement. |
| Slack | `slack.external_shared_channel_created` | `1.0.0` | `EXTERNAL_SHARED_CHANNEL_CREATED`, `SHARED_CHANNEL_INVITE_ACCEPTED` | channel name/ID; external organization/team name | Not currently automatic | On | Declarative YAML pack; the finding is emitted only when both channel and external-organization identity are present. |
| Slack | `slack.workspace_invite_link_enabled` | `catalog` | `WORKSPACE_INVITE_LINK_ENABLED`, `INVITE_LINK_CREATED` | workspace/team name when available | Not currently automatic | On | Hardcoded compatibility rule. |
| Slack | `slack.app_installed` | `catalog` | `APP_INSTALLED`, `APP_APPROVED`, `APP_SCOPES_APPROVED` | app name/ID; scopes when available | Not currently automatic | Off | Existing rule escalates to HIGH when scopes include admin, file-history, or channel-history access; no claim is made when scope data is absent. |
| Google Workspace | `google_workspace.external_sharing_enabled` | `1.0.0` | `EXTERNAL_SHARING_ENABLED` | `parameters.visibility`; document title/id/type/owner when available | `EXTERNAL_SHARING_DISABLED`, `DRIVE_FILE_VISIBILITY_CHANGED`, or `DRIVE_FILE_PRIVATE` with private/domain/internal visibility | On | Declarative YAML pack supports both resource metadata and Reports API parameter shapes. |

## Tenant overrides

The worker already reads `integration_connections.disabled_checks`. A severity
override can be stored in the existing `disabled_check_metadata` JSON object
without a new table:

```json
{
  "slack.mfa_disabled": {
    "reason": "tenant risk policy",
    "severity": "HIGH",
    "expiresAt": "2026-12-31T00:00:00Z"
  }
}
```

Only `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO` are accepted. Expired or
malformed entries are ignored. Disabling a rule still uses the existing
`disabled_checks` array and its expiry behavior.

## Known gaps

- GitHub secret-scanning alerts, dependabot alerts, membership changes, and
  webhook delivery are not advertised here because this checkout does not
  currently normalize those provider payloads into supported ingestion event
  types.
- Slack message/file export volume, guest lifecycle, and user deactivation are
  not advertised because the available payload contract does not guarantee the
  required fields.
- Rule efficacy rollups, persisted `rule_version` columns, community-pack
  signatures, and stateful/correlation rules remain follow-up work. The
  evaluator emits versioned drafts now so those consumers can be added without
  changing rule semantics.
