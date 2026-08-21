# Declarative detection rules

The built-in pack is embedded from `rules/*.yaml` and compiled once when the
ingestion worker starts evaluating a job. `LoadPack` can validate an external
directory for a bounded backtest or a future rule-management API.

Each rule has a stable `id` and semantic `version`. `source` is an allow-list
for provider/event types; `when.expression` is CEL evaluated with only these
bindings:

- `event`: immutable event metadata and provider payload
- `org.config`: non-secret tenant configuration supplied by the caller
- `org.allowlists`: non-secret tenant allowlists supplied by the caller
- `now`: RFC3339 timestamp for deterministic evaluation

Finding strings and evidence use a logic-free template subset. Dotted paths,
`first_nonempty(path, path, ...)`, and
`external_recipient(path, path, owner_path)` are supported. Templates cannot
call CEL, access the filesystem, or execute Go code. Unknown YAML fields,
invalid semantic versions, invalid severities, oversized expressions, and
duplicate rule IDs are rejected before compilation. A pack has one active
semantic version per rule ID; replacing a rule version is an explicit pack
rollout rather than an in-place overlap.

`auto_resolve_when` emits a resolution draft only. Persistence must scope the
state transition by `organization_id`, `integration_id`, rule ID, and rendered
dedupe target; the evaluator never mutates storage.

The evaluator exposes version-aware dedupe material for backtests. The current
worker preserves the existing persisted ID-plus-target hash during migration
and records the rule version in finding evidence; changing that database key
requires a separate collision/backfill rollout.

The JSON schema in `rule.schema.json` is a portable authoring contract. The Go
loader additionally compiles every expression, which catches CEL errors before
activation.
