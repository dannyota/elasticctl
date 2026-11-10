[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 7. API reuse

MCP calls the plan and apply functions the CLI calls. It adds no route. The
plan store, the hash, and the confirmation step are frontend state and live
in `-mcp`. Reading the stack and deciding what a plan means live in `-api`.

Three things are missing from `-api` today:

1. A planner returns preview text, not the state it read. MCP needs that
   state to bind a plan.
2. No function re-reads the state of named objects for a later check.
3. No plan and apply pair creates one rule from an inline value, and no
   public function returns the credential identity.

All additions are new functions, with two exceptions stated below: the case
status conflict keeps its HTTP status, and core gains one transport option.
No existing signature, request body, or error text changes.

| Kind | Planner | Re-check | Apply |
| --- | --- | --- | --- |
| `rules_set_enabled` | `rules_ops::plan_set_enabled_observed` (new) | `rules_ops::observe_rules` (new) | `rules_ops::apply_set_enabled` |
| `alerts_set_status` | `alerts_ops::plan_status_by_ids_observed` (new) | `alerts_ops::observe_alerts` with `AlertFacet::Status` (new) | `alerts_ops::apply_status_by_ids` |
| `alerts_set_tags` | `alerts_ops::plan_tags_observed` (new) | `alerts_ops::observe_alerts` with `AlertFacet::Presence` (new) | `alerts_ops::apply_tags` |
| `cases_create` | `cases_ops::plan_create` with `assignees: &[]` | None | `cases_ops::apply_create` |
| `cases_comment` | `cases_ops::plan_comment_observed` (new) | `cases_ops::observe_cases` with `with_version: false` (new) | `cases_ops::apply_comment` |
| `cases_set_status` | `cases_ops::plan_status_observed` (new) | `cases_ops::observe_cases` with `with_version: true` (new) | `cases_ops::apply_status` |
| `rules_create` | `rules_ops::plan_create` (new) | `rules_ops::observe_rules` | `rules_ops::apply_create` (new) |
| every kind | `health::credential_identity` (new) | the same | - |

### Shared types

New module `crates/elasticctl-api/src/observe.rs`, exported from `lib.rs`:

```rust
/// One object's state as read from the stack, in comparison form.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Observed {
    /// "rule", "alert", or "case".
    pub object: &'static str,
    pub id: String,
    /// `None` when the object does not exist.
    pub state: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct Preconditions(pub Vec<Observed>);

impl Preconditions {
    /// Order by `object`, then `id`.
    pub fn sorted(self) -> Self;
}

/// Fail with kind `conflict` unless every `rule` entry that has a state
/// carries a `rule_id` byte-equal to its `id`.
pub fn require_rule_identity(seen: &Preconditions) -> Result<()>;
```

`require_rule_identity` is a separate function, not part of the planners,
so the CLI path is unchanged. `-mcp` calls it after the planner and after
each `observe_rules`.

### Rules

New child modules under `crates/elasticctl-api/src/rules_ops/`, re-exported
from `rules_ops`: `observed.rs` (the planner), `recheck.rs`
(`observe_rules`), and `create.rs`:

```rust
pub async fn plan_set_enabled_observed(
    t: &Transport, selectors: &[String], enable: bool,
) -> Result<(MutationPlan, Preconditions)>;

pub async fn observe_rules(t: &Transport, rule_ids: &[String]) -> Result<Preconditions>;

#[derive(Debug, Clone, PartialEq)]
pub struct RuleCreatePlan { pub rule: Rule, pub preview: MutationPlan }

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleCreateOutcome { pub applied: bool, pub rule_id: String, pub enabled: bool }

pub async fn plan_create(t: &Transport, rule: Rule) -> Result<(RuleCreatePlan, Preconditions)>;
pub async fn apply_create(t: &Transport, plan: &RuleCreatePlan) -> Result<RuleCreateOutcome>;
```

- `plan_set_enabled_observed` holds the body of today's `plan_set_enabled`.
  It builds each `Observed` from the `(rule_id, Rule)` pairs that
  `resolve_targets` already returns, with
  `state = Some(normalize::canonical(rule).into_value())`.
  `plan_set_enabled` becomes a call to it that drops the second value.
- `observe_rules` calls `rules::get` per id. `NotFound` gives `state: None`.
  Any other error is returned. `selection::to_rule` and `rules::get` use the
  same route, so both states compare exactly.
- A read by `rule_id` does not prove identity on its own, because the route
  matches through KQL and KQL decodes escapes. Planning keeps using
  `selection::to_rule`, which reads again by the stored id when the returned
  id differs from the selector. `observe_rules` returns what the route
  returned, with `id` set to the id it asked for, and
  `require_rule_identity` then rejects any entry whose state names another
  rule.
- `plan_create` refuses, before any request: an unreadable `rule_id`, a
  missing or non-string `name` or `type`, `enabled: true`, any key in
  `VOLATILE_FIELDS` (kind `error`); a non-empty `exceptions_list`, `actions`,
  or `response_actions` (kind `unsupported`). It sets `enabled` to `false`,
  reads the rule by id, and returns kind `conflict` when it exists.
  Preconditions are one `Observed { object: "rule", id, state: None }`.
- `plan_create` preview: action `Create 1 rule (disabled)`; targets
  `[rule_id]`; details are one line per top-level key of the stored rule, in
  byte order of the key, as `<key>: <value>`. `<value>` is compact JSON with
  nested keys sorted, so a string is quoted and escaped and no value spans
  lines. `<key>` is the key's JSON string escape without the surrounding
  quotes, so a key that holds a quote, a backslash, or a control character
  cannot break the line either. Every key is rendered, including `rule_id`,
  `enabled`, and keys this version does not know. There is no summary line and no omitted field: a
  field such as `threat_query`, `filters`, or `threshold` appears in full
  like `query` does.
- `plan_create` does not cap the size of the preview. The caller that shows
  it does: `-mcp` renders the consent text from these details and refuses
  the plan when the result exceeds 8,192 bytes
  ([section 5.4](05-plans.md#54-states-expiry-and-limits)).
- `apply_create` repeats every local refusal of `plan_create` on the plan's
  rule, and also requires `enabled` to be `false`, before any request,
  because the plan's fields are public and can change after planning. It
  then calls `rules::create`. It returns kind `http` when the response
  `rule_id` differs from the plan or `enabled` is not `false`.

### Alerts

New child modules under `crates/elasticctl-api/src/alerts_ops/`:
`observed.rs` (the planners) and `recheck.rs` (`observe_alerts`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFacet { Status, Presence }

pub async fn plan_status_by_ids_observed(
    t: &Transport, ids: &[String], status: AlertStatus, reason: Option<String>,
) -> Result<(StatusPlan, Preconditions)>;

pub async fn plan_tags_observed(
    t: &Transport, ids: &[String], add: Vec<String>, remove: Vec<String>,
) -> Result<(TagsPlan, Preconditions)>;

pub async fn observe_alerts(
    t: &Transport, ids: &[String], facet: AlertFacet,
) -> Result<Preconditions>;
```

The two planners use the existing private `resolve_ids`, which fails when an
id is missing. `ResolvedAlert` already carries `status`. `Status` gives
`state = {"workflow_status": status}`; `Presence` gives `{}`.
`observe_alerts` sends the same search body, taken from one private builder
that `resolve_ids` also calls, and gives `state: None` for an id with no hit
instead of failing. `plan_status_by_ids` and `plan_tags` become calls to the
observed forms. No new request shape reaches the stack.

### Cases

New child modules under `crates/elasticctl-api/src/cases_ops/`:
`observed.rs` (the planners) and `recheck.rs` (`observe_cases`):

```rust
pub async fn plan_status_observed(
    t: &Transport, ids: &[String], target: CaseStatus,
) -> Result<(StatusPlan, Preconditions)>;

pub async fn plan_comment_observed(
    t: &Transport, case_id: &str, message: &str,
) -> Result<(CommentPlan, Preconditions)>;

pub async fn observe_cases(
    t: &Transport, ids: &[String], with_version: bool,
) -> Result<Preconditions>;
```

State is `{"status", "title"}`. When `with_version` is true it also has
`"version"` and `"sync_alerts"`. `sync_alerts` is decoded strictly from the
case's `settings.syncAlerts`: a JSON boolean is kept, and a missing
`settings`, a missing key, or any other type is `null`. The observed status
planner reads it from the same `cases::get` response through a private
sibling of `resolve_cases` that returns the decoded `Case`; the requests do
not change. `-api` reports the value and does not refuse; the refusal is in
`-mcp` ([section 5.3](05-plans.md#53-drift)), so the CLI is unchanged.
`observe_cases` calls `cases::get` per id and gives `state: None` on
`NotFound`. `plan_status` and `plan_comment` become calls to the observed
forms. `cases_ops::plan_create` is used as it is; with no assignees it makes
no profile lookup.

One existing behavior changes. `cases_ops::apply_status` rewraps a version
conflict from `cases::patch_status` with `Error::new`, which drops the HTTP
status. It will keep it: the rewrapped error carries the original
`http_status`, 409, with the same kind and message. Without the status a
conflict would be classified `unknown` instead of `stale`
([section 8.2](08-apply-errors-and-cancellation.md#82-classifying-the-write)).
The CLI effect is additive: the error object of a conflicting `cases close`
or `cases open` gains `"http_status": 409`, which shared design 11.1 allows
in a patch. It is the only CLI-visible change in 0.9.

### Identity

In `crates/elasticctl-api/src/health.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIdentity {
    pub username: String,
    pub realm_type: String,
    pub api_key_id: Option<String>,
}

pub async fn credential_identity(t: &Transport) -> Result<CredentialIdentity>;
```

It reads `/_security/_authenticate` and keeps the existing fail-closed decode
of `username` and `authentication_realm.type`. `api_key.id` is optional; a
present value of the wrong type is an `http` error. The private `identity`
that `doctor` uses becomes a call to it. `doctor` output does not change.

### What stays in `-mcp`

- `MutationClasses`, the plan store, canonical bytes and the hash, ids and
  handles, the consent text, both confirmation paths, the outcome
  projection, the error codes, and the audit lines.
- The projection from each typed `-api` plan to `operation`, and from each
  `-api` report to the outcome ([section 8.4](08-apply-errors-and-cancellation.md#84-results-and-audit-trail)).
- A lazy mutation transport, used only for the write. Planners and checks
  use the ordinary MCP transport with its bounded retries.

`-mcp` adds direct dependencies on `sha2` and `getrandom`, both already in
`Cargo.lock`, and the `elicitation` feature of `rmcp`. `-mcp` still does not
depend on the CLI crate, and no `clap` type enters it.

### One request per write, in `-core`

`TransportOptions { disable_retries: true }` is not enough for a write.
It limits the application retry loop to one attempt and sets the `reqwest`
retry policy to never, but the client it configures still pools connections,
and the reused apply functions call the ordinary `post` and `patch`, not
`post_once`. A request placed on a pooled socket that the peer has closed can
be started again by the HTTP stack on a new connection; the comment on the
one-shot client in `transport.rs` records this. Core already avoids
this for `post_once`, `put_once`, and `delete_once` with a separate client
whose idle pool is zero. There is no `patch_once`, and switching the shared
apply functions to the `_once` calls would change CLI retry behavior.

0.9.0 adds one opt-in field:

```rust
pub struct TransportOptions {
    pub debug: bool,
    pub response_body_limit: Option<usize>,
    pub disable_redirects: bool,
    pub disable_retries: bool,
    /// Keep no idle connection, so every request opens its own socket.
    pub disable_connection_pool: bool,
}
```

When it is true, the main client is built with `pool_max_idle_per_host(0)`,
as the one-shot client is. The mutation transport sets `debug: false`, the
16 MiB body limit, `disable_redirects`, `disable_retries`, and
`disable_connection_pool`. Every method on that transport, including `post`
and `patch`, then sends at most one request on a fresh connection. The
existing constructors and both existing MCP transports keep pooling.

Required proof, in core tests with a raw local HTTP responder:

- a first request succeeds and the responder then closes the socket; a
  following `post` and a following `patch` on the same transport each open a
  new connection and are received exactly once;
- the responder reads a `post` or `patch` and closes without answering: the
  call returns a connection error, the responder saw the request once, and
  no second connection was opened;
- the same two cases with `disable_connection_pool: false` are recorded for
  contrast, whatever they show, so the option's effect is measured and not
  assumed.

### Proof that the CLI did not change

- Every existing API, CLI, and snapshot test passes without an edit, apart
  from the `mcp` help text, the command-tree entry for the new flag, and any
  assertion on the case conflict error, which gains `http_status`.
- For each wrapped planner, a new test asserts that the old function and the
  first value of the observed function are equal for the same mocked
  responses, and that both send the same requests in the same order.
- The recording-mock route proofs of 0.7 are extended: MCP never calls
  `rules::delete`, `rules::update`, `rules::patch`, `rules::import`, any
  exception write, `alerts::status_by_query`, `alerts::set_assignees`,
  `cases::delete`, `cases::attach_alerts`, any data view, dashboard, Fleet,
  prebuilt, or state write, or any internal Kibana route.
