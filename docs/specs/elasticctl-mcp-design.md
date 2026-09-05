# elasticctl 0.7 MCP design

Status: 0.7.0 implementation authorized on 2026-09-05. Later scopes remain
planned. Release and publication need separate approval. The
[shared design](elasticctl-design.md) defines existing behavior.
[Research](../plans/v0.7-research.md) records sources, the 0.6.2 baseline,
and unmeasured claims.

## 1. Scope and release sequence

0.7 provides read-only MCP tools over existing Elastic capability areas.
The default server inspects an operator-selected deployment. Raw synchronous
queries require a separate startup flag because they can invoke downstream
inference services. No tool creates durable Elastic objects or reads or
writes arbitrary local files.

| Version | Deliverable | Required evidence before that version ships |
| --- | --- | --- |
| 0.7.0 | stdio server, seven stack/rule/exception tools, limits, error boundary, four-crate packaging | Current and legacy protocol tests; one real client; three-flavor reads for these tools; independent safety and release review |
| 0.7.1 | Thirteen more inspection tools; two opt-in synchronous query tools | All new schemas and route contracts; query admission and cancellation; three-flavor reads for new tools |
| 0.7.2 | Broader client matrix, integrated MCP conformance contract, confirmed review fixes | Two independent client implementations; all MCP tools exercised; eleven-contract release matrix |

These are proposed release scopes, not promised dates. A defect found before
0.7.0 ships belongs in 0.7.0. The later evidence release does not postpone
an earlier version's gates. Further 0.7 patches carry compatible fixes and
small additions within this read-only surface.

Resources, prompts, task-shaped cross-vertical tools, progressive discovery,
and durable protocol tasks remain outside 0.7. Mutation plans and confirmation
remain in 0.9. HTTP hosting and OAuth need a separate design. There is no
generic command runner, shell, HTTP proxy, file tool, export, state command,
rule preview, Fleet setup, or package installer.

## 2. Architecture and alternatives

Add a published `elasticctl-mcp` library. The existing `elasticctl` package
calls it from `elkctl mcp serve`; both existing binaries support the same
command. The MCP library owns schemas, projections, protocol routing, and
call limits. Existing API orchestration owns Elastic operations.

```text
elasticctl CLI ──> elasticctl-mcp ──> elasticctl-api ──> elasticctl-core
       └─────────────────────────> elasticctl-api
```

Both frontend crates can depend directly on core configuration and transport.
Neither `-api` nor `-core` depends on a frontend. No `clap` type enters the MCP
library, API, or core. MCP never calls the CLI renderer or captures a CLI
subprocess. `xtask` may use the MCP library for test tooling but never depends
on the CLI crate.

| Approach | Benefit | Cost | Decision |
| --- | --- | --- | --- |
| Separate library, existing binaries | Follows the planned crate boundary; same install command and binary names | Fourth published crate and packaging updates | Recommended |
| MCP modules or a third binary inside the CLI package | Preserves three published crates | Places another frontend inside the CLI crate; third binary changes archive contents if chosen | Viable, less aligned with the planned boundary |
| Reflect or subprocess the CLI | Less initial routing code | Reintroduces parsing, file flags, mutation paths, and output capture | Rejected |

There is no new generic transport trait or rewrite of existing verticals.
Core gains opt-in response limits, redirect control, and retry suppression. Explicit tool
registration and fixed adapter calls enforce the MCP operation allowlist;
the general API library still contains mutation functions for CLI callers.

## 3. Protocol and dependencies

Use `rmcp = "=3.2.0"`, `default-features = false`, with `server`, `macros`,
and `transport-io`. Use the SDK's re-exported `schemars` for schemas. Keep
the locked dependency graph and Rust 2024 / Rust 1.97.1 workspace floor.

The target protocol is 2026-07-28. Support its optional `server/discover`
and direct metadata-bearing requests without an initialization handshake.
Also test legacy 2025-11-25 initialization through the SDK compatibility path.
Override `ServerHandler::supported_protocol_versions` with exactly these two
revisions; the SDK default advertises more. Unsupported current request
metadata produces a protocol error. Legacy initialization follows version
negotiation: echo a supported requested revision; otherwise offer 2025-11-25
as the configured legacy fallback. A client that cannot use that version
disconnects. Do not claim support for the original unsupported revision or
hand-write a parallel protocol implementation.

Advertise tools only. Return the fixed catalog in lexical name order, in one
page, with no next cursor. Catalog discovery makes no Elastic requests and
does not require a credential. The catalog is fixed for a process and its
startup query setting; no tool changes it. Descriptions are static project
text, never server-supplied rule names or descriptions.

Every registered tool sets `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, and `openWorldHint: true`. These describe the data-read
contract, not deterministic results or absence of compute/inference costs.
The registration and request tests enforce scope; annotations do not.

Use object-shaped structured results and the same compact JSON as one text
content item. Each tool has an input and output schema. Input objects reject
unknown fields. Inputs are validated before network access. Protocol envelope
and unknown-tool errors use SDK JSON-RPC errors. Tool argument validation and
Elastic failures use `isError: true` with the error envelope in section 6.

The SDK owns protocol-specific fields, including the current `resultType`.
An application must not assume that the current and legacy wire envelopes
are byte-identical. Their tool data and catalog must agree.

## 4. Startup target and local access

The operator runs:

```bash
elkctl --profile analyst --space default mcp serve
elkctl --profile analyst --space default mcp serve --allow-query-tools
```

The second form is available from 0.7.1. It permits synchronous queries
against the data accessible to that credential, including possible downstream
inference calls. This setting cannot be changed through MCP. Query tools
remain absent and unknown to the router when it is false.

Resolve core config once, using the existing flags/environment/profile
precedence and paired Kibana/Elasticsearch target rules. Credentials come
from the existing profile or process environment. No tool accepts a profile,
space, host, URL, credential, config path, debug option, timeout, or file path.
Changing the process environment or config after startup does not retarget it.

Startup accepts `--config`, `--profile`, `--space`, and `--timeout` through
the normal CLI flags. Timeout defaults to 30 seconds and must be 1-120 seconds
after resolution; reject an out-of-range value. Reject `--yes`, `--out`,
`--fields`, `--json`, explicitly selected `--format`, and `--debug` for serve.
Check explicit flag provenance where a default renderer value is present.

The library validates the resolved target before starting either `serve_io`
or `serve_stdio`; CLI-only validation is insufficient. Validation requires
no credential, transport construction, or network access. Validate both
resolved URL schemes and authorities at startup. Accept only HTTP
or HTTPS with no query or fragment; reject malformed doubled schemes. Preserve
a configured base path. Disable redirects on the MCP transport. Core's
userinfo scrubbing remains in force. The resolved target never comes from
tool data or returned content.

Startup reads only operator-selected configuration and normal TLS trust
material. Tool calls have no local path inputs and create no files. There is
no client-config installer in this release. Documentation shows a placeholder
stdio launch stanza; users register it through their client.

Return target context as `{profile, host, space}` on every tool outcome.
`host` is the scrubbed Kibana authority without path, query, or credentials.
This is operator-visible runtime context, never data for public fixtures or
release reports. Return flavor and version from `stack_info`; other calls
reuse the cached capability probe where needed.

## 5. Exact catalog and input contracts

All list limits default to 50 and accept integers 1-200. Selectors and filter
strings must contain non-whitespace text when present and be at most 1,024
UTF-8 bytes. Validate without trimming or rewriting the supplied value. Enum
values match the existing API vocabulary. Unknown keys fail locally. No input
has implicit `@file`, path expansion, environment expansion, or URL fetching.

| Since | Tool | Inputs besides list limit | API orchestration |
| --- | --- | --- | --- |
| 0.7.0 | `stack_info` | None | `health::info` |
| 0.7.0 | `stack_doctor` | None | `health::doctor` |
| 0.7.0 | `rules_list` | `enabled`, `rule_type`, `severity`, `tag`, `search`, `source` (default `all`) | `rules_ops::list` |
| 0.7.0 | `rules_get` | `selector` | `rules_ops::get_one` |
| 0.7.0 | `rules_prebuilt_status` | None | `prebuilt::status` |
| 0.7.0 | `exceptions_list` | `list_type`, `tag`, `namespace`, `search` | `exceptions::list_op` |
| 0.7.0 | `exceptions_get` | `list_id`, optional `namespace`, item `limit` | `exceptions::get_op` |
| 0.7.1 | `alerts_list` | `status`, `severity`, `rule`, `tag`, `since`, `search` | `alerts_ops::list` |
| 0.7.1 | `alerts_get` | `alert_id` | `alerts_ops::get_one` |
| 0.7.1 | `cases_list` | `status`, `severity`, `tag`, `search` | `cases_ops::list` |
| 0.7.1 | `cases_get` | `id` | `cases_ops::get_one` |
| 0.7.1 | `data_views_list` | `search` | `data_views_ops::list_op` |
| 0.7.1 | `data_views_get` | `selector` | `data_views_ops::get_op` |
| 0.7.1 | `data_views_default_get` | None | `data_views::get_default` |
| 0.7.1 | `dashboards_list` | `search`, `tag` | `dashboards_ops::list_op` |
| 0.7.1 | `dashboards_get` | `selector` | `dashboards_ops::get_op` |
| 0.7.1 | `fleet_agent_policies_list` | `search` | `fleet::agent_policy_ops::list_op` |
| 0.7.1 | `fleet_agent_policies_get` | `selector` | `fleet::agent_policy_ops::get_op` |
| 0.7.1 | `fleet_integration_policies_list` | `search` | `fleet::integration_policy_ops::list_op` |
| 0.7.1 | `fleet_integration_policies_get` | `selector` | `fleet::integration_policy_ops::get_op` |
| 0.7.1, opt-in | `search_esql` | Complete `query`, `limit` | `search::esql::run_sync` |
| 0.7.1, opt-in | `search_dsl` | `index`, object `query`, optional `fields` and `sort`, `limit` | `search::dsl::run_sync` |

There are seven tools in 0.7.0, twenty by default in 0.7.1, and twenty-two
when queries are enabled. An unsupported Elastic feature remains listed and
returns `unsupported`; availability does not change catalog discovery.

Rule and Fleet selectors retain their existing exact-id/name behavior.
Exception namespace ambiguity remains a conflict. Alert and case ids never
become display-name selectors. Do not add assignee-name lookup: its Serverless
implementation uses an internal Kibana route.

The adapter reuses each existing feature floor. MCP claims tested deployment
support from 9.5.1, but `stack_info` and `stack_doctor` remain usable for
diagnosing older targets. No new global version gate hides these diagnostics.
Version and flavor behavior come from core, never hostname guesses in MCP.

### Result projections

Projections live in `-mcp`; they do not change existing CLI output.

| Family | Returned data |
| --- | --- |
| Stack info | `version`, `flavor`, `license`, `spaces`; preserve unknown license/spaces as null |
| Doctor | `ok`, `checks: [{check,status}]`; omit raw detail text, identities, URLs, and remote messages |
| Rule list | `rule_id`, `name`, `type`, `enabled`, `severity`, `risk_score`, `tags` |
| Rule get | List fields plus `description`, `language`, `query`, `index`, `from`, `interval`, and exception references reduced to `list_id`, `namespace_type`, `type` |
| Prebuilt | Existing `PrebuiltStatus` counters |
| Exception list/get | Container `list_id`, `namespace_type`, `name`, `description`, `type`, `tags`; get adds bounded items with `item_id`, `name`, `description`, `entries`, `os_types`, `tags` |
| Alert list/get | `id`, `index`, and selected source fields: `@timestamp`, `kibana.alert.rule.rule_id`, `kibana.alert.rule.name`, `kibana.alert.severity`, `kibana.alert.risk_score`, `kibana.alert.workflow_status`, `kibana.alert.reason`, `kibana.alert.workflow_tags` |
| Case list/get | `id`, `title`, `status`, `severity`, `tags`, `description`, `created_at`, `updated_at`, `totalComment`; omit `extra`, identities, assignees, connectors, and version token |
| Data-view list | Existing `DataViewSummary` fields: `id`, `title`, optional `name` and `timeFieldName` |
| Data-view get | `{data_view: {...}}` with the explicit fields defined below; omit generated `fields` and unknown top-level keys |
| Dashboard list | Existing `DashboardSummary`: `id`, `title`, optional `description` and `tags` |
| Dashboard get | `{id, data}`; `data` is an explicit open JSON object containing dashboard content; omit `meta` and `warnings` |
| Fleet | Existing safe typed summaries/details only; never raw items, vars, inputs, package metadata, or secret references |
| ES\|QL | `columns: [{name,type}]`, row-major `values`, `is_partial`; duplicate column names remain representable |
| DSL | `hits: [{id,index,score,source}]`; keep document source separate from metadata |

Data-view get requires string `id` and `title`. Optional string fields are
`name`, `timeFieldName`, and `type`; optional booleans are `allowNoIndex` and
`allowHidden`. `sourceFilters` is an optional array of JSON values.
`fieldFormats`, `runtimeFieldMap`, `fieldAttrs`, and `typeMeta` are optional
open JSON objects. Retain only those named fields, without using the portable
artifact validator or fetching mapped fields. Missing or null optional fields
are omitted; a present field of the wrong type produces a classified error.
The dashboard's open `data` object and these nested data-view objects may
contain operator-authored content. Their schemas deliberately permit nested
keys; this does not permit extra envelope keys or raw metadata siblings.

Preserve optional fields as optional. Do not coerce absent data to empty strings
or zero. For alerts, handle both flat dotted source keys and nested objects as
the existing triage code does. All returned object text is untrusted data;
never execute it, fetch its URLs, or promote it into tool instructions.

These projections reduce incidental disclosure; they cannot guarantee that
operator-authored rule text, dashboard content, or query results contain no
sensitive data. Enabling a tool grants access to its documented fields under
the selected Elastic credential.

### Query behavior

`search_esql` accepts a complete query of at most 65,536 UTF-8 bytes.
It appends `\n| LIMIT <limit+1>` and calls the synchronous endpoint. It does
not rewrite sources, parse a language subset, or infer an index from a local
file. Server rejection remains a tool error. Preserve the caller's earlier
LIMIT and all query stages; the appended stage bounds output, not work done
by earlier stages or inference calls.

`search_dsl` accepts the query clause, not an arbitrary HTTP body. Construct
the body from `query`, optional `_source` field names and `sort`,
`size: limit+1`, and `track_total_hits: false`. No PIT, scroll, async handle,
aggregation export, arbitrary request parameters, or `@file` is accepted.
Index syntax is a comma-separated nonempty list of patterns containing only
ASCII letters, digits, `.`, `_`, `-`, and `*`; reject empty components and
components equal to `.` or `..`. Reject slash, backslash, percent escapes,
colon, question mark, fragment, whitespace, and URL syntax before I/O.
This deliberately omits date-math and cross-cluster index selectors.

Both tools can expose data readable by the selected credential. Kibana space
selection is not an Elasticsearch index authorization boundary. Neither a
query text denylist nor an HTTP method check proves absence of downstream
inference effects. Startup opt-in and Elastic privileges are the controls.

Both query tools use a separate lazy transport with one HTTP attempt,
including on 429 or 5xx. Disable both elasticctl's retry loop and reqwest's
automatic retries for that transport. Ordinary inspection retains existing
bounded retries. A failed query is never retried by the server; a later
client call is a new query and can repeat downstream inference work.

## 6. Output, errors, and bounds

Successful structured content has this shape:

```json
{
  "target": {"profile": "analyst", "host": "kibana.example.test", "space": "default"},
  "data": {},
  "page": null
}
```

Each tool defines its own typed `data` schema. List results, exception items,
and query rows carry `page` with `limit`, `returned`, nullable exact `total`,
nullable `has_more`, and boolean `truncated`. Other gets have `page: null`.
Set `truncated` when the adapter omits fetched rows; set `has_more` only when
known, otherwise null. Do not turn a lower-bound server count into an exact
total. In particular, DSL totals are null because the existing decoder drops
the total relation. Fleet list operations currently count before their local
search filter. Call them with `limit: None`, derive the filtered total from
the complete returned vector, then apply MCP row/byte limits. Keep CLI totals
unchanged. There is no domain result cursor in 0.7; narrow filters
or use exact gets after a capped list. MCP catalog pagination is separate.

Errors use the same target plus an error object:

```json
{
  "target": {"profile": "analyst", "host": "kibana.example.test", "space": "default"},
  "error": {"kind": "permission", "http_status": 403,
    "code": "elastic_permission", "message": "The selected credential cannot read this data."}
}
```

Declare the success and error alternatives in each output schema. The error
object retains the existing error-kind vocabulary. Local failures use stable
codes `invalid_argument`, `busy`, `deadline_exceeded`, and `result_too_large`,
with `kind` respectively `error`, `error`, `timeout`, and `unsupported`.
An oversized input line ends the connection before a request can be decoded;
it has no tool error envelope. An upstream body-limit failure retains core's
`unsupported` kind and maps to `elastic_unsupported`. Do not parse core error
messages to invent a more specific code.
Map Elastic errors to `elastic_<kind>` and a static message per kind. Do not
copy `Error.message`, request text, raw bodies, URLs, credentials, or arbitrary
SDK error data into tool errors or startup diagnostics. Safe validation errors
may name a static field and its permitted range, never its supplied value.

Doctor failing checks remain a successful diagnostic report with `ok: false`;
they are not an exception. A failure to construct its transport is a tool
error. MCP does not reuse the CLI's rendered-field exit-status inference.

| Limit | Value | Enforcement |
| --- | --- | --- |
| Input line | 262,144 bytes, excluding newline | Before the SDK buffers/parses the full line; oversize terminates the connection with a static stderr diagnostic |
| Structured content | 262,144 serialized UTF-8 bytes | Before building the text copy |
| Complete outbound JSON-RPC frame | 1,048,576 serialized bytes, excluding newline | Includes JSON escaping, text duplication, SDK metadata, and request id |
| Upstream body | 16,777,216 decoded bytes per response | Optional core transport setting; check declared size and count streamed chunks |
| Rows | Default 50, maximum 200 | Validate before I/O; preserve explicit cap metadata |
| Active tool calls | Four | Try-acquire a semaphore; fifth call returns `busy`, with no queue or Elastic request |
| Whole call | Default 30 seconds, allowed 1-120 | Includes capability probe, retries, paging, projection, and serialization |
| Shutdown grace | Five seconds | Cancel active calls on stdin EOF or process signal, then stop |

Limits are product choices, not MCP defaults. Count UTF-8 bytes, not string
characters. Stop list output between complete rows to meet the structured and
frame caps. Mark omitted rows as truncated. If no row or a single-object result
fits, return `result_too_large`; do not split fields, emit invalid JSON, or
claim success with empty data. The error response itself must fit the frame.

Core's existing constructors preserve their behavior. Add an opt-in constructor
or options structure for response-body limits, disabled redirects, and
disabled retries; apply
the body limit to success and error responses on every transport path.
The MCP transport always has debug off. This is bounded request memory, not
a claim that a full API collector only performs one bounded read. Existing
rule, exception, and Fleet collectors may scan more than the displayed rows;
the outer deadline stops them and returns a failure, never a partial success
disguised as a complete collection. Avoid an unrelated paging rewrite in 0.7.

Observe the SDK request cancellation token while awaiting API operations.
Drop the API future and release its permit on cancellation. Send no later
result for that request. A client disconnect cancels all active work.
Synchronous queries may continue briefly inside Elastic after disconnect;
the server promises to stop client work, not to prove backend cancellation.
There are no client-owned PIT or async result objects needing cleanup.

## 7. Safety and compatibility proofs

Tests must drive the public MCP router and real stdio process, not only call
private adapter functions. Compare exact catalog names and schemas. Assert
that mutation names, arbitrary commands, target changes, file inputs,
query tools without opt-in, and internal Kibana assignee/profile lookup never
reach Elastic. Doctor's public Elasticsearch `/_security/_authenticate`
read remains allowed.

Use a recording mock to compare every emitted method/path with the routes
needed by the chosen tool. Read POST paths include signals search and,
only with query opt-in, synchronous `_query` and index `_search`. Assert zero
PUT/PATCH/DELETE, Fleet setup, preview, import, async query, and PIT requests.
Inspect actual requests on error paths as well as successful results.

Inject credential-shaped sentinels into errors and excluded response fields;
prove absence from both output channels. Check changed config/environment
between calls, redirects to another authority, malformed success bodies,
capability failures, oversized chunked bodies, Unicode/escaping, cancellation,
and the fifth concurrent call. Existing CLI snapshots remain byte-identical
apart from the new command-tree/help entries and release version snapshot.

Existing fixture files remain recorded evidence and are never hand-edited.
New synthetic responses belong in adversarial tests, not fixture directories.
Reuse existing fixture sets through the production MCP adapter before adding
recordings. Need for a new request shape triggers the existing scoped recorder
workflow and independent review.

## 8. Evidence and release contract

Before 0.7.0 and 0.7.1, run direct MCP reads for every tool shipped in that
version against Serverless, Hosted, and self-managed targets. Use marker-owned
objects prepared by the external test harness; never prepare them through MCP.
Read results stay in ignored private logs. A per-version findings document
records the protocol, client, tool coverage, aggregate outcomes, and cleanup.
Empty results alone do not prove a get/projection path works.

0.7.2 adds the eleventh conformance contract, `mcp_reads_existing_verticals`,
to the existing matrix. The test controller prepares marker rules, exceptions,
alerts/cases, data views, dashboards, and Fleet policies using existing guarded
test patterns, then runs the MCP reads. Any new fixture provisioning or
cleanup code receives adversarial ownership review before live use. It never
mutates prebuilt or unmarked objects. The harness verifies existing baselines,
marker cleanup, exact default data view, and package inventory.

The existing conformance JSON keys stay unchanged. Detailed MCP client and
tool coverage belongs in scrubbed narrative findings. Extend the report
validator for eleven contracts while retaining historical formats. Never
report a skipped or unavailable target as a pass.

The fourth published crate requires updates to root and CLI manifests,
package-content checks, workspace version validation, publishing comments and
documentation, and Trusted Publishing setup if publication is approved.
All four crates share one version. `cargo install elasticctl` still installs
`elasticctl` and `elkctl`; no third binary or new build target is proposed.
Each version runs the exact-commit CI and nonpublishing preflight in
[releasing.md](../releasing.md). Adding a library changes packaging, so that
guide's published-candidate rule applies if crates.io publishing is requested.
No release, registration, or publishing action is authorized by this plan.

## 9. Subagent execution contract

Use the three plans: [0.7.0](../plans/v0.7.0.md),
[0.7.1](../plans/v0.7.1.md), and [0.7.2](../plans/v0.7.2.md).
The primary agent owns coordination, spec changes, reviewed integration,
verification, Git, and release operations.

Set the model explicitly on each dispatch: `gpt-5.6-sol` for design and every
independent review, `gpt-5.6-terra` for implementation, and `gpt-5.6-luna` for
searches or mechanical edits. A designer or reviewer must not
implement the same slice. Each editing worker gets a separate worktree,
fixed paths, one directive, exact interfaces, forbidden actions, and checks.
Read-only research and reviews can run in parallel. Implementation uses a
fresh worker per task with review before dependent work; do not overlap
shared catalog, manifest, lockfile, or test-support ownership.

The execution ledger records task commits, tests, review verdicts, and design
rulings. Each task needs both spec-compliance and quality approval. A separate
whole-branch review covers the integrated credential, routing, and packaging
boundaries. The primary inspects worker diffs and runs required checks before
accepting them. Local builds use two jobs, tests use four threads, and only
one build-heavy process runs at a time.
