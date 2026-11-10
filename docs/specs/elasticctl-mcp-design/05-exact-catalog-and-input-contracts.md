[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 5. Exact catalog and input contracts

All list limits default to 50 and accept integers 1-200. Selectors and filter
strings must contain non-whitespace text when present and be at most 1,024
UTF-8 bytes. Validate without trimming or rewriting the supplied value. Enum
values match the existing API vocabulary. Unknown keys fail locally. No input
has implicit `@file`, path expansion, environment expansion, or URL fetching.

Free-text schemas declare `minLength: 1` and `maxLength: 1024` as character
constraints. Field descriptions state the exact non-whitespace and UTF-8 byte
rules and that supplied values stay unchanged. Runtime validation enforces
those rules; schema constraints preserve optional and explicit-null behavior.

| Since | Tool | Inputs besides list limit | API orchestration |
| --- | --- | --- | --- |
| 0.7.0 | `stack_info` | None | `health::info` |
| 0.7.0 | `stack_doctor` | None | `health::doctor` |
| 0.7.0 | `rules_list` | `enabled`, `rule_type`, `severity`, `tag`, `search`, `source` (default `all`) | `rules_ops::list_page` |
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

`rules_list` reads one page: a single `_find` request with `per_page` equal
to `limit`, ordered by rule name ascending. `page.total` is the server total;
`has_more` and `truncated` are true when it exceeds `returned`. An empty
source-filtered page runs the same source-partition proof as `rules list`,
which keeps its complete read. Through 0.7.4 the tool read the whole corpus in
one request; at 2,263 rules that response was 19.3 MB, over the 16 MiB body
cap, so the call failed with `unsupported`.

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

Exception list data is `{lists: [...]}`; get data is
`{container: {...}, items: [...]}`. Containers require string `list_id` and projected
`namespace_type`; preserve a string namespace and emit `single` when it is
absent or null, matching the API identity default. The other named container
fields are optional. Each nested item requires only string `item_id`; its
container supplies `list_id` and `namespace_type`. Item `entries` is an
optional array of arbitrary JSON values; `name` and `description` are
optional strings, and `os_types` and `tags` are optional arrays of strings.
Missing or null optional fields are omitted, and a present selected field of
the wrong type fails projection. Do not validate entry variants or hidden item
parent fields.

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

