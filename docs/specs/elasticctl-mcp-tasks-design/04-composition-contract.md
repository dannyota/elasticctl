[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 4. Composition contract

A task tool is one call into `elasticctl_api::compose`. The API function
runs a fixed request plan and returns a typed report. The MCP adapter
validates arguments before any I/O, calls the function with the bounded
transport from `ServerState::transport()`, and projects the report into the
0.7 success envelope `{target, data, page}`.

```text
tools/call ──> server admission, deadline, cancellation (0.7, unchanged)
          ──> tools/compose/<tool>.rs   validate, call, project
          ──> elasticctl_api::compose   fixed request plan, typed report
          ──> existing vertical modules and core transport
```

Rules that hold for all four tools:

- Requests run one at a time in the documented order. A later request never
  starts before the earlier one ends.
- All requests use the 0.7 inspection transport: 16 MiB body cap, redirects
  off, existing retries on, debug off. The query transport is never used.
- No request text, path, index name, or query comes from the model except
  the validated selector, id, filter, and `since` inputs listed per tool.
- Each plan has a stated maximum request count. The count is logical
  requests; core may retry a 429 or 5xx up to its existing limit. The first
  call in a process may add one cached capability probe, `GET /api/status`.
- The whole-call deadline, the four-call admission limit, cancellation, and
  the output byte caps are those of 0.7 section 6. A deadline returns
  `deadline_exceeded` with no partial data.
- No task tool has a domain cursor. `detection_coverage` is the only one
  with `page`.

### 4.1 Parts and partial failure

The first read is primary. If it fails, the tool returns the 0.7 failure
envelope with that error. Every later read is a part. A part is an object:

| Field | Type | Present |
| --- | --- | --- |
| `status` | `"ok"`, `"unavailable"`, or `"skipped"` | always |
| `value` | the part's data | only when `ok` |
| `error` | the 0.7 `ToolError` object: `kind`, `http_status`, `code`, `message` | only when `unavailable` |
| `skip_reason` | `"not_applicable"`, `"dependency_unavailable"`, or `"not_configured"` | only when `skipped` |

A failed part read is classified by its core error kind:

| Kind | Effect |
| --- | --- |
| `auth`, `connection`, `timeout` | The whole call fails with this error. No part data is returned. |
| `permission`, `not_found`, `conflict`, `unsupported`, `http`, `error` | The part becomes `unavailable` with the static 0.7 error mapping. The plan continues. |

Skip reasons:

- `not_applicable`: the object has nothing to read for this part, for
  example an ES|QL rule has no index patterns.
- `dependency_unavailable`: an earlier part this one needs is not `ok`.
- `not_configured`: the startup target lacks what the part needs, for
  example no Elasticsearch URL.

Some parts hold rows that are read one request at a time. Such a row has its
own `status` of `"ok"` or `"unavailable"` and an `error` field with the same
rules. A fatal kind in a row read fails the whole call.

`data.partial` is `true` when any part or row is `unavailable`, or when any
`rule_readiness` pattern row is `unresolved`. It is `false` otherwise;
`skipped` does not set it.

`data.findings` is an array of static codes in the order each tool section
lists them. A finding is emitted only from parts and rows whose status is
`ok`, except the findings that report a missing object. The list is closed:
adding a code is additive, removing or renaming one is a break.

### 4.2 Shared building blocks

These live in `elasticctl_api::compose` and are used by more than one tool.

**Rule snapshot.** One rule read that keeps what `rules_get` drops. The
canonical rule feeds the same projection as `rules_get`. The raw response
feeds `execution`, taken from `execution_summary.last_execution`:

| `execution` field | Type | Rule |
| --- | --- | --- |
| `status` | string | required; passed through unchanged |
| `date` | string | required |
| `status_order` | number | optional |
| `message` | string | optional; first 2,048 UTF-8 bytes, cut on a character boundary |
| `message_truncated` | boolean | always; `true` when the cut removed text |
| `metrics` | object | always; holds only the optional numbers `total_search_duration_ms`, `total_indexing_duration_ms`, `total_enrichment_duration_ms`, `execution_gap_duration_s` |

`execution` is `null` when the rule has no `execution_summary`. A present
summary without string `status` and `date` is a projection error of kind
`http`. A named metric of the wrong type is the same error; other metric keys
are dropped.

A snapshot by exact `rule_id` is one request,
`GET /api/detection_engine/rules?rule_id=`. A response whose `rule_id`
differs from the requested value is treated as `not_found`. A snapshot by selector uses the
existing `selection::to_rule` path: one request when the selector is a
`rule_id`, three when it is a display name.

**Rule context.** The MCP projection of a snapshot: every `rules_get` field
plus `execution`. `rule_id` is required, `execution` is required and
nullable, and every other field is optional as in `rules_get`.

**Exception coverage.** Takes the rule's exception references through
`model::exception_refs`, in rule order, and reads the first five. Each list
costs two requests: the container through `exceptions::get_list`, then a
count through `GET /api/exception_lists/items/_find` with the list key,
`page=1`, and `per_page=1`, reading only `total`.

| Field | Type |
| --- | --- |
| `referenced` | integer; references on the rule |
| `truncated` | boolean; `true` when `referenced` is above five |
| `lists[]` | rows in rule order |
| `lists[].list_id`, `lists[].namespace_type` | strings; the reference identity |
| `lists[].type` | string, optional; the reference type |
| `lists[].status` | `"ok"` or `"unavailable"` |
| `lists[].error` | `ToolError`, only when `unavailable` |
| `lists[].name`, `lists[].list_type` | strings, optional, only when `ok` |
| `lists[].item_count` | integer, only when `ok` |

A container read that fails skips its count request. A rule with no
references yields `referenced: 0` and an empty `lists` with no request.

**Alert activity.** One `POST /api/detection_engine/signals/search` for one
`rule_id` over a window:

```json
{
  "query": {"bool": {"filter": [
    {"term": {"kibana.alert.rule.rule_id": "<rule_id>"}},
    {"range": {"@timestamp": {"gte": "now-<since>"}}}
  ]}},
  "sort": [{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
  "size": 0,
  "track_total_hits": true,
  "aggs": {"status": {"terms": {"field": "kibana.alert.workflow_status", "size": 8}}}
}
```

`size` is 0 for `alert_context` and 5 for `rule_health`. The decoder
requires `hits.total.value` as an unsigned integer with
`hits.total.relation` equal to `"eq"`, and `aggregations.status.buckets` as
an array of objects with string `key` and unsigned `doc_count`. Anything else
is an `http` error. Buckets `open`, `acknowledged`, and `closed` fill their
counters. Every other bucket and `sum_other_doc_count` add to `other`.

| Field | Type |
| --- | --- |
| `window` | string; the validated `since` value |
| `total` | integer |
| `by_status` | object with integers `open`, `acknowledged`, `closed`, `other` |
| `recent[]` | `rule_health` only; up to five alerts in the `alerts_get` projection, newest first |

**The `since` input.** Optional string, default `"24h"`. It must be one to
four ASCII digits not starting with `0`, followed by one of `s`, `m`, `h`,
`d`, `w`. Timestamps and date math are rejected before I/O with
`invalid_argument`. This is narrower than `alerts_list.since` on purpose: the
value is echoed as `window`.

### 4.3 Flavor behavior

Flavor and version come from the cached core capability probe. No tool
branches on a hostname or carries per-flavor code.

| Condition | Effect |
| --- | --- |
| Kibana below 9.5.1 and the read needs exception lists | Each exception list row is `unavailable` with `elastic_unsupported`. |
| Kibana below 9.5.1 and `detection_coverage` or `rules_list` has `source` other than `all` | The call fails with `elastic_unsupported`, as `rules_list` does today. |
| Kibana below 9.5.1 and the read needs Fleet | The `integrations` part is `unavailable` with `elastic_unsupported`. |
| Serverless, pattern names a remote cluster | Elasticsearch answers 404; the row is `no_match`. Measured on 9.7.0. |
| Hosted or self-managed, pattern names an unknown remote cluster | Elasticsearch answers 404; the row is `no_match`. Measured on Hosted 9.5.6. |
| Profile has no `es_url` | The `patterns` part is `skipped` with `not_configured`. |
| Credential lacks a privilege for one family | That part or row is `unavailable` with `elastic_permission`. |

Serverless has no license endpoint. No 0.8 tool reads the license.
Supported-version claims stay those of 0.7: tested from 9.5.1.
