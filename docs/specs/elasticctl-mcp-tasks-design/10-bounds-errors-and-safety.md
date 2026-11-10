[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 10. Bounds, errors, and safety

### 10.1 Limits

Every limit of [0.7 section 6](../elasticctl-mcp-design/06-output-errors-and-bounds.md#6-output-errors-and-bounds)
applies unchanged: 262,144-byte input line, 262,144-byte structured content,
1,048,576-byte frame, 16,777,216-byte upstream body, four active calls,
whole-call deadline of 1 to 120 seconds with a default of 30, and a
five-second shutdown grace. 0.8 adds these:

| Limit | Value | Applies to |
| --- | --- | --- |
| Exception lists read per rule | 5 | `alert_context`, `rule_health` |
| Case details read per alert | 5 | `alert_context` |
| Recent alerts returned | 5 | `rule_health` |
| Index patterns resolved per rule | 16 | `rule_readiness` |
| Packages checked per rule | 8 | `rule_readiness` |
| Execution message | 2,048 UTF-8 bytes | rule context |
| Corpus page | 500 rules | `detection_coverage` |
| Corpus size | 4,000 matching rules | `detection_coverage` |
| Integration policies read | 1,000, one page | `rule_readiness` |
| Corpus read passes | 2 | `detection_coverage` |
| Resource URI | 4,096 bytes | `resources/read` |
| Prompt argument | 256 characters | `prompts/get` |

| Tool | Maximum logical requests |
| --- | --- |
| `alert_context` | 19 |
| `rule_health` | 14 |
| `rule_readiness` | 29 |
| `detection_coverage` | 8 per pass, 16 in total |
| `rules_list` | 1; 4 when the page is empty and the filter is only a `custom` or `prebuilt` source (the page plus three reads in `verify_source_partition`) |

Every maximum is enforced by a cap in code, not by an expectation about the
deployment. A recording mock asserts each maximum and the exact order, using
inputs built to reach it. The caps are product choices set from section 11
measurements; changing one is a spec change.

Resource reads and tool calls share the four permits. `prompts/get` and all
list requests hold none.

When a task result does not fit the structured cap, `detection_coverage`
drops whole trailing rows and marks `page.truncated`. The other three tools
have no rows to drop and return `result_too_large`. No field is split and no
part is silently removed.

### 10.2 Tool errors

Tool failures keep the 0.7 envelope, kinds, codes, and static messages. 0.8
adds no kind and no code. Part and row errors reuse the same `ToolError`
object.

| Situation | Result |
| --- | --- |
| Unknown field, wrong type, bad `since`, bad `technique`, bad `tactic`, limit out of range | `invalid_argument`; no request sent |
| Primary read fails | failure envelope with `elastic_<kind>` |
| Part read fails with `auth`, `connection`, or `timeout` | failure envelope with `elastic_<kind>` |
| Part read fails with another kind | success envelope; that part `unavailable` |
| Corpus changed during both read passes | failure envelope with `elastic_conflict` |
| Corpus above 4,000 rules, or a page above the body cap | failure envelope with `elastic_unsupported` |
| More than 1,000 integration policies | success envelope; `integrations` `unavailable` with `elastic_unsupported` |
| `alert_id` is exactly `.` or `..` | `invalid_argument`; no request sent |

### 10.3 Protocol errors

0.7 rewrites every outbound JSON-RPC error: it replaces `message` with a
static text chosen by code and removes `data`. 0.8.1 keeps that single
choke point and makes two narrow allowances:

- `message` is kept when it equals one of these strings exactly:
  `Resource not found`, `Resource read failed`, `Invalid cursor`,
  `Unknown prompt`, `Invalid prompt arguments`. Any other message is replaced
  as in 0.7. Code `-32002` gets the default `MCP resource not found`.
- `data` is kept only when it is an object with exactly the keys `kind`,
  `http_status`, and `code`, where `kind` is one of the nine core kinds,
  `code` is one of the four local codes or `elastic_<kind>`, and
  `http_status` is null or an integer from 100 to 599. Any other `data` is
  removed.

The existing 0.7 messages for tools do not change.

### 10.4 Safety envelope

0.8 keeps the 0.7 envelope exactly:

- No request creates, updates, or deletes an Elastic object. No PUT, PATCH,
  or DELETE is sent. The POST routes are the read-only signals search and,
  only with the startup flag, the two query routes.
- No tool, resource, or prompt reads or writes a local file, accepts a path,
  URL, target, profile, space, credential, timeout, or debug option.
- The query tools stay opt-in and unchanged. No task tool, resource, or
  prompt calls them or their transport.
- No internal Kibana route is called.

Routes that 0.8 adds to the server's allowlist, all reads:

| Route | Used by | New to elasticctl |
| --- | --- | --- |
| `GET /api/detection_engine/rules/_find` with `sort_field`, `sort_order`, and threat KQL | `rules_list`, `detection_coverage` | parameters only |
| `POST /api/detection_engine/signals/search` with `aggs` and `size` 0 or 5 | `alert_context`, `rule_health` | body only |
| `GET /api/cases/alerts/{alert_id}` | `alert_context` | yes |
| `GET /api/exception_lists/items/_find` with `per_page=1` | `alert_context`, `rule_health` | parameters only |
| `GET /api/data_views` | `rule_readiness` | no |
| `GET /api/fleet/package_policies`, `GET /api/fleet/epm/packages/{name}` | `rule_readiness` | new to MCP |
| `GET {es}/_resolve/index/{pattern}` | `rule_readiness` | yes |

The cases route is marked technical preview by Elastic. Its decoder fails
closed and its part degrades, so a changed shape cannot break the rest of
`alert_context`.

**Text in request paths.** Four values become one URL path segment: the
`alert_context` alert id (from the caller), a case id returned by the cases
route, a rule's index pattern, and a package name from
`related_integrations`. The last three are remote text, authored by whoever
can write cases or rules.

`core::urlencode` encodes `/`, `?`, `#`, `%`, and every other reserved byte,
so a value cannot add a segment, query, or fragment. It keeps `.`, and URL
parsing removes `.` and `..` segments, so those two values would move the
request off its fixed prefix. Each is therefore refused before a request is
built:

| Value | When it is exactly `.` or `..` |
| --- | --- |
| `alert_id` input of `alert_context` | `invalid_argument` for the call |
| Case id from the cases route | the `cases` part is `unavailable` with kind `http`, as for any malformed route response |
| Index pattern | the row is `unresolved`; no request |
| Package name | fails the package grammar; the row is `unavailable`; no request |

Patterns are also length-checked and capped at 16 per call, package names
must match `a-z`, `0-9`, `_`, `-`, and both are sent only with GET under
`/_resolve/index/` and `/api/fleet/epm/packages/`. Tests assert the path the
mock server actually received, not the string the client built. The
`_resolve/index` response is reduced to three counts, so a pattern such as
`*` costs one metadata response bounded by the body cap and reveals no name.

The 0.7 `cases_get` tool builds the same case path from its `id` input.
0.8.0 makes it refuse `.` and `..` with `invalid_argument`, and reviews every
other 0.7 get tool for an id that reaches a path segment.

**Remote text in results.** Rule names, descriptions, queries, execution
messages, case titles, and alert reasons are returned as data inside `data`.
They are never copied into tool descriptions, server instructions, prompt
text, finding codes, error messages, resource names, or URIs the server
mints. Findings come from typed comparisons, not from remote strings.

**Model-supplied text.** A selector or id is used only as an exact value in
an existing API call. `since`, `technique`, `tactic`, and `group_by` are
checked against closed grammars. Prompt arguments are checked against a
character allowlist before they enter prompt text, and they are serialized
as JSON strings.

**Added disclosure.** The owner approved these default-on reads on
2026-11-10, with no new startup flag. Compared with 0.7, a default 0.8
session can also learn:

- the last execution status and message of a rule. The message is remote
  text that can name index patterns, privileges, and error details. Each
  message is cut at 2,048 UTF-8 bytes;
- alert counts per rule and workflow status, and the five newest alerts of a
  rule in the projection `alerts_get` already returns;
- which cases contain an alert;
- how many indices, aliases, and data streams each of a rule's index
  patterns matches on Elasticsearch, as counts only;
- which Fleet packages a rule names, whether each is installed and at which
  version, and how many integration policies use it.

All of it is readable by the selected credential, and none of it needs the
query flag. An operator who does not want a model to see it must use a
credential without those privileges; the server has no switch for it.
Projections reduce incidental disclosure; they cannot make operator-authored
text safe to share.

### 10.5 Required proofs

In addition to the 0.7 section 7 proofs, which still run:

- For each task tool, a recording mock compares every method and path with
  the plan table, in order, on success and on each part failure.
- Each fatal kind in each part yields a failure envelope and sends no later
  request. Each non-fatal kind yields `unavailable` and the plan continues.
- For each task tool, through the router: a cancellation that arrives while
  a middle request of the plan is in flight yields no response, no later
  request, and a free permit; a deadline that expires at the same point
  yields the `deadline_exceeded` failure envelope with no part data, no
  later request, and a free permit.
- Credential-shaped sentinels placed in execution messages, case fields
  outside the projection, package metadata, `_resolve/index` names, and
  error bodies do not appear in output, except the execution message, which
  is returned by design and proven to be cut at the cap.
- For index patterns, package names, the alert id, and case ids: the values
  `.` and `..` send no request, and `../_bulk`, `a/b`, `a?b`, `a#b`,
  `%2e%2e`, `...`, a 1,025-byte value, and a control character either send
  nothing or arrive as one segment under the fixed prefix. The assertion is
  on the path the mock server received.
- More than 1,000 integration policies makes `integrations` unavailable
  after exactly one Fleet list request and no package request.
- An empty source-only `rules_list` sends exactly four requests; an empty
  result with any other filter sends one.
- Hostile URIs and prompt arguments reach no request.
- The catalogs, lists, instructions, and prompt texts match literal
  expectations held in the tests, not values derived from production code.
- Existing CLI snapshots stay byte-identical.
