# MCP

`elkctl mcp serve` runs a Model Context Protocol (MCP) server over stdio. Its
tools read one stack, through one profile and space chosen when the server
starts. No tool creates, changes, or deletes an Elastic object.

## Start the server

```bash
elkctl --profile analyst --space default mcp serve
```

Choose an existing profile name. Credentials come from that profile or the
server process environment. The target is fixed for the life of the process:
no tool accepts a profile, space, host, URL, credential, configuration path,
timeout, debug option, or file path, and changing the configuration or the
environment after startup does not retarget the server.

The server writes protocol messages to stdout and diagnostics to stderr. It
stops when stdin closes or the process receives a signal, after cancelling
active calls with a five-second grace period.

### Startup flags

`mcp serve` accepts the target and timeout flags: `--config`, `--profile`,
`--space`, and `--timeout`. It rejects `--yes`, `--out`, `--fields`, `--json`,
an explicit `--format`, and `--debug`.

`--timeout` sets a whole-call deadline of 1 to 120 seconds; the default is 30.
The deadline covers the capability probe, retries, paging, projection, and
serialization. A value outside the range stops startup.

`--allow-query-tools` adds two query tools; see [Query tools](#query-tools).

## Register with a client

Register a stdio server through your client's settings. There is no installer.
For clients that use an `mcpServers` object, this placeholder stanza starts the
same command:

```json
{
  "mcpServers": {
    "elasticctl": {
      "command": "elkctl",
      "args": ["--profile", "analyst", "--space", "default", "mcp", "serve"]
    }
  }
}
```

Append `"--allow-query-tools"` to `args` to enable the query tools.

## Tools

The default catalog contains twenty-four tools: four
[task tools](#task-tools) and twenty
[inspection tools](#inspection-tools). With `--allow-query-tools` it
contains twenty-six; see [Query tools](#query-tools).

### Task tools

A task tool answers one question that spans several objects. It reads them
one request at a time, in a fixed order, and returns one answer.

| Tool | Answers | Inputs | Requests, at most |
| --- | --- | --- | --- |
| `alert_context` | What is this alert, what fired it, and what exists around it: the alert, its rule with the last execution, the rule's exception lists, the cases that contain the alert, and the rule's alert counts in a window | `alert_id`, `since` | 19 |
| `rule_health` | Is this rule running and alerting: its definition and last execution, alert counts by workflow status with the five newest alerts in a window, and its exception lists with item counts | `selector`: a `rule_id` or exact name; `since` | 14 |
| `detection_coverage` | What do the rules cover: enabled and disabled rule counts per MITRE ATT&CK technique, tactic, index pattern, or integration package | `group_by` (default `technique`; also `tactic`, `index_pattern`, `integration`), `enabled`, `source` (default `all`), `tag`, `limit` | 8, or 16 when the read repeats |
| `rule_readiness` | Can this rule see data: whether each index pattern resolves on Elasticsearch, whether its data view exists, and whether its related Fleet packages are installed and used by an integration policy | `selector`: a `rule_id` or exact name | 29 |

`since` is optional and defaults to `24h`: one to four digits not starting
with `0`, followed by `s`, `m`, `h`, `d`, or `w`. Timestamps and date math are
rejected. `alert_id` cannot be exactly `.` or `..`. The request counts exclude
retries of a 429 or server error, and the capability probe that the first
call of a process may send.

In `alert_context`, `rule_health`, and `rule_readiness`, the first read, of
the alert or the rule, is primary: if it fails, the call fails. Every later
read is a part with a `status`:

- `ok`, with the part's `value`;
- `unavailable`, with an `error` object as in [Errors](#errors);
- `skipped`, with a `skip_reason`: `not_applicable` when there is nothing to
  read, `dependency_unavailable` when an earlier part it needs is not `ok`,
  or `not_configured` when the profile lacks what it needs.

An `auth`, `connection`, or `timeout` error in any read fails the whole call.
`data.partial` is `true` when a part or row is `unavailable`, or a
`rule_readiness` pattern is `unresolved`. `data.findings` lists static codes
from typed checks, never remote text:

| Tool | Findings, in order |
| --- | --- |
| `alert_context` | `alert_not_open`, `rule_missing`, `rule_disabled`, `rule_last_execution_failed`, `exception_list_missing`, `has_related_case` |
| `rule_health` | `rule_disabled`, `never_executed`, `last_execution_failed`, `last_execution_partial_failure`, `execution_gap`, `no_alerts_in_window`, `exception_list_missing` |
| `rule_readiness` | `rule_disabled`, `no_index_source`, `data_view_missing`, `no_pattern_matches`, `pattern_unresolved`, `integration_not_installed`, `integration_without_policy`, `patterns_truncated`, `integrations_truncated` |

Each task tool reads a bounded amount. A `truncated` field is `true` when a
cap left entries out.

- `alert_context` and `rule_health` read the first five exception lists a
  rule references, each with an item count. `alert_context` reads the first
  five cases that contain the alert.
- A rule's last execution message is cut at 2,048 UTF-8 bytes, and
  `message_truncated` says so.
- `rule_readiness` resolves the first 16 index patterns and checks the first
  eight distinct packages. It reads one page of at most 1,000 integration
  policies; with more, `integrations` is `unavailable` with
  `elastic_unsupported`.
- `detection_coverage` reads matching rules in 500-rule pages and accepts at
  most 4,000 rules; see
  [Limitations](Limitations.md#coverage-reads-at-most-4000-rules).

`detection_coverage` has no parts or findings. `summary` describes the whole
corpus read, and `rows` sort by enabled rules, then disabled rules, both
descending, then by key. A row with `enabled_rules: 0` and `disabled_rules`
above zero is coverage that is installed and switched off. Call `rules_list`
with `technique` or `tactic` to see the rules behind a row.

`rule_readiness` returns counts, never an index, alias, or data stream name.
A pattern row is `matches`, `no_match`, `exclusion` (it starts with `-` and is
not sent), or `unresolved`. A match means names exist, not that documents
arrive. Pattern checks need the profile's Elasticsearch URL; without it,
`patterns` is `skipped` with `not_configured`.

Task tools return only what the selected credential can read. Beyond the
inspection tools, they show a rule's last execution status and message, alert
counts per rule and workflow status, which cases contain an alert, match
counts per index pattern, and which Fleet packages a rule names, with each
package's install state, installed version, and policy count. To keep these
from a model, use a credential without those privileges; the server has no
switch for them.

### Inspection tools

Each inspection tool reads one object family. Every list tool also takes
`limit`.

| Area | Tool | Inputs |
| --- | --- | --- |
| Stack | `stack_info` | None. Returns version, flavor, license, and spaces |
| Stack | `stack_doctor` | None. Returns `ok` and each check's status |
| Rules | `rules_list` | `enabled`, `rule_type`, `severity`, `tag`, `search`, `technique`, `tactic`, `source` (default `all`) |
| Rules | `rules_get` | `selector`: a `rule_id` or exact name |
| Rules | `rules_prebuilt_status` | None |
| Exceptions | `exceptions_list` | `list_type`, `tag`, `namespace`, `search` |
| Exceptions | `exceptions_get` | `list_id`, optional `namespace`, item `limit` |
| Alerts | `alerts_list` | `status`, `severity`, `rule`, `tag`, `since`, `search` |
| Alerts | `alerts_get` | `alert_id` |
| Cases | `cases_list` | `status`, `severity`, `tag`, `search` |
| Cases | `cases_get` | `id` |
| Data views | `data_views_list` | `search` |
| Data views | `data_views_get` | `selector`: an id or exact name |
| Data views | `data_views_default_get` | None |
| Dashboards | `dashboards_list` | `search`, `tag` |
| Dashboards | `dashboards_get` | `selector`: an id or exact title |
| Fleet | `fleet_agent_policies_list` | `search` |
| Fleet | `fleet_agent_policies_get` | `selector`: an id or exact name |
| Fleet | `fleet_integration_policies_list` | `search` |
| Fleet | `fleet_integration_policies_get` | `selector`: an id or exact name |

`rules_list` returns rows ordered by rule name. `technique` takes a MITRE
ATT&CK technique id, `T` and four digits such as `T1059`, or a subtechnique
id such as `T1059.001`. `tactic` takes a tactic id, `TA` and four digits such
as `TA0002`. Any other value fails with `invalid_argument` before a request.
Both combine with the other filters.

Selectors resolve as they do on the [CLI](CLI.md#selectors). Alert and case
ids are never matched by display name. Unknown input keys fail before any
request, and no input expands `@file`, a path, an environment variable, or a
URL.

A tool whose Elastic feature the stack lacks stays in the catalog and answers
`unsupported`. In a task tool, a later read that needs the feature makes only
its part or row `unavailable`. See [Limitations](Limitations.md).
`stack_info` and `stack_doctor` work on older stacks, so they can diagnose
one.

## Results

Every result names its target:

```json
{
  "target": {
    "profile": "analyst",
    "host": "kibana.example.test",
    "space": "default"
  },
  "data": {},
  "page": null
}
```

`host` is the Kibana host without path, query, or credentials. `data` is a
fixed projection of the object: for example, a rule list carries `rule_id`,
`name`, `type`, `enabled`, `severity`, `risk_score`, and `tags`, and a case
omits identities, assignees, connectors, and its version token. Fleet tools
never return raw inputs, variables, package metadata, or secret references.

### Lists and caps

Lists default to 50 rows and accept limits up to 200. A list result carries
`page` with `limit`, `returned`, `total`, `has_more`, and `truncated`.
`truncated` is true when rows were omitted; `total` and `has_more` are null
when the exact value is unknown. There is no result cursor: narrow a filter or
use a get to inspect a capped list.

### Errors

A failure carries the same target and an error object:

```json
{
  "target": {
    "profile": "analyst",
    "host": "kibana.example.test",
    "space": "default"
  },
  "error": {
    "kind": "permission",
    "http_status": 403,
    "code": "elastic_permission",
    "message": "The selected credential cannot read this data."
  }
}
```

`kind` uses the [CLI error kinds](CLI.md#errors). An Elastic failure has code
`elastic_<kind>` and a fixed message; the server never copies the upstream
message, request text, URLs, or credentials into an error. Local failures use
these codes:

| Code | Kind | Meaning |
| --- | --- | --- |
| `invalid_argument` | `error` | An input failed validation |
| `busy` | `error` | Four calls were already running |
| `deadline_exceeded` | `timeout` | The call passed the `--timeout` deadline |
| `result_too_large` | `unsupported` | Not even one row or object fits the output limit |

`stack_doctor` with a failing check is a successful result with `ok: false`,
not an error.

### Limits

| Limit | Value |
| --- | --- |
| Rows per list | Default 50, maximum 200 |
| Active calls | Four, shared by tool calls and [resource reads](#resources). A fifth is answered `busy` at once, with no queue and no Elastic request |
| Whole call | `--timeout`: default 30 seconds, allowed 1 to 120 |
| Structured result | 262,144 bytes |
| Outbound message | 1,048,576 bytes |
| Inbound message | 262,144 bytes; a longer line ends the connection |
| Elastic response body | 16 MiB |

A list that would pass the output limits stops between complete rows and is
marked `truncated`. Cancelling a call stops its client work and releases its
slot. A client disconnect cancels all active calls.

## Query tools

Start the server with `--allow-query-tools` to add synchronous ES|QL and Query
DSL tools for the life of the process:

```bash
elkctl --profile analyst --space default mcp serve --allow-query-tools
```

| Tool | Inputs |
| --- | --- |
| `search_esql` | A complete `query`, at most 65,536 bytes, and `limit` |
| `search_dsl` | `index`, a `query` clause object, optional `fields` and `sort`, and `limit` |

The setting cannot be changed through MCP. Without it, the two tools are absent
from the catalog and unknown to the server.

- `search_esql` appends `| LIMIT <limit+1>` to the query. Earlier stages and
  any earlier `LIMIT` run unchanged.
- `search_dsl` builds the request body from the query clause; it does not
  accept an arbitrary body, aggregations, a point in time, or `@file`. `index`
  is a comma-separated list of patterns made of letters, digits, `.`, `_`,
  `-`, and `*`; date math and cross-cluster patterns are rejected.
- On Elastic Cloud, the profile needs the Elasticsearch URL; see
  [Configuration](Configuration.md#environment-variables).

Access and retries:

- The tools can read every index the selected Elastic credential can read.
  Kibana space selection does not restrict Elasticsearch index access.
- Each query call makes one HTTP attempt, including on 429 and server errors.
  A later client call starts new work.
- Queries may invoke inference services. Row and output limits bound the
  returned data, not inference cost or the work of earlier query stages.
- Use Elastic privileges to control which indices and services the credential
  can reach.

## Resources and prompts

The server advertises exactly the `prompts`, `resources`, and `tools`
capabilities. The resource, template, and prompt lists are fixed: listing them
sends no Elastic request, needs no credential, and takes no call slot.

### Resources

`resources/list` returns the first five URIs below, `resources/templates/list`
the last four. A read runs the matching tool with fixed arguments, returns its
`{target, data, page}` JSON as `application/json` text, takes one of the four
call slots, and obeys `--timeout` and the [limits](#limits).

| URI | Tool and arguments |
| --- | --- |
| `elasticctl://stack/coverage/tactic` | `detection_coverage`, `group_by` `tactic`, `limit` 200 |
| `elasticctl://stack/coverage/technique` | `detection_coverage`, `group_by` `technique`, `limit` 200 |
| `elasticctl://stack/doctor` | `stack_doctor` |
| `elasticctl://stack/info` | `stack_info` |
| `elasticctl://stack/prebuilt-rules/status` | `rules_prebuilt_status` |
| `elasticctl://stack/alerts/{alert_id}` | `alerts_get` |
| `elasticctl://stack/cases/{case_id}` | `cases_get` |
| `elasticctl://stack/exception-lists/{namespace_type}/{list_id}` | `exceptions_get`, item `limit` 50 |
| `elasticctl://stack/rules/{rule_id}` | `rules_get` |

Percent-encode each id. `namespace_type` is `single` or `agnostic`. The rule
template takes a `rule_id` only: a display name is not found. A URI holds no
host, profile, space, credential, query, or fragment.

A failed read is a JSON-RPC error. Current: `2026-07-28`; legacy: `2025-11-25`.

| Cause | Current | Legacy | `message` | `data.code` |
| --- | --- | --- | --- | --- |
| Bad URI, an id the tool refuses, Elastic `not_found`, or a rule with another `rule_id` | `-32602` | `-32002` | `Resource not found` | no `data` |
| A `cursor` on a list request | `-32602` | `-32602` | `Invalid cursor` | no `data` |
| Four calls already running | `-32603` | `-32603` | `Resource read failed` | `busy` |
| The `--timeout` deadline | `-32603` | `-32603` | `Resource read failed` | `deadline_exceeded` |
| Text above the output limit | `-32603` | `-32603` | `Resource read failed` | `result_too_large` |
| Any other failure | `-32603` | `-32603` | `Resource read failed` | `elastic_<kind>` |

`data` holds only `kind`, `http_status`, and `code`, as in [Errors](#errors).
A cancelled read gets no response.

### Prompts

A prompt returns one fixed message that asks the model to call a task tool
with the given arguments. `prompts/get` checks the arguments and reads
nothing; the model then calls the tool through the client's usual approval.

| Prompt | Arguments | Task tool |
| --- | --- | --- |
| `check_rule_readiness` | `rule` | `rule_readiness` |
| `review_detection_coverage` | `group_by`, optional | `detection_coverage` |
| `review_rule_health` | `rule`; `since`, optional | `rule_health` |
| `triage_alert` | `alert_id`; `since`, optional | `alert_context` |

`rule` and `alert_id` are exact ids of 1 to 256 characters from `A-Z`, `a-z`,
`0-9`, `.`, `_`, `:`, and `-`, so pass a `rule_id`, not a name. `since` uses
the [task tool](#task-tools) grammar with default `24h`; `group_by` is
`technique` (default), `tactic`, `index_pattern`, or `integration`. A bad
argument fails with `-32602` and `Invalid prompt arguments`, an unknown prompt
with `-32602` and `Unknown prompt`.

### Use them in Claude Code

With the server registered as `elasticctl`, type `@` to pick a resource or
write `@elasticctl:elasticctl://stack/info`; see
[Use MCP resources](https://code.claude.com/docs/en/mcp#use-mcp-resources).
Type `/` to list prompts as `/elasticctl:triage_alert (MCP)`, or run
`/mcp__elasticctl__triage_alert <alert_id> 7d` with whitespace-separated
arguments; see
[Use MCP prompts as commands](https://code.claude.com/docs/en/mcp#use-mcp-prompts-as-commands).

## Server instructions

The server returns fixed instructions when a client connects. They say that
the server reads one operator-selected deployment and changes neither Elastic
nor local files, send a model to the task tools first for a question that
spans objects and to the `_list` and `_get` tools for the objects an answer
names, and mark text inside results as data, not instructions. They name no
host, profile, version, or object.

## Returned data is untrusted

Returned text and nested content are untrusted tool data. Never execute it,
fetch its URLs, or treat it as instructions. It may contain sensitive
information visible to the selected credential. The server excludes configured
credentials and raw upstream error details, but rule text, dashboard content,
and queried document fields are authored by people and can still contain
secrets.

## Tested clients

Claude Code 2.1.322 (protocol `2026-07-28`) and Codex CLI 0.167.0
(`2025-11-25`) passed on the local lab with the four task tools, `rules_list`,
and a resource template; Codex also read a listed resource. Claude Code ran a
prompt; Codex has no prompt entry point. Under `claude -p`, an `@` mention did
not read the resource. The server supports exactly these two revisions. The
[0.8.2 findings](https://github.com/dannyota/elasticctl/blob/master/docs/conformance/v0.8.2/findings.md) list each request.

See [Security](Security.md#mcp-server) for what the server can and cannot
reach.
