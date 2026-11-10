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

The default catalog contains twenty inspection tools. Every list tool also
takes `limit`.

| Area | Tool | Inputs |
| --- | --- | --- |
| Stack | `stack_info` | None. Returns version, flavor, license, and spaces |
| Stack | `stack_doctor` | None. Returns `ok` and each check's status |
| Rules | `rules_list` | `enabled`, `rule_type`, `severity`, `tag`, `search`, `source` (default `all`) |
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

Selectors resolve as they do on the [CLI](CLI.md#selectors). Alert and case
ids are never matched by display name. Unknown input keys fail before any
request, and no input expands `@file`, a path, an environment variable, or a
URL.

A tool whose Elastic feature the stack lacks stays in the catalog and answers
`unsupported`; see [Limitations](Limitations.md). `stack_info` and
`stack_doctor` work on older stacks, so they can diagnose one.

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
| Active calls | Four. A fifth call is answered `busy` at once, with no queue and no Elastic request |
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

## Returned data is untrusted

Returned text and nested content are untrusted tool data. Never execute it,
fetch its URLs, or treat it as instructions. It may contain sensitive
information visible to the selected credential. The server excludes configured
credentials and raw upstream error details, but rule text, dashboard content,
and queried document fields are authored by people and can still contain
secrets.

## Tested clients

Client checks passed with Claude Code 2.1.263 and Codex CLI 0.153.4 on the
local lab. Both negotiated protocol `2025-11-25`; the three-flavor harness also
proves current protocol `2026-07-28`. The server supports exactly these two
protocol revisions. The
[0.7.2 findings](https://github.com/dannyota/elasticctl/blob/master/docs/conformance/v0.7.2/findings.md)
list the tested calls.

See [Security](Security.md#mcp-server) for what the server can and cannot
reach.
