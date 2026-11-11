# elasticctl 0.8.2 conformance findings

All twelve contracts passed on all three targets, two product clients ran the
ten-step script on the lab with no server defect, and the protocol tests now
cover the whole 0.8 surface at once. No server code changed in this patch.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 12 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 12 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 12 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `3e8cbbefce62f99aa5b8d120b71e9b55843b29a6`.
Hosted ran from `2026-11-10T17:20:03Z` to `17:39:53Z`. Serverless first ran
alongside it from `17:19:43Z`: the `search` contract passed with its own
cleanup, and the audit after it then failed on a connection error, which
stops a leg. Serverless ran again alone from `17:40:22Z` to `17:55:09Z`; its
baseline check at start found the stack clean, and all twelve passed. The
self-managed leg is the Live lab run on the release pull request from
`17:25:21Z` to `17:36:57Z`. Later commits change the stdio shim script and two
offline timing tests, plus documents; none changes what a contract sends or
checks.

The 0.8.0 latency gates still hold. Slowest call of each tool, from the public
whole-second lines:

| Tool | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 |
| --- | --- | --- | --- |
| `alert_context` | 2 s | 3 s | 1 s |
| `rule_health` | 2 s | 2 s | 1 s |
| `rule_readiness` | 6 s | 7 s | 2 s |
| `detection_coverage`, two calls | 4 s, 3 s, 5 pages | 5 s, 4 s, 5 pages | 3 s, 3 s, 8 pages |

## Protocol tests

`crates/elasticctl-mcp/tests/task_surface_conformance.rs` passed all nine
tests, five runs in a row; no server defect was found.
Through the rmcp client it validates a success and a failure of every one of
the 26 tools against the tool's `outputSchema`, and the text of the nine
resource shapes against the schema of their tool. Exact request counts with the recording mock:

| Input | `alert_context` | `rule_health` | `rule_readiness` | `detection_coverage` | `rules_list` |
| --- | --- | --- | --- | --- | --- |
| Maximum work | 19 | 14 | 29 | 8 (4,000 rules), 16 (second pass) | 1, and 4 for an empty source-only page |
| Degraded | 18 (missing list) | 13 (missing list) | 28 (exclusion), 21 (1,001 policies) | 1 (4,001 rules) | |

Mixed admission held two tool calls and two resource reads, answered a fifth
call and a fifth read `busy`, and still served `prompts/get` and all four list
requests. A 262,145-byte line after a resource read ended the connection with
only the static diagnostic on both paths, and a resource text at the
structured cap passed while one byte more failed. A credential-shaped sentinel
placed in every excluded upstream field never reached stdout or stderr across
the 24 tools, nine reads, and four prompts.

## Product clients

Two product clients ran the ten steps against the local lab, never a trial
deployment, because tool results carry `target.host` and a model-driven client
sends them to its model provider.

| Client | Version | Negotiated protocol | Version path |
| --- | --- | --- | --- |
| Claude Code | 2.1.322 | `2026-07-28` | `server/discover`, then per-request `_meta` |
| Codex CLI | 0.167.0 | `2025-11-25` | `initialize` |

Host: macOS 27.2. Lab: self-managed 9.5.1, booted with `lab/up.sh` and
seeded with the full `lab/seed.sh`, prebuilt rules included. Server:
`elasticctl` 0.8.2 built at source commit
`6884c30bf704092cc18590e8f8b51cfcd2e63a2a`. The run took place from
`2026-11-11T02:21:21Z` to `2026-11-11T02:32:53Z`.

Each client run started its own server through `scripts/mcp-stdio-shim.sh`,
one log directory per server process, so every frame belongs to one step. The
shim captured 166 JSON-RPC frames in total. No frame broke the line
protocol, and no response was a JSON-RPC error. The only tool errors were the
ones steps 5 and 9 ask for, one per step for each client.

Before the run, the CLI imported one marker rule,
`elasticctl-sample-2b-probe`, with one MITRE ATT&CK `threat` entry, and one
marker exception list that the rule references. Lab teardown was the cleanup.

### Launch

The scratch client configuration lived outside the repository. No
`.mcp.json`, `.vscode/mcp.json`, user client setting, or `mcp add` entry was
created. Each command ran from a scratch working directory with every
inherited `CLAUDE*` variable removed except `CLAUDE_CONFIG_DIR`.

```bash
claude -p "<prompt>" --mcp-config <step>/mcp.json --strict-mcp-config \
  --allowed-tools mcp__elasticctl__<each tool>,ToolSearch,ListMcpResourcesTool,ReadMcpResourceTool \
  --permission-mode dontAsk --permission-prompts none \
  --output-format stream-json --verbose --debug-file <step>/claude-debug.log \
  --no-session-persistence --model opus

codex exec --json --ephemeral --skip-git-repo-check --ignore-user-config \
  --disable shell_tool -C <work> -s read-only -c 'approval_policy="never"' \
  -c 'mcp_servers.elasticctl.command="<bash>"' \
  -c 'mcp_servers.elasticctl.args=[<shim and server arguments>]' \
  -c mcp_servers.elasticctl.startup_timeout_sec=30 \
  -c mcp_servers.elasticctl.tool_timeout_sec=120 \
  -c mcp_servers.elasticctl.required=true -o <step>/last-message.txt -- "<prompt>"
```

The Claude stanza in `<step>/mcp.json`. `<launcher>` drops the
`ELASTICCTL_*` target variables, pins `PATH`, and runs
`<shim> <step>/proc-<time>-<pid> -- <elasticctl> ...`, one log directory per
server process. Codex gets the same command and arguments through the two
`mcp_servers.elasticctl` overrides.

```json
{"mcpServers": {"elasticctl": {"type": "stdio", "command": "<bash 4.4+>",
  "args": ["<launcher>", "<step>", "<shim>", "<elasticctl>", "--config",
           "<cfg>", "--profile", "lab", "mcp", "serve"],
  "env": {}}}}
```

## M11: methods each client sends

From the shim frames only. A method is `observed` when the client sent it at
least once, `not sent` when it never did.

| Method | Claude Code | Codex CLI |
| --- | --- | --- |
| `server/discover` | observed, every server process | not sent |
| `initialize` | not sent | observed, every server process |
| `tools/list` | observed, once per server process | observed, once per server process |
| `resources/list` | observed, every server process | observed, when asked to list resources |
| `resources/templates/list` | not sent | not sent |
| `resources/read` | observed | observed |
| `prompts/list` | observed, every server process | not sent |
| `prompts/get` | observed | not sent |
| `completion/complete` | not sent | not sent |
| `subscriptions/listen` | not sent | not sent |

Both clients read a template URI that `resources/list` does not list,
`elasticctl://stack/rules/<rule_id>`, without sending
`resources/templates/list`. Neither sent a method the server does not
advertise.

## M12: tool deferral and server instructions

| Measurement | Claude Code | Codex CLI |
| --- | --- | --- |
| The 24 tool definitions are deferred | observed: deferred. `ToolSearch` ran before the first `elasticctl` call in every step that called a tool. | not testable: `--json` output reports no tool-search event |
| The server instructions are loaded | observed: loaded. The step 1 answer quoted their first sentence. | observed: loaded. The step 1 answer quoted their first sentence. |

The server sent the instructions to every server process of both clients.

## Client steps

| Step | Request | Claude Code | Codex CLI |
| --- | --- | --- | --- |
| 1 | List the elasticctl tools | observed: 24 tools, `tools/list` once | observed: 24 tools, `tools/list` once |
| 2 | Health of the marker rule by `rule_id` | observed: `rule_health` and its result | observed: `rule_health` and its result |
| 3 | Coverage by technique, then the rules behind the marker technique | observed: `detection_coverage` (`group_by` `technique`), then `rules_list` with `technique` | observed: the same two calls |
| 4 | Data readiness of the marker rule | observed: `rule_readiness` and its result | observed: `rule_readiness` and its result |
| 5 | Triage an absent alert id | observed: `alert_context` with tool error `elastic_not_found`, kind `not_found` | observed: the same |
| 6 | Reference `elasticctl://stack/info` | not sent: the `@elasticctl:elasticctl://stack/info` mention in a `claude -p` prompt sent `resources/list` but no `resources/read` | observed: `resources/list`, then `resources/read` of `elasticctl://stack/info` |
| 7 | Read `elasticctl://stack/rules/<rule_id>` | observed: `resources/read` through the client's resource tool, answered with the rule | observed: `resources/read`, answered with the rule |
| 8 | Invoke `review_rule_health` | observed: `prompts/get`, then a `rule_health` call with the prompt's arguments | not sent: the client has no prompt entry point and answered that it has none |
| 9 | `rules_list` with `limit: 0` | observed: sent; tool error `invalid_argument` | observed: sent; tool error `invalid_argument` |
| 10 | Exit | observed: every server process ended with its client run; no process left | observed: the same |

## Client observations

These are client behaviors, not server defects. None changes the server in
this patch.

- Under `claude -p`, an `@server:uri` mention of an MCP resource does not read
  the resource. Interactive Claude Code resolves the mention; scripted use
  should name the resource and let the model read it.
- Codex CLI 0.167.0 exposes no MCP prompt entry point, so the four
  prompts are reachable only from Claude Code among the tested clients.
- Claude Code writes `unknown format "uint64" ignored in schema` lines to
  stderr, and the same for `uint` and `uint16`, for integer `format`
  annotations in the tools' output schemas. JSON Schema treats an unknown
  format as an annotation, the client ignores it, and no call failed
  because of it. The schemas are unchanged in this patch.
- Codex CLI writes `Reading additional input from stdin...` to stderr when
  stdin is not a terminal. It has no effect on the run.
- A `claude -p` run started from inside another Claude Code session inherits
  that session's `CLAUDE_CODE_*` variables, including its messaging socket,
  unless the caller removes them. The run above removed them.

## Client evidence limits

- Model-driven clients ran only on the local lab. Raw frames, transcripts, and
  client logs stay private; this page records methods, tool names, and
  outcomes only.
- A behavior is `observed` from the frames, `not sent` when the frames show no
  such request, or `not testable` when neither the frames nor the client's own
  output can show it. Client documentation never counts as a test.
- The prompts name the tool and arguments for steps 2 to 5 and 9, so those
  steps test what each client sends, not whether its model picks the tool
  unprompted.
- Each client ran once per step. Versions other than those above are untested.

## Cleanup and evidence limits

Every contract and end-of-leg audit passed: rule counts, the default data
view, Fleet marker inventories, and installed package names and versions
matched their baselines, and no marker object remained. The lab fill of 4,000
rules was removed and the lab destroyed with its runner. The client lab was
torn down with `lab/down.sh`, leaving no lab container, volume, or network.

No live request capture is claimed: the Cloud and lab legs keep raw results in
private ignored logs, and only whole-second timing lines reach public output.
