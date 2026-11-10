[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 2. Decisions and alternatives

Each row is final for 0.8. Sources and measurements are in
[research](../../plans/v0.8-research.md) and [section 11](11-measured-behavior.md#11-measured-behavior).

| # | Decision | Reason |
| --- | --- | --- |
| D1 | Ship four task tools: `alert_context`, `rule_health`, `detection_coverage`, `rule_readiness`. | Each answers one question that today takes three to twenty mirror calls, and each has a fixed, capped request plan. |
| D2 | Composition lives in a new `elasticctl_api::compose` module. MCP adapters only validate, call, and project. | Orchestration belongs in `-api`; a later CLI command can render the same typed values. |
| D3 | Requests inside one call run in a fixed order, one at a time. | Upstream concurrency stays at the 0.7 bound of four, and recorded mocks can assert the exact sequence. |
| D4 | The first read of a tool is primary: its failure fails the call. Later reads are parts with their own status. | The answer stays useful when one family is missing or forbidden, and never hides which part failed. |
| D5 | `auth`, `connection`, and `timeout` in any part fail the whole call. | A broken credential or target fails every later read; continuing only burns the deadline. |
| D6 | No soft deadline. The 0.7 whole-call deadline stays the only time bound. Caps are sized by measurement so the worst call stays under half the default deadline. | One rule is easier to prove than per-part budgets. Section 11.1 makes the latency gate explicit. |
| D7 | Findings are a closed list of static codes computed locally. | A model gets a stable signal that no remote text can forge. |
| D8 | `detection_coverage` reads the corpus in sorted 500-rule pages and verifies it. | One 10,000-row request returned 19.3 MB on both trial stacks, above the 16 MiB body cap. |
| D9 | The bounded, name-ordered `rules_list` page ships in 0.7.5, not in 0.8. 0.8.0 starts from it and changes nothing in that read. | Owner decision, 2026-11-10. 0.7.4 returns `elastic_unsupported` on both trial stacks at 2,263 rules, and a fix should not wait for a minor. |
| D10 | `rules_list` gains optional `technique` and `tactic` filters on top of the 0.7.5 page. | The follow-up to a coverage row is "which rules"; Kibana filters it server-side in one request. |
| D11 | `rule_readiness` resolves index patterns through Elasticsearch `GET /_resolve/index/{pattern}` and returns counts only. The read is on by default, with no new flag. | It is the public metadata read for this question, and counts keep index names out of results. The owner approved the default on 2026-11-10; section 10.4 states the added disclosure. |
| D12 | Related cases come from `GET /api/cases/alerts/{alert_id}`. | It is the documented public route. The `kibana.alert.case_ids` alert field is unmeasured. |
| D13 | Resources use `elasticctl://stack/...` URIs with no host, profile, space, credential, or local path. | The server has one fixed target; target identity already travels in the result body. |
| D14 | `resources/list` is a fixed list of five URIs and performs no Elastic request. | Clients list resources when they connect. Discovery stays free of I/O and of data disclosure, as in 0.7. Owner decision, 2026-11-10. |
| D15 | Each resource is one existing tool called with fixed arguments, and its text equals that tool's text content. | One projection, one limit set, one proof. |
| D16 | No subscriptions, no list-changed notifications, no completion. | The lists never change, updates would need background polling, and neither evidence client is verified to use completion. |
| D17 | Four prompts, one per task tool. Each is static text plus validated arguments and performs no I/O. | Prompts are user-invoked shortcuts. The data read stays a visible tool call under the client's permission flow. |
| D18 | Prompt arguments are single tokens from a strict grammar. | Claude Code splits prompt arguments on whitespace, and argument text is inserted into model-visible instructions. |
| D19 | Keep all 22 mirror tools unchanged. Catalog size is 24 by default and 26 with query tools. | Task tools return ids; mirror tools are the drill-down. Nothing is removed or renamed. |
| D20 | No server-side progressive discovery. | Both evidence clients defer tool definitions themselves, and the protocol forbids a tool list that changes as a side effect of a request. |
| D21 | Durable protocol tasks are not in 0.8. | Every call ends within 120 seconds, tasks are a Beta extension, and a durable handle needs local state this release does not have. |
| D22 | The conformance contract lands in 0.8.0, and every 0.8 release passes the three-flavor matrix. | Decoder measurements start while the trial stacks exist. The gate is not weakened for a short trial; if the window closes, the owner supplies replacement stacks. |
| D23 | Fleet integration policies are read through a one-request collector capped at 1,000 policies. Above the cap the `integrations` part is `unavailable`. | The request maximum is then enforced, and a policy count is never reported from an incomplete read. |
| D24 | A value that becomes a URL path segment is refused when it is exactly `.` or `..`. | Percent-encoding keeps dots, and URL parsing removes dot segments, which would move the request off the fixed prefix. |
| D25 | The corpus read stops at 4,000 matching rules. | Two verified passes at the cap are 16 requests, which the measured page time keeps inside the latency gate. |

### Alternatives where the trade-off matters

**Concurrent fan-out inside a call (rejected for D3).** Running the secondary
reads of `alert_context` in parallel would cut latency from about 4 seconds to
about 1. It would also raise upstream concurrency to four calls times the
fan-out and make the request order nondeterministic in tests. Measured
single-request latency is 0.15 to 0.45 seconds on both trial stacks, so the
sequential worst case fits the gate. Revisit only if section 11.1 fails.

**Dynamic resource listing (rejected for D14).** Listing custom rules and
open cases would make `@` mention useful in Claude Code. It would also send
three or four Elastic requests whenever a client connects, fail the list when
the stack is down, and hand object names to the client before any tool call.
A dynamic list is a compatible later addition, because the protocol lets the
list change over time. The owner decided against it for 0.8 on 2026-11-10.

**Prompts that embed live data (rejected for D17).** `prompts/get` could run
the tool and return its result as an embedded resource, saving one model
turn. It would add a second path to Elastic with protocol-level errors and no
tool permission prompt. Codex CLI is not verified to surface prompts, so the
tool path must stand alone anyway.

**Deprecating mirror tools (rejected for D19).** Fewer tools would shrink the
58,671-byte catalog. Removal is a break under shared spec 11.1, the task
tools do not cover dashboards, data views, Fleet, or search, and client-side
tool search already keeps deferred definitions out of the model context.

**`kibana.alert.case_ids` for related cases (deferred for D12).** Reading the
field from the alert would save one request. No trial alert carries the field
today, so its presence is unmeasured. Measurement M2 records it; switching
later changes no schema.

**One merged rule tool (rejected for D1).** Merging `rule_health` and
`rule_readiness` would give one call per rule and a worst case above 40
requests across Kibana, Elasticsearch, and Fleet. Two tools keep each plan
under 30 requests and keep a Fleet or Elasticsearch outage from degrading the
execution answer.
