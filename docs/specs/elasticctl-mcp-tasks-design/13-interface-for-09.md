[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 13. Interface for 0.9

0.9 adds mutation through plan-and-confirm. It is specified in
[`elasticctl-mcp-mutation-design.md`](../elasticctl-mcp-mutation-design.md),
whose section 10 states what it needs from 0.8. This section is the 0.8 side
of that agreement. 0.8 designs no mutation.

### What 0.8 guarantees

| Guarantee | Where 0.8 enforces it |
| --- | --- |
| The tool catalog is a pure function of `ServerOptions`. The router resolves a name against that catalog before it decodes arguments. | `catalog::definitions_for` and `dispatch_target`; 0.8 adds no other input. |
| Server `instructions` come from one function of `ServerOptions`. Tests pin the literal for the 0.8 options, not a global constant. | `server/handler.rs`; 0.9 adds a second literal for its option. |
| Every 0.8 tool is registered with `readOnlyHint: true` and calls no `plan_*` or `apply_*` function in `-api`. | Catalog tests and the route proofs of section 10.5. |
| No 0.8 tool name starts with `plan_` or ends with `_plan`. | The four new names are in section 7. |
| Resources are a fixed table of read tools with fixed arguments. `resources/read` cannot reach a tool outside that table. | `resources.rs`; the table is a constant. |
| The `plans` URI namespace is reserved and unused. | Section 8.1 rejects every authority except `stack`. |
| `tools/call` and `resources/read` share one admission, deadline, and cancellation helper. | `server/admission.rs` from 0.8.1. |
| Prompts are static, read-only, and name no plan tool. | Section 9. |
| The twelfth conformance contract and the `v0.8` validator list land in 0.8.0. | Section 12.3. |
| The stdio shim and the scratch client configuration of the 0.8.2 matrix are kept. | `scripts/mcp-stdio-shim.sh` and the 0.8.2 findings. |
| `rmcp` stays at `=3.9.0` with `server`, `macros`, and `transport-io`. | Section 3. 0.9 owns any feature it adds. |

### What 0.9 may change

These 0.8 statements hold for the read-only server. 0.9 may narrow them to
"when no mutation class is enabled":

- every tool carries the read-only annotation set;
- the tool list depends only on the query flag;
- the instructions say the server never changes Elastic;
- the SDK features `elicitation` and `request-state` are off.

The advertised server capability object does not need to change for 0.9.

### What 0.8 leaves ready

- **Stable identities in every answer.** Task results name rules by
  `rule_id`, exception lists by `list_id` and `namespace_type`, cases and
  alerts by id. A planner can take them as input without a name lookup.
- **Target context in every result.** `{profile, host, space}` is in each
  tool result and resource body, so a plan can be compared with the target
  it was made for.
- **Findings as codes.** `rule_disabled`, `exception_list_missing`, and the
  other codes are typed signals a person can cite when asking for a change.
  They are evidence, never authorization.
- **A static error allowlist.** The protocol-error allowances of section
  10.3 are closed lists. A new message or code is one entry plus its test.
- **A resource registry with room for a second namespace.** Adding
  `elasticctl://plans/{plan_id}` later is additive. It would also need
  decision D14 restated as "no Elastic request" rather than "fixed list",
  because a plan list changes over time.
- **Two measured facts.** An unfiltered rule read exceeds the body cap on
  both trial stacks, and default-order paging can return duplicate rows
  while rules are written. A planner should read named objects by id.

### Shared files and order of work

Parallel tasks own separate files. A file that 0.7.5, 0.8, and 0.9 all edit
has one serialized owner task in each version, and a later version's owner
starts only after the earlier one is merged. This mirrors section 10 of the
0.9 design.

| Shared file | 0.7.5 | 0.8 owner | 0.9 owner |
| --- | --- | --- | --- |
| `crates/elasticctl-api/src/rules.rs`, `src/rules_ops.rs` | `find_first_by_name`, `list_page` | 0.8.0 Task 2 | 0.9.0 Task 2 |
| `crates/elasticctl-api/src/lib.rs`, `src/alerts.rs`, `src/cases.rs`, `src/exceptions.rs`, `src/exceptions/list_endpoints.rs`, `src/fleet/integration_policy_ops.rs` | none | 0.8.0 Task 3 | 0.9.0 Task 2 for `lib.rs`; 0.9 does not edit the others |
| `crates/elasticctl-api/src/alerts_ops.rs`, `src/cases_ops.rs`, `src/health.rs` | none | not edited by 0.8 | 0.9.0 Task 2 |
| `crates/elasticctl-mcp/src/catalog.rs`, `src/tools/mod.rs`, `src/server.rs`, `src/lib.rs`, `tests/support/mod.rs` | none | 0.8.0 Task 3, then the 0.8.1 primary stubs and Task 2 | after 0.8.2 |
| `crates/elasticctl-mcp/src/tools/rules.rs` | `rules_list` adapter | 0.8.0 Task 2, then Task 3 | after 0.8.2 |
| `crates/elasticctl-mcp/src/server/handler.rs`, `src/server/admission.rs`, `src/bounded_io.rs`, `src/result.rs` | none | 0.8.0 Task 5, then 0.8.1 Tasks 1C and 2 | after 0.8.2 |
| `crates/elasticctl-cli/tests/live.rs`, `tests/mcp.rs` | none | 0.8.0 Tasks 6A and 5, then 0.8.1 Tasks 4 and 3 | after 0.8.2 |
| `xtask/src/conformance/contracts.rs`, `xtask/src/conformance.rs`, `scripts/check-conformance-reports.sh` | none | 0.8.0 Task 6B | after 0.8.2 |
| `README.md`, `CHANGELOG.md`, shared specs, `AGENTS.md` | its own entry | the last primary task of each version | the last task of each version |

Order:

1. 0.7.5 merges first. 0.8.0 Task 2 starts from it.
2. 0.8.0 Tasks 2 and 3 are the only 0.8 tasks that edit an existing `-api`
   source file. Task 3 starts after Task 2 is merged. The four tool tasks
   that follow create new files only.
3. 0.9.0 Task 2 starts when `master` holds 0.7.5 and the merged 0.8.0 Tasks
   2 and 3. No 0.9 work edits `lib.rs`, `rules.rs`, or `rules_ops.rs` before
   that.
4. Every 0.9 task that edits an `-mcp`, CLI, or `xtask` file in the table
   starts after 0.8.2 is released.

"Request plan" in this document means the fixed read order inside a task
tool. In tool names, results, and operator text, "plan" is reserved for the
stored mutation plan of 0.9.
