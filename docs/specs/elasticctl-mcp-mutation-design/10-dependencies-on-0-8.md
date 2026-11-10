[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 10. 0.8 dependencies

Read against the [0.8 design](../elasticctl-mcp-tasks-design.md) of
2026-11-10. Its
[section 13](../elasticctl-mcp-tasks-design/13-interface-for-09.md#13-interface-for-09)
is the 0.8 side of this page and guarantees each row of the first table
below.

0.9 needs no 0.8 feature at run time. A plan is made, read, and applied with
0.9 tools alone. The needs below are about shared code and shared words.

### What 0.9 needs 0.8 to keep

| Need | Why |
| --- | --- |
| The tool catalog stays a pure function of startup options, resolved before arguments are decoded. | The class gate is one more input to that function. |
| Server `instructions` are built from startup options, and tests do not pin one constant as the only legal value. | 0.9 swaps one sentence when a class is enabled ([section 3](03-startup-opt-in-and-catalog.md#server-instructions)). |
| The resource tables stay fixed lists of read tools. `resources/read` never resolves to a planner or a plan tool. | A resource read has no confirmation step and returns protocol errors. |
| The `plans` resource namespace stays reserved and unused. | 0.9 leaves it unused too; see below. |
| No 0.8 tool is registered with `readOnlyHint: false`, and none calls a `plan_*` or `apply_*` function in `-api`. | The route proofs of 0.9 assume every write comes from `plan_apply`. |
| No 0.8 tool name ends in `_plan` or starts with `plan_`. | 0.9 reserves both patterns. The four 0.8 names do not collide. |
| `tools/call` and `resources/read` keep one admission, deadline, and cancellation helper (`server/admission.rs` from 0.8.1). | `plan_apply` uses it, and adds a release and re-take of the permit for the legacy wait. |
| The single outbound rewrite of JSON-RPC errors (0.8 section 10.3) touches errors only. | An `input_required` result and a server-sent `elicitation/create` request must leave unchanged. 0.9 adds no protocol error message; its new codes are tool errors. |
| The twelfth conformance contract and the `v0.8` validator list land in 0.8.0. | 0.9.2 appends the thirteenth and a `v0.9` list. |
| `scripts/mcp-stdio-shim.sh` and the scratch client configuration of the 0.8.2 client matrix are kept. | The 0.9 client matrix reuses them. |

0.8 uses "request plan" for the fixed read order inside a task tool. That is
internal wording. In tool names, results, and operator text, "plan" means a
stored mutation plan from 0.9 on.

### What 0.9 changes that 0.8 set

| 0.8 statement | 0.9 change |
| --- | --- |
| `rmcp` features are `server`, `macros`, `transport-io`; `elicitation` stays off. | 0.9.0 adds `elicitation` for the legacy path. `request-state` stays off. |
| Every tool carries the read-only annotation set. | True for every tool outside [section 3](03-startup-opt-in-and-catalog.md#annotations). |
| The tool list depends only on the query flag. | It also depends on `--allow-mutations`. |
| "It never changes Elastic or local files." | Replaced when a class is enabled. |
| `ServerOptions` fields as 0.8 leaves them. | One more field, `allow_mutations`. |
| The advertised capability object. | Unchanged. Elicitation is a client capability; the server declares nothing new and no extension. |

### Resources and prompts for plans

0.9 adds none.

- **No plan resource.** `plan_get` and `plan_list` already return plans as
  tool results under the normal permission flow. A `plans` resource would be
  a second read path with protocol-level errors, and listing open plans would
  make `resources/list` change from call to call, which 0.8 decision D14
  rules out. Adding `elasticctl://plans/{plan_id}` later is additive.
- **No mutation prompt.** A prompt that tells a model to plan and apply adds
  no safety, because the safety is in `plan_apply`. Codex CLI is not verified
  to surface prompts. The four 0.8 prompts stay read-only and do not mention
  plan tools.

### Shared files and order of work

Parallel tasks own separate files
([workflow](../../../instructions/workflow.md)). A file that both bands edit
is owned, in each version, by one serialized integration task, and the 0.9
task runs only after the earlier version's task is merged.

| Shared file | Edited by | 0.9 owner |
| --- | --- | --- |
| `crates/elasticctl-api/src/lib.rs` | 0.8.0 Task 3 (`compose`), 0.9.0 (`observe`, re-exports) | 0.9.0 Task 2 |
| `crates/elasticctl-api/src/rules_ops.rs` | 0.7.5 (`list_page`), 0.8.0 Task 2, 0.9.0 (module lines, `plan_set_enabled` wrapper) | 0.9.0 Task 2 |
| `crates/elasticctl-api/src/alerts_ops.rs`, `cases_ops.rs`, `health.rs` | 0.9.0 only | 0.9.0 Task 2, as one owner for every existing `-api` file |
| `crates/elasticctl-core/src/transport.rs` and its tests | 0.9.0 only | 0.9.0 Task 1 |
| `crates/elasticctl-mcp/src/catalog.rs`, `src/tools/mod.rs`, `src/server.rs`, `src/lib.rs`, `tests/support/mod.rs` | 0.8.0 Task 3, 0.8.1, 0.9.0, 0.9.1 | 0.9.0 Task 6, then 0.9.1 Task 1 |
| `crates/elasticctl-mcp/src/server/handler.rs`, `src/server/admission.rs` | 0.8.0 Task 5, 0.8.1, 0.9.0 | 0.9.0 Task 9 |
| `crates/elasticctl-cli/src/cli.rs`, `src/main.rs`, `src/cmd/mcp.rs` | 0.8 where it touches the serve command, 0.9.0 | 0.9.0 Task 10 |
| `crates/elasticctl-cli/tests/live.rs` | 0.8.0 Task 6A, 0.9.0, 0.9.2 | 0.9.0 Task 11, then 0.9.2 Task 2A |
| `xtask/src/conformance/contracts.rs`, `xtask/src/conformance.rs`, `scripts/check-conformance-reports.sh` | 0.8.0 Task 6B, 0.9.2 | 0.9.2 Task 2B |
| `README.md`, `CHANGELOG.md`, shared specs, `AGENTS.md` | every version | The integrator's last task in each version |

Order:

1. 0.9.0 Task 2 starts when `master` holds 0.7.5 and the merged 0.8.0 Tasks
   2 and 3. No 0.9 work edits `lib.rs` or `rules_ops.rs` before that.
2. The 0.9.0 `-api` tasks that follow Task 2 create new files only and run in
   parallel.
3. Every 0.9 task that edits an `-mcp`, CLI, or `xtask` file in the table
   starts after 0.8.2 is released.

`rules_ops::list_page`, the bounded page behind `rules_list`, ships in 0.7.5,
not in 0.8.0. 0.9 does not call it. It matters to 0.9 in two ways: it is one
more earlier edit to `rules_ops.rs`, and the live and client runs of 0.9 use
`rules_list` to find marker rules, which fails on the trial stacks before
0.7.5.

0.8 measured two facts that 0.9 relies on: an unfiltered rule read exceeds the
16 MiB body cap on the trial stacks, and default-order paging can return
duplicate rows while rules are being written. No 0.9 planner or check lists
rules. Each reads named objects by id.
