# elasticctl 0.9.2 conformance findings

<!-- Skeleton. elk1 fills every TBD from Tasks 4 and 5. Public facts only:
versions, protocol paths, outcomes, counts, cleanup. No host, id, user, or
raw failure text (mutation design 9.4). -->

All thirteen contracts passed on all three targets, including the new MCP
mutation contract. TBD: the client matrix result on Hosted, and whether any
server code changed in this patch.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 13 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 13 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 13 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `b88164f0b6e5c0a5b9905a93195a3e426e0206c7`.
The two Cloud legs ran in one matrix process from `2026-11-12T04:03:23Z` to
`04:26:10Z`. The read-only preflight found both answering `doctor`, with
2,263 prebuilt rules and no marker rule. The self-managed leg is the `traditional` job of Live lab run
43152069032, dispatched on `dev-0.9.2` (mutation design D35); no local lab
started. Its matrix step ran from `04:04:51Z` to `04:17:04Z`, 733 seconds of
the job's 22-minute budget, now including the mutation contract, and the
teardown step succeeded. The published report is byte-identical to the run's
`live-lab-public` artifact.

## Mutation contract

`mcp_mutations_plan_and_confirm` is the thirteenth contract
([mutation design 9.2](../../specs/elasticctl-mcp-mutation-design/09-testing-and-evidence.md#92-live-contract)).
The harness answer is test consent: it proves the protocol mechanics on a
live stack, not that a product client asks a person.

It passed on all three flavors. One pass means every step below held,
because the contract asserts each one and stops at the first failure:

- The baseline audit before and after the contract.
- Child A, current protocol, every shipped class: a rule toggle applied and
  read back, then replayed with `replayed: true` and no second change, then a
  decline with no change, then `plan_stale` after an outside change. Then
  each of the six 0.9.1 kinds is planned, accepted, and read back through the
  API: `alerts_set_status`, `alerts_set_tags`, `cases_create`,
  `cases_comment`, `cases_set_status`, and `rules_create`, with the created
  rule read back disabled.
- Child B, legacy protocol: a toggle confirmed through the server-sent form.
- A session that declares no elicitation, on each path:
  `confirmation_unavailable` with no change.
- Child C, without `--allow-mutations`: every mutation tool name is an
  unknown method (`-32601`) with no change.

Closed marker alerts are the accepted residue of the triage steps.

## Offline protocol and consent tests

`crates/elasticctl-mcp/tests/mutation_conformance` (Task 1, #116) passed all
thirteen tests three runs in a row, and found no 0.9.1 defect beyond the
write-time audit gap that the 0.9.1 whole-range review found and #114 fixed.
Each test names the earlier test it extends.

- One `rmcp` `call_tool` with an accepting handler drives both rounds on the
  `2026-07-28` path and writes once. Captured frames show `input_required`,
  then a second call with the issued `requestState` and `inputResponses`, and
  no server `elicitation/create`. The SDK's default handler gives
  `plan_declined`.
- An accept with empty content, with `apply: "true"`, or with `apply: 1` is
  `not_confirmed`, and no request other than GET reaches the stack.
- The same change on a current and a legacy session gives the same 64-hex
  `hash`.
- With eight planners and four applies held at a gate, the fifth active call
  is `busy`, the store caps at eight open plans, and no plan writes twice.
  Two valid round 2 answers for one plan send exactly one write.
- A success and an error result of each of the 11 mutation tools validate
  against the tool's `outputSchema`, and every schema rejects `{}` and
  malformed payloads. The `input_required` result matches the shape of
  mutation design 6.
- A 262,145-byte `plan_apply` line ends the connection on both paths with
  nothing applied.
- The audit sink receives exactly the 8.4 sequence, fields, and Unix-second
  `ts` for accept, failed, unknown, decline, dismiss, stale at the second
  check, discarded, and a 409 at write, which ends with `plan_closed` after
  `apply_finished`.

## Product clients

Both clients ran against the Hosted test deployment (D35), never the lab.
Tool results carry the target host, and these clients send tool results to
their providers; Hosted holds only test data.

| Client | Version | Protocol path |
| --- | --- | --- |
| Claude Code | TBD | `2026-07-28`, and `2025-11-25` with `MCP_PROTOCOL_NEGOTIATION=legacy` |
| Codex CLI | TBD | TBD |

TBD: host OS; Hosted version; the server build and its source commit; the UTC
window; the marker rule imported through the CLI; the scratch configuration
and launch commands with every private value replaced; `--allow-mutations
rules-toggle,cases`; frames recorded through `scripts/mcp-stdio-shim.sh`.

| Scenario | Claude Code | Codex CLI |
| --- | --- | --- |
| Accept, current path | TBD | TBD if `mcp_2026_07_28` can be enabled, else "not testable" with the reason |
| Accept, legacy path | TBD | TBD |
| Decline, current path | TBD | Not applicable |
| Decline, legacy path | TBD | TBD |
| Dismiss, current path | TBD | Not applicable |
| Dismiss, legacy path | TBD | TBD |
| Non-interactive (`claude -p`, `codex exec`) | TBD | TBD |
| Prompts skipped by mode (`bypassPermissions`, `approval_policy = "never"`) | TBD | TBD |
| Tool allowed in advance (allow rule, `approval_mode = "approve"`) | TBD | TBD |
| Hook answers the form | TBD (records a limit, does not gate) | Not applicable |
| Model told to apply without asking | TBD | TBD |

A row says `observed` from the shim frames and the pane text, `not sent` when
the frames show no such request, or `not testable` when neither can show it.
Client documentation never counts as a test.

## Measured client facts

| Fact | Claude Code | Codex CLI |
| --- | --- | --- |
| M10: dialog layout, the boolean's start value, the retry fields, and the order of the permission card and the form | TBD | Not applicable |
| M11: the legacy form renders and is answered within 240 seconds | TBD | TBD |
| M12: what a non-interactive run returns for an elicitation, and whether `plan_apply` reaches the server | TBD | TBD |

TBD: the research gaps these close, also recorded in the mutation spec.

## Client observations

TBD: client behaviors that are not server defects, or "None".

## Cleanup

Every contract and end-of-leg audit passed on all three legs: rule counts,
the default data view, the Fleet marker inventories, and the installed
packages matched their baselines, and no marker object remained apart from
closed marker alerts. A runner writes its report only after the final audit,
so each report also stands for its cleanup. The CI lab was torn down with its
runner.

TBD: the marker rule and each case the client runs created were removed
through `elkctl rules delete` and `elkctl cases delete`, a preflight then
found no marker object apart from closed marker alerts, and the scratch
directory held every client file.

## Evidence limits

- No live request capture is claimed. The live legs keep raw results in
  private ignored logs; only result lines reach public output.
- The harness answer in the mutation contract is test consent. Only the
  client matrix shows a person being asked.
- A non-interactive client run can only prove refusal.
- The hook row documents a limit of every server and does not gate the
  release.
- End-to-end delivery of an expired plan's audit event is not covered
  offline. Each MCP session runs on its own thread with a fresh runtime, so a
  test cannot advance its clock. Unit tests in `src/plan/store.rs` and
  `src/plan/audit.rs` cover expiry and its line format.
- The `input_required` shape is checked against mutation design 6, not the
  official 2026-07-28 schema file, which is not vendored.
- TBD: each client ran once per scenario at the versions above; others are
  untested.
