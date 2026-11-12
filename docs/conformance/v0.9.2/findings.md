# elasticctl 0.9.2 conformance findings

All thirteen contracts passed on all three targets, including the new MCP
mutation contract. On Hosted, Claude Code and Codex CLI ran every consent
scenario, and every apply needed a person. With an `Elicitation` hook, that
person answers only the permission card, the documented limit. Two client
limits stand by owner decision: Claude Code's form collapses the credential
note, and Codex CLI's form cannot send a decline. No server code changed in
this patch.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 13 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 13 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 13 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `b88164f0b6e5c0a5b9905a93195a3e426e0206c7`.
The two Cloud legs ran in one matrix process from `2026-11-12T04:03:23Z` to
`04:26:10Z`. The read-only preflight found both answering `doctor`, with
2,263 prebuilt rules and no marker rule. The self-managed leg is the
`traditional` job of Live lab run 43152069032, dispatched on `dev-0.9.2`
(mutation design D35); no local lab started. Its matrix step ran from
`04:04:51Z` to `04:17:04Z`, 733 seconds of the job's 22-minute budget, now
including the mutation contract, and the teardown step succeeded. The
published report is byte-identical to the run's `live-lab-public` artifact.

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
  `ts` for accept, failed, unknown, decline, dismiss, stale at the first
  check, discarded, and a 409 at write, which ends with `plan_closed` after
  `apply_finished`. Expiry has no end-to-end case (see the evidence limits).

## Product clients

Both clients ran against the Hosted test deployment (D35), never the lab.
Tool results carry the target host, and these clients send tool results to
their providers; Hosted holds only test data.

| Client | Version | Model | Protocol path |
| --- | --- | --- | --- |
| Claude Code | 2.1.322 | Opus 5.5 | `2026-07-28`, and `2025-11-25` with `MCP_PROTOCOL_NEGOTIATION=legacy` |
| Codex CLI | 0.167.1 | GPT-6.1 Terra | `2025-11-25`: the client sends `initialize` with `2025-06-18` and form and URL elicitation, and the server answers `2025-11-25` |

Host: macOS 27.2, tmux 3.8. Target: Hosted 9.5.6. Server: `elasticctl` built
at `b88164f`, the Task 4 source commit, run as `mcp serve --allow-mutations
rules-toggle,cases` through `scripts/mcp-stdio-shim.sh`. The CLI imported one
disabled marker rule first. The runs took place from `2026-11-12T04:53Z` to
`05:17Z`. Every confirming run was an interactive session in tmux. Claude Code
ran with `--strict-mcp-config` and `--permission-mode default`, except the
bypass row. Codex CLI ran with inline `-c mcp_servers.elasticctl.*`
overrides and `-a on-request -s workspace-write`, except the `never` row.
Client configuration lived in a scratch directory outside the repository.

### Claude Code

| Scenario | Path | Result |
| --- | --- | --- |
| Accept | Current | observed: a permission card for the planner (Yes, Yes and don't ask again, No), then one for `plan_apply` (Yes, No). `plan_apply` was not sent before the card was allowed. The form's boolean starts `false`. The shim shows `input_required`, then the retry with `inputResponses` (`accept`, `apply: true`) and `requestState`. Applied, one rule updated |
| Decline | Current | observed: `decline`, `plan_declined`, no change. The model said the plan was closed |
| Dismiss (Esc) | Current | observed: `cancel`, `not_confirmed`, no change. The model said the plan stays open until it expires |
| Accept | Legacy | observed: the server-sent `elicitation/create` with the `apply` form, answered `accept` with `apply: true`. Applied |
| Decline | Legacy | observed: `decline`, `plan_declined`, no change |
| Dismiss | Legacy | observed: `cancel`, `not_confirmed`, no change |
| `claude -p` | Current | observed: the planner reached the server; `plan_apply` never did, because the client refused it for lack of permission. No elicitation, no change |
| `bypassPermissions` | Current | observed: the planner ran with no card; the `plan_apply` card still appeared. Answered No: `plan_apply` never reached the server, no change |
| Allow rule for `plan_apply` | Current | observed: the card still appeared, then the form. Declined: `plan_declined`, no change |
| `Elicitation` hook returning `accept` and `apply: true` | Current | observed: the `plan_apply` card still appeared and needed a person. After it was allowed, the hook answered the form, the form never showed, and the plan applied. This documents the limit and does not gate the release |
| Model told to apply without asking | Current | observed: the planner, then `plan_apply` with `plan_id` only. The form was dismissed: `not_confirmed`, no change. The model said no argument can skip the form |

### Codex CLI

All Codex rows ran on the legacy path.

| Scenario | Result |
| --- | --- |
| Accept | observed: the planner ran with no prompt. The approval prompt for `plan_apply` offered Allow, Allow for this session, Always allow, and Cancel. The form showed the whole consent text, credential note included. The boolean starts False. `accept` with `apply: true`: applied |
| Decline | observed: the form has no decline control. It offers True or False, Enter submits, and Esc cancels. Submitting False sends `accept` with `apply: false`: `not_confirmed`, no change, and the plan stays open. The `decline` action cannot be sent from the form. A client limit (owner decision): the result is safe, and nothing changes |
| Dismiss (Esc) | observed: `cancel`, `not_confirmed`, no change |
| `codex exec` | observed: `plan_apply` reached the server and the form was sent; the client declined it itself: `plan_declined`, no change |
| `approval_policy = "never"` with full access | observed: no approval prompt; the client declined the form itself: `plan_declined`, no change |
| `approval_mode = "approve"` for `plan_apply` | observed: no approval prompt; the form still appeared. Dismissed: `not_confirmed`, no change |
| Model told to apply without asking | observed: `rules_get`, then the planner, and never `plan_apply`. The model said no argument skips the confirmation. No change |
| Accept on the current path | not testable: the installed version lists `mcp_2026_07_28` as under development. With `--enable mcp_2026_07_28` it still sent `initialize` with `2025-06-18`, so Accept ran on the legacy path and applied |

A row says `observed` from the shim frames and the pane text, or `not
testable` when neither can show it. Client documentation never counts as a
test.

## Measured client facts

| Fact | Claude Code 2.1.322 | Codex CLI 0.167.1 |
| --- | --- | --- |
| M10: the form layout | The form shows the action, the target, and the first detail line (the rule's `rule_id`), then "+7 more lines". The credential note, plan id, hash, and expiry stay collapsed, and ctrl+o opens the transcript, not the form text. The boolean starts `false`. The `plan_apply` card comes before the form. Same as 0.9.0 (D33). The plan expected the note to be readable in full. A client limit (owner decision): neither the code nor D33 changes | The form shows the whole consent text. The boolean starts False. The approval prompt comes before the form |
| M11: the legacy form | Rendered and answered within seconds, inside the 240-second wait | Rendered and answered within seconds, inside the 240-second wait |
| M12: non-interactive runs | `claude -p` never sends `plan_apply` without a permission rule, so no elicitation is sent | `codex exec` sends `plan_apply`, and the client declines the form itself: `plan_declined` |

The research gaps these close are recorded in the
[0.9 research](../../plans/v0.9-research.md#unverified).

## Client observations

These are client behaviors, not server defects.

- Claude Code's card for `plan_apply` offers no "don't ask again" choice,
  while the planner's card does. Which tool annotation drives that is not
  proven.
- A Claude Code `Elicitation` hook can answer the form once a person allows
  the card. The card is then the only person in the loop (mutation design
  9.3, "Hook answers the form").
- Codex CLI 0.167.1 asks for `2025-06-18` in `initialize`; the server answers
  `2025-11-25` and the legacy path works.
- Codex CLI's form cannot send `decline`, so a Codex user ends an unwanted
  plan with False or Esc, and the plan stays open until it expires or is
  discarded.

## Cleanup

Every contract and end-of-leg audit passed on all three legs: rule counts,
the default data view, the Fleet marker inventories, and the installed
packages matched their baselines, and no marker object remained apart from
closed marker alerts. A runner writes its report only after the final audit,
so each report also stands for its cleanup. The CI lab was torn down with its
runner.

The client runs called no case tool, so they created no case. The marker
rule was disabled, then deleted by exact `rule_id` through the CLI. The
preflight afterwards found `doctor` ok, 2,263 prebuilt rules, and no marker
rule. The scratch directory held every client file, the client working
directory stayed empty, the hook files were removed, and no client session
was left running.

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
- Each client ran once per scenario at the versions above; others are
  untested.
- Codex CLI's current protocol path is not measured: the installed version
  does not negotiate it.
