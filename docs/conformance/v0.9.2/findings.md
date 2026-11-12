# elasticctl 0.9.2 conformance findings

<!-- Skeleton. elk1 fills every TBD from Tasks 4 and 5. Public facts only:
versions, protocol paths, outcomes, counts, cleanup. No host, id, user, or
raw failure text (mutation design 9.4). -->

TBD: one-paragraph result. All thirteen contracts on three targets, the
client matrix on Hosted, and whether any server code changed in this patch.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | TBD | TBD of 13 pass | TBD |
| Elastic Cloud Hosted | TBD | TBD of 13 pass | TBD |
| Self-managed | 9.5.1 | TBD of 13 pass | TBD |

TBD: the source commit of every leg; the UTC window of the Cloud matrix
process; the Live lab run and its window. The self-managed leg is the
`traditional` job of `live-lab.yml` (mutation design D35); no local lab
started. Record the matrix step's duration against the job's 22-minute
budget, since the job now also runs the mutation contract.

## Mutation contract

`mcp_mutations_plan_and_confirm` is the thirteenth contract
([mutation design 9.2](../../specs/elasticctl-mcp-mutation-design/09-testing-and-evidence.md#92-live-contract)).
The harness answer is test consent: it proves the protocol mechanics on a
live stack, not that a product client asks a person.

| Step | Serverless | Hosted | Self-managed |
| --- | --- | --- | --- |
| Baseline before and after | TBD | TBD | TBD |
| Child A, current protocol: `rules_set_enabled` applied and read back | TBD | TBD | TBD |
| Child A: `alerts_set_status`, `alerts_set_tags` | TBD | TBD | TBD |
| Child A: `cases_create`, `cases_comment`, `cases_set_status` | TBD | TBD | TBD |
| Child A: `rules_create`, read back disabled | TBD | TBD | TBD |
| Child A: decline, then `plan_stale` after an outside change, then replay | TBD | TBD | TBD |
| Child B, legacy protocol: toggle through the server-sent form | TBD | TBD | TBD |
| Child B: no elicitation declared, `confirmation_unavailable` | TBD | TBD | TBD |
| Child C, no `--allow-mutations`: every mutation tool unknown | TBD | TBD | TBD |

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

TBD: every contract and end-of-leg audit passed, or what failed; the marker
rule and each case the client runs created were removed through `elkctl rules
delete` and `elkctl cases delete`, and the preflight found no marker object
apart from closed marker alerts; the scratch directory held every client file.

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
