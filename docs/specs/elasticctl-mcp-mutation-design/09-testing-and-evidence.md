[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 9. Testing and evidence

Tests drive the public MCP router and the real stdio process with only the
network faked, as in 0.7. A private function test alone proves nothing about
consent.

### 9.1 Offline tiers

**Unit tests in `-mcp`.** Canonical bytes and hash for nested and reordered
objects; id and handle format; every state change and every refused change;
all limits of [section 5.4](05-plans.md#54-states-expiry-and-limits) at both
sides of the boundary; expiry with paused time; the consent text rules,
including each replaced character class, multi-line values, the left-margin
property, and the 8,192 byte boundary; every row of the answer table; the
outcome mapping per kind; class parsing.

**SDK-level tests.** An `rmcp` client and the raw JSON-RPC harness against
`serve_io`, with a recording mock as the stack:

| Area | Must show |
| --- | --- |
| Startup and catalog | The catalog without the flag is byte-identical to the pre-0.9 catalog. Each class adds exactly its tools. A tool of a class that is off is the unknown-tool error and sends nothing. Annotations and `_meta` match [section 3](03-startup-opt-in-and-catalog.md#annotations). Every result validates against its output schema |
| Arguments never confirm | `plan_apply` with `confirm`, `yes`, `apply`, `inputResponses`, or `requestState` inside `arguments` is `invalid_argument` with zero requests |
| Current path | Round 1 returns the exact `input_required` shape. Each answer row gives its result. A handle works once. A missing, wrong, or other plan's handle is `not_confirmed`. The fourth prompt closes the plan |
| Legacy path | The server sends the form. Accept, decline, cancel, client error, and the 240 second timeout each give their result. A second waiting confirmation is `confirmation_pending`. Four reads run while one call waits. Cancelling the waiting call sends no result |
| No elicitation | On both paths `plan_apply` is `confirmation_unavailable` and the mock saw no request after the planner's |
| Drift | A changed object before the question is `plan_stale` with no question. A change between question and answer is `plan_stale` after acceptance with zero writes. A changed identity is `plan_stale` |
| Replay | A second `plan_apply` returns `replayed: true` and the request count does not move |
| Write classification | 200, 400, 403, 409, 429, 500, 503, timeout, reset, and a malformed 200 body each give the state of [section 8.2](08-apply-errors-and-cancellation.md#82-classifying-the-write). The write is sent exactly once in every case. The 409 cases go through the real `-api` apply functions, with the recorded case conflict, and end in `stale` |
| One request per write | Core tests with a raw responder: after the peer closes a used socket, a `post` and a `patch` on the mutation transport open a new connection and arrive once; a request that is read and then dropped is not sent again |
| Consent completeness | A new rule with `threat_query`, `filters`, `threshold`, and an unknown key shows each whole value; a rule one byte over the consent limit is `plan_too_large`; a comment plan shows the case id; two cases with one title give different texts; both rule kinds show the key note with the plan's credential value |
| Rule identity | A selector `r\\n` that the route answers with the rule stored as `r\n` plans against the stored id through `selection::to_rule`. A read that still returns another id is `elastic_conflict` with no plan. At either check, a read that returns another `rule_id` is `plan_stale` with zero writes |
| Case alert sync | A case with `settings.syncAlerts: true` and attached alerts, a case without `settings`, and one with `"syncAlerts": "false"` are each refused with `case_sync_alerts`, no plan, and no write. A setting turned on between plan and either check is `case_sync_alerts` and `stale`. A create sends `settings.syncAlerts: false` and its consent text shows it |
| Exact display | A title, comment, tag, or rule string holding a replaced character is `invalid_argument` with zero requests |
| Cancellation and deadline | Cancel before commit: nothing written, plan `open`. Cancel after commit: no result, outcome recorded. Deadline after commit: `apply_pending`, then `plan_get` shows the final state |
| Routes | Per tool, the exact list of methods and paths. Planners send GET and the alert search POST only. Across the suite, the only PUT, PATCH, DELETE, or mutating POST is the one write of an applied plan |
| Leak and injection | Credential-shaped and instruction-shaped text in rule names, case titles, tags, and stack errors is absent from errors and stderr, and appears in the consent text only on indented lines |
| Audit | Each flow emits its events once, in order, with only the allowed fields |

**Fixture-backed tests.** Mocks replay the recorded responses of all three
existing fixture sets for the routes the planners, checks, and applies use.
0.9 adds no request shape, so it records no fixture. Three responses have no
recording: the enable form of `_bulk_action` (the recorded disable response
has the same summary), the 404 for an absent rule, and the 409 for an
existing `rule_id`. Tests build the last two inside the test file, as
existing rule tests do, and the live contract measures all three.

**CLI tests.** Process tests for `--allow-mutations` on both binaries: valid
sets, each rejected form, the stderr warning, and stdout empty before input.
Snapshots change only for the `mcp` description and the new flag.

### 9.2 Live contract

One ignored test, `mcp_mutations_plan_and_confirm`, runs per flavor on
Serverless, Hosted, and the lab. The harness prepares and removes objects
through reviewed test code outside MCP. Every object carries the live
contract marker of [live stacks](../../../instructions/live-stacks.md): the
`elasticctl-live-` prefix and the `elasticctl-live-marker` tag, which the
baseline audit checks. No prebuilt or unmarked object is named in any call.

1. Verify the baseline. Create a disabled marker rule, a marker index with a
   marker rule that raises at least two alerts, and a marker case.
2. Child A: current protocol, every shipped class enabled, the harness
   declares form elicitation and answers it. For each shipped planner: plan,
   apply with `accept` and `apply: true`, then read the object through the
   API and compare. Then, with the rule toggle: decline and verify no change;
   change the rule outside MCP after planning and verify `plan_stale` with
   no change; apply the same plan twice and verify `replayed: true` with no
   second change.
3. Child B: legacy protocol. One toggle confirmed through the server-sent
   form. One `plan_apply` from a session that declares no elicitation:
   `confirmation_unavailable` and no change.
4. Child C: started without `--allow-mutations`. Every mutation tool name is
   unknown.
5. Remove the marker rule, the created rule, the marker case, the created
   case, and the marker index through the harness. Verify the baseline. Closed
   marker alerts are the accepted residue of the triage contract.

The harness answering the form is test consent. It proves the protocol
mechanics on a live stack. It does not prove that a product client asks a
person; section 9.3 does.

As in 0.7.2, the MCP transport has debug off, so a live run has no request
log. The offline route proofs, the child's command line, and state equality
before and after are the evidence that planners write nothing.

0.9.0 runs this test with the `rules-toggle` steps only and adds the direct
`-api` measurements M1 to M9 of the [research](../../plans/v0.9-research.md).
0.9.1 runs it with all classes. 0.9.2 registers it as a conformance contract.

### 9.3 Real clients

Model-driven clients run against the Hosted test deployment (D35). Tool
results carry the target host, and these clients send tool results to their
providers, so the target holds only test data. The 0.9.0 client runs used the
local lab. Public evidence never records the host or an id. Client
configuration lives in a scratch directory outside the repository. A shim
records both stdio directions to private files.

Confirming needs a person or a scripted terminal. A confirming run uses an
interactive session in a terminal multiplexer; the keys that answer the
dialog are sent to that terminal, and the pane text and the shim log are the
record.

| Scenario | Claude Code | Codex CLI | Pass means |
| --- | --- | --- | --- |
| Accept | Current path, and again with `MCP_PROTOCOL_NEGOTIATION=legacy` | Legacy path | The dialog shows the consent text; the marker rule changes; the shim shows the answer on the elicitation channel |
| Decline | Both paths | Legacy path | `plan_declined`; no change |
| Dismiss | Both paths | Legacy path | `not_confirmed`; no change; plan still open |
| Non-interactive | `claude -p` | `codex exec` | No change. Record whether the call reached the server and which answer came back |
| Prompts skipped by mode | `bypassPermissions` | `approval_policy = "never"` with full access | No change without a person. For Claude Code the permission card still appears. For Codex the form is declined |
| Tool allowed in advance | An allow rule for `plan_apply` | `approval_mode = "approve"` for `plan_apply` | The form still appears; nothing applies without it |
| Hook answers the form | An `Elicitation` hook returning `accept` and `apply: true` | Not applicable | Record the result. Expected: the permission card still needs a person. This row documents a limit, whatever the result |
| Model tries to confirm | The prompt tells the model to apply without asking | The same | No argument applies. Record what the model tried |

0.9.0 needs the Accept and Decline rows for Claude Code on one path. 0.9.2
needs the whole table. A client that cannot run is an evidence gap, never a
pass taken from its documents.

### 9.4 Evidence and release contract

- Raw client logs, child output, and live results stay in ignored private
  logs. Public findings hold versions, protocol paths, scenario outcomes,
  aggregate counts, and cleanup facts. They hold no host, id, user, or raw
  failure text.
- Findings: `docs/conformance/v0.9.0-findings.md`,
  `docs/conformance/v0.9.1-findings.md`, and `docs/conformance/v0.9.2/` with
  the three matrix reports and `findings.md`. Reviews:
  `docs/reviews/v0.9.0.md`, `v0.9.1.md`, `v0.9.2.md`.
- Every version passes the gates of
  [testing](../../../instructions/testing.md) on the exact release commit.
- Every version gets an independent adversarial review of the consent path,
  the class gate, the write path, and the audit lines, by a reviewer who
  wrote none of it. A confirmed finding gets a failing regression first.
- A runtime change after a live pass reruns that pass on every flavor.
- A missing live or client measurement keeps its gate open. It is never
  inferred, lowered, or moved to a later version.
- A release ends at the tag and the GitHub Release. Publishing to crates.io
  follows [releasing](../../releasing.md) and needs its own approval. The new
  `ServerOptions` field is a Rust source change in the `elasticctl-mcp` crate,
  outside the compatibility promise of shared design 11.1.
