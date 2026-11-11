[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 11. Decisions log

Each row is final for 0.9. Sources are in
[research](../../plans/v0.9-research.md).

| # | Decision | Reason |
| --- | --- | --- |
| D1 | Consent is a form elicitation answered `accept` with `apply: true`. | It is the one protocol channel that carries an answer from the client and not from tool arguments. |
| D2 | `plan_apply` takes `plan_id` only. | Any input that could confirm would be written by the model. |
| D3 | No form elicitation, no apply; the plan names the CLI command instead. | Fail closed. The CLI already gives a person a guarded path. |
| D4 | No out-of-band confirm command and no URL mode. | A caller with a shell shares the operator's OS user, so neither adds a party. |
| D5 | The form has one required boolean with default `false`. | Codex CLI accepts a form without fields on its own in one mode; a blind accept with defaults sends `false`. |
| D6 | `plan_apply` is marked `destructiveHint: true` and `anthropic/requiresUserInteraction: true`. | These make both evidence clients prompt. They are defense in depth, not the consent. |
| D7 | Classes are enabled only by `--allow-mutations`, with no `all`. | The operator decides what can change, and a new class is never granted by an old command line. |
| D8 | The set is seven mutations chosen by conditions S1 to S6. | One request, named objects, a direct effect that is set back or only adds, public routes, showable in full, no files. No kind is claimed to be exactly reversible. |
| D9 | Rule update, deletes, exception items, assignment, imports, Fleet, and `state push` are out. | Each fails at least one condition ([section 4](04-mutation-set.md#out)). |
| D10 | `rules-toggle` ships first. | Owner decision. It has the strongest re-check and the best measured route. |
| D11 | A plan lives in process memory for 900 seconds. Eight may be open. | No file, no state that outlives the credential, and a bounded number of things a person can be asked about. |
| D12 | The hash is SHA-256 over sorted-key JSON of kind, target, credential, operation, and observed state. | It names exactly what was confirmed and is the same for the same change against the same state. |
| D13 | Planners return preview and observed state from the same reads. | The text a person confirms describes the state the plan is bound to. |
| D14 | Drift is checked before the question and again before the write. A mismatch closes the plan. | Nobody confirms a stale plan, and a confirmed plan is not applied to changed state. |
| D15 | The credential is bound through `_security/_authenticate`, read when planning and before writing. | It gives the audit trail an actor and refuses a key that cannot perform the kind before a person is asked. |
| D16 | Writes use a transport with one attempt, no redirects, and no connection pool, through a new opt-in core option. | A create or a comment must never be sent twice, and a pooled socket can cause a replay below the application retry loop. |
| D17 | A sent write runs to its response even if the call is cancelled or times out. | An abandoned write has an unknown result. A finished one is recorded. |
| D18 | A 4xx is `failed`; a 409 on a case status or rule create write is `stale`; a 5xx, a timeout, or an undecodable body is `unknown`. `cases_ops::apply_status` keeps the HTTP status so this works. | Only a refusal proves nothing changed, and a refusal for drift is drift. |
| D19 | A repeated `plan_apply` returns the stored result. | Clients repeat idempotent calls; a plan must apply once. |
| D20 | `decline` closes the plan, and a plan prompts at most three times. | The same question is not put to a person again and again. |
| D21 | The consent text is never truncated or summarized. A plan that does not fit is refused. A new rule shows every field in full. | A person must see every affected object and every value that will be written. |
| D22 | The audit trail is JSON lines on stderr with ids and counts only. | 0.7 tools write no file, and stack text must not reach logs. |
| D23 | 0.9 uses no MCP tasks, no resources, and no prompts for plans. | Every apply is one request inside the deadline; `plan_get` and `plan_list` already read plans. |
| D24 | All `-api` additions and all live measurements land in 0.9.0. | Live stacks are available briefly. |
| D25 | No new CLI command. CLI output changes in one place: a case status conflict error gains `http_status: 409`. | 0.9 is an MCP capability area. Snapshots prove the rest is unchanged. |
| D26 | The consent text of a rule toggle and a rule create states that Kibana ties the rule to this server's credential and that undo does not restore the earlier one. | Kibana documents the key assignment for both routes. It changes how the rule runs and no tool sets it back. D34 replaces the wording. |
| D27 | Every object a plan writes to is named by identity in the consent text. A comment plan shows the case id. | Titles and names are not unique. |
| D28 | Text that will be written must display exactly; input with a replaced character is refused. | What is shown must be what is stored. |
| D29 | `--allow-mutations` with a profile that has no `es_url` fails at startup with a line naming `es_url`. | Every plan needs the credential read; a clear early error beats a failed planner. |
| D30 | Files that 0.8 and 0.9 both edit have one serialized owner task per version. | Parallel tasks own separate files. |
| D31 | A case status plan requires a strictly decoded `syncAlerts == false`, when planning and at both checks, and is refused with `case_sync_alerts` otherwise. A new case is created with `syncAlerts: false`, shown in the consent text. | With sync on, Kibana changes attached alerts that the plan does not list and nobody confirmed. |
| D32 | A rule read must return the `rule_id` that was asked for, when planning and at both checks. Planning reuses `selection::to_rule`. | The route matches through KQL, which decodes escapes, so a read can return another rule than the one the write targets. |
| D33 | The consent text opens with the action, the target, and the first detail line. `plan_declined` says the plan is closed. | Claude Code 2.1.322 shows only the first three lines of a form message (M10), with no key to show more, and a person must see what they confirm. After a decline, a model told the person the plan was still open. |
| D34 | The key note says each rule keeps the credential it has, and a rule without one gets this server's credential when it is enabled. | M13 on the 9.5.1 lab: a keyless rule took the enabler's key, and a disable or an enable by another credential kept the existing owner. The earlier wording claimed every write reassigns the key. |
| D35 | Model-driven clients run against the Hosted test deployment, not only the local lab. | Owner decision. Hosted holds only test data and is a supported flavor, so its host reaching a model provider exposes nothing real, and the run tests a flavor users run. Tool results carry no secret; the credential appears only as a fingerprint. |

### Owner decisions, 2026-11-10

| Question | Decision |
| --- | --- |
| Which class ships first | `rules-toggle`, with the credential note of D26 |
| Exception items and rule update | Out of 0.9 |
| A reachable Elasticsearch URL for plans | Required. The error names `es_url` (D29) |
| Two prompts per apply in Claude Code | Accepted |
| Audit trail on stderr only | Accepted |
| Organization-level key for measurement M9 | Supplied and measured on 2026-11-11 (M9): Serverless accepts it, Hosted refuses it at `_authenticate` |

### Alternatives where the trade-off matters

**`alerts-triage` first (rejected for D10).** Alert tags and status have a
lower impact than a rule toggle. They also need live alerts in every test
tier of the first release, and their re-check is search-backed. The owner
chose `rules-toggle`.

**Recording prior tag membership (rejected for D8).** A tags plan could read
each alert's tags and offer an exact inverse. That read is a new request
shape with new fixtures. 0.9 drops the claim instead: a tag edit is a named
add or remove, and the design says prior membership is not restored.

**`post_once` in the shared apply functions (rejected for D16).** Core
already has non-replaying calls. Using them in `-api` would change CLI retry
behavior for every mutation and there is no `patch_once`. A transport option
gives MCP the property without touching the CLI path.

**Exception item create (rejected for D9).** It is the most asked-for triage
write: suppress this false positive. It also silences detections at once,
has no single-item undo in the CLI, and is removed by the next `state push`
from a mirror that lacks it. It needs a design that settles its relation to
the mirror first.

**A durable audit file (rejected for D22).** A file survives the client's log
rotation. It would also be the first local write from the MCP server and need
the path identity and locking rules the report files already carry. stderr
is enough for a release with no delete and no content change. The owner
accepted stderr only.

**Skipping the credential read (rejected for D15).** It would let profiles
without an Elasticsearch URL make plans and save two requests per apply. The
audit trail would then have no actor, and a key the stack refuses, such as an
organization-level key on Hosted (M9), would fail only after a person had
already confirmed.

**Typed confirmation code (rejected for D5).** See
[section 2.2](02-consent-model.md#22-rejected-alternatives). It returns if a
destructive class is ever added.
