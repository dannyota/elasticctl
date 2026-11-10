[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 8. Apply, errors, limits, and cancellation

All 0.7 limits stay: four active calls, the whole-call deadline, the input
line, structured content, frame, and upstream body caps. Planner calls and
plan tools are ordinary calls under those limits. This section covers what is
new in `plan_apply` after a person has confirmed.

### 8.1 The apply sequence

| Step | Work | Can be cancelled | On failure |
| --- | --- | --- | --- |
| A | Second check: identity and `observe_*` reads on the ordinary transport | Yes | Read error: mapped Elastic error, plan stays `open`. Mismatch: `stale` |
| B | Commit: under the store lock, move `open` to `applying`. Write `apply_started` | No | Not possible; another caller won the move and this call follows [section 5.5](05-plans.md#55-replay) |
| C | Write: one `-api` apply call on the mutation transport (one attempt, fresh connection), in a spawned task that owns the call permit | No | Classified in section 8.2 |
| D | Record: store the outcome and final state under the lock. Write `apply_finished` | No | - |

The handler waits for the task and returns its result. Three things can end
the wait first:

- **The call deadline passes.** The handler returns the tool error
  `apply_pending`. The task continues. `plan_get` later shows `applied`,
  `failed`, or `unknown`.
- **The client cancels the request.** The handler sends no result, as the
  protocol asks. The task continues and records its outcome. Cancellation
  before step B stops the call with nothing written and the plan `open`.
- **The session ends** (stdin closes or a signal arrives). The existing five
  second shutdown grace applies. The task is not aborted before the grace
  ends. A plan still `applying` at exit gets an `apply_interrupted` audit
  line. The client cannot learn that outcome from this process.

A sent write is never abandoned by choice. The protocol lets a server ignore
a cancellation for a request that cannot be cancelled, and step C is such a
request. The transport timeout of the profile, 1 to 120 seconds, bounds the
task.

The deadline covers steps A to D. On the current protocol it starts with the
round 2 request. On the legacy protocol it starts again after the person's
answer.

### 8.2 Classifying the write

The `-api` apply call returns a report or a classified error. The HTTP status
decides what is known:

| Result of the apply call | State | Returned |
| --- | --- | --- |
| A report | `applied` | The plan and its outcome. `outcome.complete` may be false |
| Error of kind `conflict` with status 409, for `cases_set_status` or `rules_create` | `stale`, straight from `applying` | `plan_stale` |
| Error with any other status from 400 to 499, including 429 | `failed` | The 0.7 `elastic_<kind>` error with `http_status` |
| Error with a status of 500 or more | `unknown` | `apply_outcome_unknown` with `http_status` |
| Error without a status: timeout, connection failure, or a response body that does not decode | `unknown` | `apply_outcome_unknown` |

The classifier reads `http_status` from the error the `-api` function
returns. That only works if the function keeps it. `cases_ops::apply_status`
dropped it when rewrapping a conflict; 0.9.0 makes it keep it
([section 7](07-api-reuse.md#cases)). Tests drive the real `-api` apply
functions against the recorded `case_conflict.json` and against a 409 on
rule create, and assert the state, so a later rewrap that loses the status
fails a test instead of turning `stale` into `unknown`.

Reasons:

- A 409 on these two kinds is the stack's own drift check: the case
  `version` moved, or the `rule_id` now exists. Nothing was written.
- A 4xx answer means the stack refused the request. With one request per
  plan, nothing changed.
- A 5xx answer, a timeout, or a lost connection does not say whether the
  write landed.
- A success status with a body that fails the fail-closed decoders of
  [shared design 6.3](../elasticctl-design/06-contracts.md#63-fail-closed-boundaries)
  most likely did write. It is `unknown`, never "nothing happened".
- The server never retries a write, so a 429 is `failed`. The caller makes a
  new plan.

### 8.3 What is atomic

| Atomic | Not atomic |
| --- | --- |
| Each plan state change, under the store lock | The second check together with the write |
| Taking the confirmation handle | The effect of one bulk request across its objects |
| The single write request as elasticctl sends it: sent once, on its own connection, or not at all | Anything across two plans |

A bulk request can change some objects and not others. The stack reports
that in its counters, and the outcome carries them. elasticctl does not roll
back.

### 8.4 Results and audit trail

**Plan view.** Planners, `plan_get`, and `plan_apply` return the 0.7 success
envelope with this `data`:

```json
{"plan": {"plan_id": "pln_<32 hex>", "hash": "<64 hex>",
   "kind": "rules_set_enabled", "class": "rules-toggle", "state": "open",
   "expires_in_secs": 900, "credential": "<12 hex>",
   "action": "Disable 1 rule(s)", "details": ["<detail line>"],
   "targets": ["<id>"], "operation": {},
   "confirmation": "elicitation",
   "cli_equivalent": ["rules", "disable", "<rule_id>"]},
 "outcome": null, "replayed": false}
```

- `confirmation` is `elicitation` or `unavailable`, from the capabilities of
  the request that asked.
- `cli_equivalent` is an argument list after the binary name and global
  flags, without `--yes`, or `null`. It is `null` for `rules_create`.
- `expires_in_secs` is 0 for a plan that is not `open`.
- `action`, `details`, `targets`, and `operation` are data from the stack or
  from the caller. They are untrusted text, as in 0.7.
- `outcome` is set only for an `applied` plan. `replayed` is true only from
  `plan_apply` on a plan that had already left `open`. Such a call returns
  this view, not the error the first call returned.
- `plan_list` returns `{"plans": [...]}` with `plan_id`, `kind`, `class`,
  `state`, `action`, and `expires_in_secs` per plan: open plans first, then
  final records, newest first. `page` is `null`; the store holds at most 40.
- `plan_discard` returns the plan view. It closes an `open` plan, returns a
  final plan unchanged, and returns `plan_not_open` for `applying`.

**Outcome.**

```json
{"requested": 2, "updated": 1, "unchanged": 0, "failed": 1,
 "complete": false, "created": null}
```

| Kind | `requested` | `updated` | `unchanged` | `failed` |
| --- | --- | --- | --- | --- |
| `rules_set_enabled` | Target count | `succeeded` | 0 | `failed + skipped + (requested - total)` |
| `alerts_set_status`, `alerts_set_tags` | Target count | `updated` | `noops` | The report's `failed`, plus `requested - total` when positive |
| `cases_set_status` | `resolved` | `updated` | `resolved` minus planned updates | `failed` |
| `cases_comment` | 1 | 1 | 0 | 0 |
| `cases_create` | 1 | 1 | 0 | 0; `created` is `{"case_id": "..."}` |
| `rules_create` | 1 | 1 | 0 | 0; `created` is `{"rule_id": "..."}` |

`complete` is true when `updated + unchanged == requested` and `failed == 0`.
A result with `complete: false` is a success envelope, not a tool error: the
call worked and the data says what did not. Per-object failure text from the
stack is not returned. The caller reads the objects with the read tools.

**Errors.** New local codes, each with a static message. `kind` uses the
existing vocabulary.

| Code | Kind | Meaning |
| --- | --- | --- |
| `plan_not_found` | `not_found` | No plan with that id in this process |
| `plan_expired` | `conflict` | The plan's life ended |
| `plan_stale` | `conflict` | The target changed after the plan was made |
| `plan_declined` | `permission` | A person declined, or the prompt limit was reached |
| `plan_discarded` | `conflict` | The plan was discarded |
| `plan_not_open` | `conflict` | `plan_discard` on a plan that is applying |
| `plan_too_large` | `unsupported` | The plan or its consent text exceeds a limit |
| `too_many_plans` | `error` | Eight plans are open |
| `not_confirmed` | `permission` | The form was not accepted with `apply: true` |
| `confirmation_unavailable` | `unsupported` | The client cannot show a form |
| `confirmation_pending` | `error` | Another confirmation is waiting (legacy) |
| `confirmation_timeout` | `timeout` | No answer in 240 seconds (legacy) |
| `credential_unsuitable` | `permission` | The credential's realm cannot perform this kind |
| `case_sync_alerts` | `unsupported` | A case in the plan has `settings.syncAlerts` on or unreadable; changing its status would change attached alerts. The message names `syncAlerts` |
| `apply_pending` | `timeout` | The write was sent; the call ended before its answer |
| `apply_outcome_unknown` | the error's kind | The write was sent; its result is not known |

An unlisted mutation tool stays the protocol error for an unknown tool.
Messages never include a plan id, an object id, or stack text.

**Audit trail.** Each event is one JSON line on stderr:

```json
{"audit":{"ts":1794300000,"event":"apply_finished","plan_id":"pln_...","hash":"<64 hex>","kind":"rules_set_enabled","class":"rules-toggle","profile":"analyst","host":"kibana.example.test","space":"default","credential":"<12 hex>","protocol":"2026-07-28","state":"applied","outcome":{"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true},"http_status":null}}
```

| Event | When | Extra fields |
| --- | --- | --- |
| `plan_created` | A planner stored a plan | `targets` |
| `confirmation_requested` | A question was issued | `prompt` (1 to 3) |
| `confirmation_answered` | An answer, timeout, or refusal was handled | `result`: `confirmed`, `not_confirmed`, `declined`, `timeout`, or `unavailable` |
| `apply_started` | Step B | none |
| `apply_finished` | Step D | `state`, `outcome`, `http_status` |
| `apply_interrupted` | Exit with a plan `applying` | none |
| `plan_closed` | A plan became `stale`, `expired`, `discarded`, or `declined` | `state` |

Rules:

- `ts` is seconds since the Unix epoch. Every line has `event`, `plan_id`,
  `hash`, `kind`, `class`, `profile`, `host`, `space`, `credential`, and
  `protocol`.
- `targets` holds object ids, JSON-escaped. They are the only stack-supplied
  strings in the trail. Names, titles, tags, messages, rule bodies, queries,
  usernames, key ids, URLs, and error messages never appear.
- The lines use the same explicit stderr writer as the startup diagnostics.
  SDK logging stays suppressed. stdout stays protocol only.
- The trail lasts as long as the operator keeps the process's stderr. 0.9
  writes no file. `plan_list` shows up to 32 final records while the process
  lives.
- The trail records what this process did. It is not proof against a party
  that controls the process.
