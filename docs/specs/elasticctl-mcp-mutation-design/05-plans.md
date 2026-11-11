[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 5. Plans

A plan is a record in server memory. It holds everything the apply will send
and everything the planner saw. The model gets a handle to it and a read-only
view of it. The model cannot edit it.

### 5.1 Content and hash

| Field | Content | In hash |
| --- | --- | --- |
| `plan_id` | `pln_` plus 32 lowercase hex characters from 16 bytes of OS randomness (`getrandom`) | No |
| `kind`, `class` | Static names, for example `rules_set_enabled` and `rules-toggle` | Yes |
| `target` | `profile`, `kibana_url`, `es_url` or null, `space`. The URLs are the resolved, validated strings; they are hashed and never output. Output uses the 0.7 `{profile, host, space}` | Yes |
| `credential` | 64 hex characters ([section 5.2](#52-binding)) | Yes |
| `operation` | What the apply sends, as JSON (table below) | Yes |
| `preconditions` | What the planner read, as a list of `{object, id, state}` sorted by `object` then `id` ([section 5.3](#53-drift)) | Yes |
| `action`, `details` | The `preview_action` and `preview_details` of the `-api` plan, from the same reads | No |
| `hash` | SHA-256 of the canonical body, 64 lowercase hex characters | - |
| Times, state, prompt count, pending handle, outcome | Process bookkeeping | No |

The hashed body is this object, with `v` fixed at 1:

```json
{"v":1,"kind":"rules_set_enabled","class":"rules-toggle",
 "target":{"profile":"analyst","kibana_url":"https://kibana.example.test","es_url":null,"space":"default"},
 "credential":"<64 hex>","operation":{},"preconditions":[]}
```

Canonical bytes: sort the keys of every object by UTF-8 byte order at every
depth, keep array order, and write compact `serde_json` output with no
trailing newline. The workspace builds `serde_json` with `preserve_order`, so
the sort is explicit. The hash identifies a change within one release. It is
not an interchange format; `v` changes when the body changes.

The id and the times are outside the hash. Two plans for the same change
against the same observed state have the same hash and different ids.

| Kind | `operation` |
| --- | --- |
| `rules_set_enabled` | `{"enabled": bool, "rule_ids": [...]}` |
| `alerts_set_status` | `{"status": "...", "reason": "..." or null, "alert_ids": [...]}` |
| `alerts_set_tags` | `{"add": [...], "remove": [...], "alert_ids": [...]}` |
| `cases_create` | `{"title": "...", "description": "..." or null, "tags": [...], "severity": "..." or null, "sync_alerts": false}` |
| `cases_comment` | `{"case_id": "...", "message": "..."}` |
| `cases_set_status` | `{"status": "...", "updates": [{"id": "...", "version": "..."}], "resolved": n}` |
| `rules_create` | `{"rule": {...}}`, the stored rule with `enabled: false` |

The plan also keeps the typed `-api` plan value (`MutationPlan`, `StatusPlan`,
`TagsPlan`, `CreatePlan`, `CommentPlan`, the case `StatusPlan`,
`RuleCreatePlan`). The apply passes that value to the `-api` apply function.
`operation` is its projection for the hash and for `plan_get`.

### 5.2 Binding

**Target.** One process has one resolved target, fixed at startup (0.7
section 4). A plan stores it. The apply compares the stored target with the
process target and refuses a mismatch as `plan_stale`. In a correct build the
two are always equal; the check exists so a later change to target handling
cannot silently break the binding.

**Credential.** The planner reads `GET /_security/_authenticate` through
`health::credential_identity`, the read `doctor` already makes. The plan
stores

```text
credential = SHA-256("v1\n" + realm_type + "\n" + username + "\n" + api_key_id)
```

with an empty `api_key_id` when the response has none. Rules:

- The read needs the profile's Elasticsearch URL. A server started with
  `--allow-mutations` and a profile without `es_url` does not start: it
  exits with a static line that names `es_url`
  ([section 3](03-startup-opt-in-and-catalog.md#3-startup-opt-in-and-catalog)).
  The owner accepted this requirement on 2026-11-10.
- If the read fails at run time, the planner fails with the mapped Elastic
  error. No plan is stored.
- Every mutation kind is refused with `credential_unsuitable` when
  `realm_type` is `_cloud_api_key`, before any other read (D41). An
  organization-level key reaches every deployment and project of the
  organization, and `_authenticate` does not show its role scope, so a plan
  cannot show what the key may do. The refusal
  is policy: Serverless 9.7.0 accepts such a key for an enable, and Hosted
  refuses it at `_authenticate`
  ([shared design 7.2](../elasticctl-design/07-verified-api-facts.md#72-rule-mutation-requires-a-project-scoped-api-key)).
  The person is never asked to confirm a change made with a key whose reach
  the plan cannot show.
- Each check before a write reads the identity again and compares. A
  different value is `plan_stale`. A failed read is an error and the plan
  stays open.
- Output and audit lines carry the first 12 hex characters of `credential`.
  The username, realm, and key id are never output.

**Client.** stdio has one client per process. Plans are visible to that
client for the life of the process and to nothing else. There is no
cross-process or cross-user plan.

### 5.3 Drift

Each planner returns the preview and the preconditions from the same reads,
so the text a person confirms describes the state the plan is bound to.

| Kind | `object` | `id` | `state` |
| --- | --- | --- | --- |
| `rules_set_enabled` | `rule` | `rule_id` | The rule after `normalize::canonical`, which keeps `enabled` and drops the volatile fields |
| `alerts_set_status` | `alert` | `_id` | `{"workflow_status": "..."}` |
| `alerts_set_tags` | `alert` | `_id` | `{}`: the alert exists. A tag edit is relative, and the consent text names the edit, not the full tag set |
| `cases_set_status` | `case` | case id | `{"status": "...", "title": "...", "version": "...", "sync_alerts": false}`. `sync_alerts` is `settings.syncAlerts` when that is a JSON boolean, and `null` when it is missing or any other type |
| `cases_comment` | `case` | case id | `{"status": "...", "title": "..."}` |
| `cases_create` | none | - | The list is empty |
| `rules_create` | `rule` | `rule_id` | `null`: the rule must not exist |

Two rules hold when a plan is made and again at each check, before states
are compared:

- **A rule read must return the id that was asked for.** The route
  `GET rules?rule_id=` matches through KQL, which decodes escapes, so asking for
  `r\\n` can return the rule stored as `r\n`, while the escaped bulk query
  targets the id as written. Planning resolves selectors with
  `selection::to_rule`, which already reads again by the stored id when the
  two differ. On top of that, every `rule` entry with a state must have
  `state.rule_id` byte-equal to its `id`
  (`observe::require_rule_identity`). A mismatch when planning is
  `elastic_conflict` and no plan. A mismatch at a check is `plan_stale`.
- **A case whose status will change must not sync alert status.** Kibana
  closes or reopens the alerts attached to a case when the case's
  `settings.syncAlerts` is on. Those alerts are not in the plan, nobody saw
  them in the consent text, and the write would reach them even with
  `alerts-triage` off. A `cases_set_status` plan therefore requires
  `sync_alerts` to be exactly `false` for every case. `true` or `null` when
  planning is the tool error `case_sync_alerts` and no plan. `true` or
  `null` at a check closes the plan as `stale` and returns
  `case_sync_alerts`. A setting changed after the last check moves the case
  `version`, so Kibana answers the write with 409.

A check re-reads the credential identity, calls the kind's `observe_*`
function with the plan's ids, sorts the result, and compares its canonical
bytes with the stored list. `plan_apply` runs the check twice:

1. before the person is asked, so nobody confirms a plan that is already
   stale;
2. after the person accepts, immediately before the write.

Outcomes of a check:

- Equal: continue.
- Different, or an object is missing, or a rule that must be absent exists:
  the plan becomes `stale`, which is final, and the call returns
  `plan_stale`. The error does not say what changed. A new planner call shows
  the new state.
- The read itself fails: the call returns the mapped Elastic error. The plan
  stays open. If this was the second check, the confirmation is spent and
  the person is asked again on the next `plan_apply`.

The stack adds two checks of its own. A case status write carries the
`version` the planner read, and Kibana answers 409 when it is stale. A rule
create collides on `rule_id` with 409. Both map to `stale`.

What the checks do not cover:

- Rule toggles and alert writes have no conditional form. A change that
  lands between the second check and the write is not seen. The window is
  one request long. The CLI has the same window between its preview and
  `--yes`, and it is longer there.
- Alert state is read through a search. A change made within the index
  refresh interval may be missed. Alert writes are idempotent, and a second
  plan can set the status back. Measurement M4 records the observed delay.
- A comment plan does not track `version`, so another person's comment does
  not make it stale. That is intended.

### 5.4 States, expiry, and limits

| State | Meaning | Final |
| --- | --- | --- |
| `open` | Stored, not applied | No |
| `applying` | The write has been handed to the transport | No |
| `applied` | The write returned a decoded response | Yes |
| `failed` | The stack refused the write. Nothing changed | Yes |
| `unknown` | The write was sent and no trustworthy answer came back | Yes |
| `declined` | A person declined, or three prompts passed without a confirmation | Yes |
| `stale` | A check found a change, or the stack refused the write with 409 because the object changed | Yes |
| `expired` | The plan's life ended while it was open | Yes |
| `discarded` | `plan_discard` closed it | Yes |

`open` moves to `applying` once, under the store lock. `applying` moves only
to `applied`, `failed`, `unknown`, or `stale`. `applying` to `stale` happens
in one case: the write of a `cases_set_status` or `rules_create` plan is
answered 409 ([section 8.2](08-apply-errors-and-cancellation.md#82-classifying-the-write)).
`open` also moves to `stale` when a check fails. No state returns to
`open`.

| Limit | Value | When reached |
| --- | --- | --- |
| Plans not final (`open` or `applying`) | 8 | A planner returns `too_many_plans`. Neither state is evicted, so the store holds at most 40 plans |
| Final plan records | 32 | The oldest is dropped. Its id then returns `plan_not_found` |
| Plan life | 900 seconds from creation, on the monotonic clock | An open plan becomes `expired` at its next access. No call extends it |
| Objects per plan | 20 | `invalid_argument` before I/O |
| Canonical plan body | 262,144 bytes | The planner returns `plan_too_large`; nothing is stored |
| Consent text | 8,192 bytes | The planner returns `plan_too_large`; nothing is stored |
| Prompts per plan | 3 | The plan becomes `declined` |
| Legacy confirmations waiting | 1 per process | A second `plan_apply` returns `confirmation_pending` |
| Legacy wait for a person | 240 seconds | `confirmation_timeout`; the plan stays open |

The consent text is built and measured when the plan is made. Every stored
plan can therefore be shown in full.

Expiry is evaluated when a plan is read. A confirmation that arrives after
expiry does not apply; the call returns `plan_expired`. A plan that is
`applying` does not expire. Any store operation may expire other open plans
on the way; it hands each one it closed back to the caller, which writes one
`plan_closed` line per plan.

The store is one `std::sync::Mutex` inside `ServerState`. The lock is never
held across an await. Nothing is written to disk. When the process exits,
every plan is gone and a later process answers `plan_not_found`.

### 5.5 Replay

`plan_apply` is safe to call again. What it does depends only on the plan's
state:

| State | `plan_apply` does |
| --- | --- |
| `open` | Runs the confirmation flow ([section 6](06-confirmation-protocol.md#6-confirmation-protocol)) |
| `applying`, `applied`, `failed`, `unknown` | Returns the plan view with its state, its stored outcome if any, and `replayed: true`. No prompt, no Elastic request |
| `declined`, `stale`, `expired`, `discarded` | Returns the tool error named after the state |

Rules that make this hold:

- A plan has at most one live confirmation handle. The handle is `cfm_` plus
  32 hex characters of OS randomness. It is spent the first time it is
  presented, whatever the answer.
- The write is sent on a transport with one HTTP attempt, no redirects, and
  no connection reuse ([section 7](07-api-reuse.md#one-request-per-write-in--core)).
  Neither the server nor the HTTP stack repeats a write. A create or a
  comment cannot be sent twice.
- After `unknown`, the server does nothing further. The caller reads the
  object and decides. Planning the same change again makes a new plan and
  asks the person again.
