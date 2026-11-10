[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 6. Confirmation protocol

`plan_apply` asks the client to show one form. The same form, text, and
answer rules apply on both supported protocol revisions. Only the transport
of the question differs.

The path is chosen from the protocol version of the `plan_apply` request:
2026-07-28 uses [section 6.2](#62-current-protocol), 2025-11-25 uses
[section 6.3](#63-legacy-protocol). The SDK rejects the wrong shape on each
side, so a wrong choice is a protocol error, never an apply.

Before either path, `plan_apply` runs these steps in order and stops at the
first that fails:

1. Decode `{plan_id}`. Unknown keys are `invalid_argument`.
2. Find the plan. Handle every state other than `open` as
   [section 5.5](05-plans.md#55-replay) says. Apply expiry.
3. Check that the request's client capabilities include form elicitation:
   an `elicitation` entry with `form`, or an empty `elicitation` object.
   Otherwise return `confirmation_unavailable`
   ([section 2.1](02-consent-model.md#21-what-happens-without-elicitation)).
   No Elastic request has been sent at this point.
4. If the plan has already prompted three times, set it to `declined` and
   return `plan_declined`.
5. Run the first drift check ([section 5.3](05-plans.md#53-drift)).
6. Count one prompt. On the current protocol, create a new confirmation
   handle and replace any older handle on the plan. Write the
   `confirmation_requested` audit line.

The prompt is counted when the question is issued, not when it is answered,
so unanswered questions are bounded too.

### 6.1 Consent text

The elicitation `message` is this text. Lines in angle brackets are filled
in; every other character is fixed.

```text
elasticctl asks to apply a change.

Target: profile <profile> @ <host>, space <space>
Change: <action>
  <detail>
  <detail>
Note: <note>
Plan: <plan_id>
Hash: <first 16 hex characters of the plan hash>
Expires in <n> min.

Set "Apply this change" to true and accept to apply it.
Decline, or leave it false, and nothing changes.
```

`<action>` and `<detail>` are the plan's `action` and `details`. They come
from the `-api` plan, the same text the CLI guard prints. For a kind whose
`-api` preview omits text that will be written, the server appends detail
lines built from `operation`:

| Kind | Detail lines |
| --- | --- |
| `rules_set_enabled` | `-api` details: `<rule_id>  <name>  <from> -> <to>` per rule. Key note |
| `alerts_set_status` | `-api` details: `<_id>  <rule name>  <from> -> <to>` per alert; then `reason: <reason>` when set |
| `alerts_set_tags` | `-api` details: `<_id>  <rule name>  +<tag> -<tag>` per alert |
| `cases_create` | `-api` details (`severity`, `tags`); then `description: <text>` when set; then the static line `syncAlerts: false`, which is what `cases::create` sends |
| `cases_comment` | `case_id: <case id>` from `operation`, then the `-api` details: the message. The `-api` preview names the case by title only, and titles are not unique |
| `cases_set_status` | `-api` details: `<id>  <title>  <from> -> <to>` per case; then the static line `attached alerts: not changed (syncAlerts is off for every case listed)` |
| `rules_create` | `-api` details from `rules_ops::plan_create`: one line per field of the stored rule, every field, whole value ([section 7](07-api-reuse.md#rules)). Key note |

Every object a plan writes to is named by its identity on a detail line:
`rule_id`, alert `_id`, or case id. A name or title alone never identifies a
target.

The `Note:` line is present only for the two rule kinds. It is static text:

```text
Note: Kibana ties each rule listed to this server's credential (<12 hex>). The rule then runs with that credential's privileges and stops if it is deleted or disabled. Undoing this change does not restore the earlier one.
```

`<12 hex>` is the plan's credential value. Kibana documents that the
caller's API key is assigned to the affected rules, for rule create and for
bulk actions. The server cannot read which key a rule had before, so the
text does not claim a difference; it states what will be true after the
write.

Rendering rules, applied to every filled-in value:

1. Replace each of these characters with U+FFFD: C0 controls other than line
   feed, DEL, C1 controls, U+2028, U+2029, and the bidirectional controls
   U+202A to U+202E and U+2066 to U+2069.
2. Split the value on line feeds. The first line goes where the template
   shows. Each further line starts with two spaces, a vertical bar, and a
   space.
3. Detail lines start with two spaces.
4. Nothing is truncated or summarized. If the finished text is longer than
   8,192 bytes, the planner refuses the plan with `plan_too_large`.
5. Text that the plan will write is never altered by rule 1. The planner
   refuses such input instead
   ([section 4.1](04-mutation-set.md#41-planner-inputs)), so what is shown
   is what is stored. Rule 1 applies only to text read from the stack.
6. `<n>` is the remaining life in whole minutes, rounded up, from 15 down to
   1. The planner measures the text with 15, so a later, smaller number
   never makes it longer.

The result has one property a reader can use: a line that starts at the left
margin was written by elasticctl, and an indented line is data. Text from the
stack or from the model cannot produce a line at the left margin, cannot
change the target line, and cannot hide an affected object, because every
object has its own detail line or the plan does not exist.

The text names no URL meant to be opened.

The form has one field:

```json
{"type": "object",
 "properties": {"apply": {"type": "boolean", "title": "Apply this change",
   "description": "True applies the change shown above. False keeps the dry run.",
   "default": false}},
 "required": ["apply"]}
```

Reading the answer:

| Answer | Result | Plan |
| --- | --- | --- |
| `accept` with `content.apply` exactly `true` | Confirmed | Continues to the second check |
| `accept` with `apply` false, missing, or not a boolean | `not_confirmed` | Stays `open` |
| `decline` | `plan_declined` | Becomes `declined` |
| `cancel` | `not_confirmed` | Stays `open` |
| Anything that does not decode as an elicitation result | `not_confirmed` | Stays `open` |

Extra keys in `content` are ignored. `decline` closes the plan so the same
plan cannot be put in front of the person again.

### 6.2 Current protocol

On 2026-07-28 the question is a tool result and the answer is a second
request.

Round 1, a `plan_apply` request without `inputResponses`: after the six steps
above, return

```json
{"resultType": "input_required",
 "inputRequests": {"confirm": {"method": "elicitation/create",
   "params": {"mode": "form", "message": "<consent text>", "requestedSchema": {}}}},
 "requestState": "cfm_<32 hex>"}
```

with the schema from section 6.1. This is not a tool result envelope and has
no `structuredContent`. The call ends here and frees its permit. No time
limit runs between the rounds except the plan's life.

Round 2, a `plan_apply` request with `inputResponses`:

1. Decode `{plan_id}` and find the plan as before. It must be `open` and not
   expired.
2. Take the plan's live handle, leaving none. If the request has no
   `requestState`, or it differs from the handle taken, or there was no
   handle, return `not_confirmed`.
3. Read `inputResponses.confirm` and apply the answer table. Other keys in
   `inputResponses` are ignored.
4. If confirmed, run the second check and the write
   ([section 8](08-apply-errors-and-cancellation.md#8-apply-errors-limits-and-cancellation)).

Edge cases:

- A request with `requestState` and no `inputResponses` is treated as round
  1: the old handle is replaced and the question is asked again, as the MRTR
  rules ask for a missing input. It counts as a prompt.
- The handle is stored on one plan. A round 2 request that names a different
  `plan_id` finds a different handle or none and is `not_confirmed`.
- The handle carries no data. Changing it can only make the request fail, so
  it needs no signature. Single use is enforced by taking it in step 2.

### 6.3 Legacy protocol

On 2025-11-25 the question is a request the server sends while the
`plan_apply` call is open.

1. Run the six steps above. Between steps 4 and 5, if another legacy
   confirmation is waiting in this process, return `confirmation_pending`.
2. Free the call permit. A call that waits for a person does not block reads.
3. Send `elicitation/create` with `mode: "form"`, the consent text, and the
   schema, using a 240 second timeout. Wait for the first of: the answer, the
   timeout, cancellation of the `plan_apply` request, or session shutdown.
4. On timeout return `confirmation_timeout`. On cancellation send no result.
   The plan stays `open` in both cases.
5. On an answer, apply the answer table. An SDK error from the client counts
   as `not_confirmed`.
6. If confirmed, take a call permit again, waiting at most the call timeout;
   if none frees, return `busy` and leave the plan `open`. Then run the
   second check and the write under a fresh call deadline.

The call deadline of 0.7 covers the steps before the question and, started
again, the steps after the answer. It does not run while a person reads. 240
seconds is below the 300 second default tool timeout of Codex CLI, the
shortest verified client limit.

No handle exists on this path. The answer is tied to the plan by the open
request itself.
