# MCP Mutations

`elkctl mcp serve --allow-mutations <CLASSES>` lets an MCP client change a
bounded set of Elastic Security objects, one stored plan at a time, after a
person at the client confirms each plan. Without the flag the server is the
read-only server described in [MCP](MCP.md). Four classes cover rule enable
and disable, alert status and tags, case create, comment, and status, and
disabled rule create; see [MCP Mutation Kinds](MCP-Mutation-Kinds.md).

## How consent works

The operator decides which classes of change are possible. The person at the
client decides whether one plan applies. The model decides nothing: its tool
arguments are requests.

A change takes two calls and one answer:

1. A planner tool, such as `rules_set_enabled_plan`, reads the stack and
   stores a plan in server memory. It writes nothing to Elastic and returns a
   plan id.
2. `plan_apply` takes that plan id and nothing else. It asks the client to
   show a form that the server wrote, describing the plan.
3. Only a form answer of `accept` with "Apply this change" set to `true`
   applies the plan. Any other answer applies nothing.

No tool argument confirms a change: `plan_apply` has no `confirm`, `yes`,
`force`, or hash input. A planner call, a tool result, a resource, a prompt,
or text that says a person agreed is not consent either.

A client that cannot show a form cannot apply. `plan_apply` returns
`confirmation_unavailable` and sends no Elastic request. The plan stays open
and names the CLI command that makes the same change in `cli_equivalent`, for
example `["rules", "disable", "<rule_id>"]`. Run it with your global flags,
read the dry run, then add `--yes`. No flag, environment variable, or tool
makes the server apply without a form answer.

Client tool approval is not consent, but the server sets the hints clients
prompt on. `plan_apply` is marked `destructiveHint: true` and carries
`_meta["anthropic/requiresUserInteraction"]: true`; planners are marked
read-only. Claude Code then shows the `plan_apply` permission prompt on every
call, even in `acceptEdits`, `auto`, and `bypassPermissions` modes, and allow
rules do not skip it; in `dontAsk` mode it denies the call instead
([Claude Code docs](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool)).
In Claude Code a person therefore answers twice for one apply: the permission
prompt, then the form. Claude Code shows forms only in interactive terminal
sessions, so confirm plans from an interactive session, not `claude -p`.

## Start the server

```bash
elkctl --profile analyst --space default mcp serve \
  --allow-mutations rules-toggle
```

- The value is a comma-separated list of class names, and the flag may
  repeat. Duplicates fold into one set.
- Class names are `rules-toggle`, `alerts-triage`, `cases`, and
  `rules-create`. There is no `all` value and no wildcard, so a class added in
  a later version is never granted by an existing command line.
- An empty value, an unknown name, a trailing comma, or surrounding
  whitespace stops startup with exit code 2 and the static stderr message
  `Invalid MCP serve arguments.`, which never echoes the value.
- The flag combines with `--allow-query-tools`. For a client that uses an
  `mcpServers` object, append `"--allow-mutations", "rules-toggle"` to `args`
  in the [client stanza](MCP.md#register-with-a-client).
- The class set cannot be read or changed through MCP. Changing the
  configuration or the environment after startup does not change it.

Every plan reads the credential identity from Elasticsearch, so mutation
classes need the profile's Elasticsearch URL; see
[Configuration](Configuration.md#environment-variables). The form names the
target on one line, so the profile name, host, and space need no line break or
control character. Otherwise startup exits 1 before the protocol, with one of
these lines; without the flag, such a profile serves the read-only tools.

```json
{"error":{"kind":"error","message":"MCP mutation tools need an Elasticsearch URL. Set es_url in the profile or ELASTICCTL_ES_URL."}}
{"error":{"kind":"error","message":"MCP mutation tools need a profile name, host, and space without line breaks or control characters."}}
```

With at least one class enabled, startup writes this warning line to stderr
before the protocol starts, with the classes in name order. Startup makes no
Elastic request; a credential that cannot perform a class is found when a plan
is made.

```json
{"warning":{"kind":"mutations_enabled","message":"MCP mutation tools are enabled.","classes":["rules-toggle"]}}
```

## Tools

The four plan tools are listed when any class is enabled, and each planner
only when its class is enabled: 35 tools with all four classes, or 37 with
`--allow-query-tools`. A call to a tool that is not listed is the protocol
error for an unknown tool.

| Tool | Inputs | Returns |
| --- | --- | --- |
| A planner: `rules_set_enabled_plan`, `alerts_set_status_plan`, `alerts_set_tags_plan`, `cases_create_plan`, `cases_comment_plan`, `cases_set_status_plan`, or `rules_create_plan` | Per kind; see [MCP Mutation Kinds](MCP-Mutation-Kinds.md) | A new open plan |
| `plan_apply` | `plan_id` | The plan with its outcome, after a person confirms |
| `plan_get` | `plan_id` | The plan and its outcome |
| `plan_list` | None | `{"plans": [...]}`: open plans, then final records, newest first, each with `plan_id`, `kind`, `class`, `state`, `action`, and `expires_in_secs` |
| `plan_discard` | `plan_id` | The plan. An open plan is closed as `discarded`, a final plan is returned unchanged, and a plan that is applying returns `plan_not_open` |

A planner reads the credential identity and each object it names, and sends
no write. Every planner refuses an organization-level Elastic Cloud API key
with `credential_unsuitable` before any other read; use a scoped key
([which key](Configuration.md#which-api-key-to-use)).

With no class enabled the [server instructions](MCP.md#server-instructions)
are unchanged. With a class enabled, the sentence "It never changes Elastic or
local files." is replaced by:

```text
It changes Elastic only through a stored plan that a person confirms in the client; no tool argument confirms a change. It never changes local files. To change something, call a tool whose name ends in _plan, then plan_apply with the plan id.
```

## The plan

Planners, `plan_get`, and `plan_apply` return the usual
[result envelope](MCP.md#results) with this `data`:

```json
{"plan": {"plan_id": "pln_<32 hex>", "hash": "<64 hex>",
   "kind": "rules_set_enabled", "class": "rules-toggle", "state": "open",
   "expires_in_secs": 900, "credential": "<12 hex>",
   "action": "Disable 1 rule(s)",
   "details": ["<rule_id>  <name>  enabled -> disabled"],
   "targets": ["<rule_id>"],
   "operation": {"enabled": false, "rule_ids": ["<rule_id>"]},
   "confirmation": "elicitation",
   "cli_equivalent": ["rules", "disable", "<rule_id>"]},
 "outcome": null, "replayed": false}
```

| Field | Meaning |
| --- | --- |
| `hash` | SHA-256 of the kind, class, target, credential, operation, and the object state the planner read. The same change against the same state gives the same hash |
| `expires_in_secs` | Seconds left for an open plan; 0 for any other state |
| `credential` | The first 12 hex characters of a fingerprint of the credential. The username, realm, and key id are never returned |
| `action`, `details`, `targets`, `operation` | The change, as the CLI preview prints it. Rule names and case titles come from the stack, and planner inputs from the caller; both are [untrusted data](MCP.md#returned-data-is-untrusted) |
| `confirmation` | `elicitation` when the client that asked can show a form, `unavailable` when it cannot |
| `cli_equivalent` | The CLI arguments after the binary name and global flags, without `--yes`. `null` for a rule create |
| `outcome`, `replayed` | See [Results](#results) and [Replay](#replay) |

## Confirmation

`plan_apply` first finds the plan; one that is not open is handled as in
[Replay](#replay). It then checks that the client can show a form, closes the
plan as `declined` if it has already prompted three times, checks the plan
for [drift](#drift), and asks the person. After an accept with "Apply this
change" set to `true`, it checks for drift again and sends one write.

### What the person sees

The form message is this text. Values in angle brackets are filled in; every
other character is fixed.

```text
elasticctl asks to apply: <action>
Target: profile <profile> @ <host>, space <space>
  <detail>
  <detail>
Note: <note>
Plan: <plan_id>
Hash: <first 16 hex characters of the plan hash>
Expires in <n> min.

Set "Apply this change" to true and accept to apply it.
Decline, or leave it false, and nothing changes.
```

- Claude Code shows only the first three lines of the form. Read the full
  plan with `plan_get` before you accept.
- A line at the left margin was written by elasticctl. An indented line is
  data. Each object has its own detail line that names it by identity;
  [MCP Mutation Kinds](MCP-Mutation-Kinds.md) shows the lines of each kind.
- A detail value that spans lines continues on lines that start with `  | `.
  The action line holds one line: a line break from the stack shows there as
  U+FFFD. Text from the stack or the model therefore cannot produce a line at
  the left margin, change the target line, or hide an object. Control
  characters, Unicode line and paragraph separators, and bidirectional
  controls from the stack show as U+FFFD.
- Nothing is truncated or summarized. A plan whose text would pass 8,192 bytes
  is refused when it is made, with `plan_too_large`. The text names no URL.
- `<n>` is the remaining life in minutes, rounded up. `Hash` is the start of
  the plan's `hash`.

The `Note:` line appears only for a rule toggle and a rule create; see the
[toggle note](MCP-Mutation-Kinds.md#rules-toggle) and the
[create note](MCP-Mutation-Kinds.md#rules-create).

The form has one boolean field, "Apply this change", with default `false`.
Only `accept` with it set to `true` continues to the second drift check and
the write. `decline` closes the plan as `declined` and returns
`plan_declined`. `accept` with `false` or no value, `cancel`, or an answer
that does not decode returns `not_confirmed` and leaves the plan open.

### Protocol revisions

The question travels differently on the two supported revisions:

- **`2026-07-28`:** `plan_apply` returns an input request with the form and a
  single-use `requestState`. The client shows the form, then calls
  `plan_apply` again with the same `plan_id`, the answer, and that
  `requestState`. No timer runs between the two calls except the plan's life.
  A missing or mismatched `requestState` is `not_confirmed`. A first-round
  call repeated before the answer asks again and counts as a prompt.
- **`2025-11-25`:** the server sends the form to the client while the
  `plan_apply` call waits, for up to 240 seconds. No answer in time is
  `confirmation_timeout`, and the plan stays open. One such wait runs per
  process; another `plan_apply` meanwhile returns `confirmation_pending`. The
  waiting call frees its call slot. The `--timeout` deadline starts again
  after the answer and covers the slot, the check, and the write; if no slot
  frees within it, the call returns `busy` and the plan stays open.
- **A mismatched shape:** another version in `_meta` after `initialize`, or
  `requestState` or `inputResponses` on `2025-11-25`, makes a mutation call
  the protocol error `invalid_request`, before any read.

## Plan lifecycle

| State | Meaning | Final |
| --- | --- | --- |
| `open` | Stored, not applied | No |
| `applying` | The write has been handed to the transport | No |
| `applied` | The write returned a decoded response | Yes |
| `failed` | The stack refused the write. Nothing changed | Yes |
| `unknown` | The write was sent and no trustworthy answer came back | Yes |
| `declined` | A person declined, or three prompts passed without a confirmation | Yes |
| `stale` | A drift check found a change, or the stack refused the write with 409 because the object changed | Yes |
| `expired` | The plan's life ended while it was open | Yes |
| `discarded` | `plan_discard` closed it | Yes |

| Limit | Value | When reached |
| --- | --- | --- |
| Plans open or applying | 8 | A planner returns `too_many_plans` |
| Final plan records kept | 32 | The oldest is dropped; its id then returns `plan_not_found` |
| Plan life | 15 minutes from creation | An open plan becomes `expired`. No call extends it |
| Objects per plan | 20 | `invalid_argument` before any request |
| Consent text | 8,192 bytes | `plan_too_large`; nothing is stored |
| Plan body | 262,144 bytes | `plan_too_large`; nothing is stored |
| Prompts per plan | 3 | The plan becomes `declined` |
| Waiting confirmations on `2025-11-25` | 1 per process | `confirmation_pending` |
| Wait for a person on `2025-11-25` | 240 seconds | `confirmation_timeout`; the plan stays open |

The [MCP limits](MCP.md#limits) still apply: four active calls and the
whole-call `--timeout`. Plans live in server memory only and are visible only
to the connected client. When the process exits every plan is gone, and a
later process answers `plan_not_found`.

### Drift

A plan is bound to the target, the credential, the exact operation, and the
state of each object the planner read. `plan_apply` checks that binding
twice: before it asks the person, and after the person accepts, right before
the write. Each check reads the credential identity and each object again.

- If the credential differs, an object is missing or changed, or a rule to be
  created now exists, the plan becomes `stale` and the call returns
  `plan_stale`. The error does not say what changed; plan again to see the
  new state. What counts as a change differs by [kind](MCP-Mutation-Kinds.md).
- If a read fails, the call returns the Elastic error and the plan stays
  open. After a failed second check the person is asked again.
- A case status write carries the case `version`, and a rule create collides
  on `rule_id`. A 409 answer to either also makes the plan `stale`.
- A rule toggle or an alert write has no conditional form, so a change made
  between the second check and the write is not seen.

### Replay

`plan_apply` is safe to call again. A plan applies at most once.

| State | `plan_apply` returns |
| --- | --- |
| `open` | The confirmation flow |
| `applying`, `applied`, `failed`, `unknown` | The plan with its state and outcome, `replayed: true`. No prompt and no Elastic request |
| `declined`, `stale`, `expired`, `discarded` | The error named after the state, such as `plan_stale` |

## Results

An applied plan carries an outcome; any other state has `outcome: null`.

```json
{"requested": 2, "updated": 1, "unchanged": 0, "failed": 1,
 "complete": false, "created": null}
```

[Outcomes](MCP-Mutation-Kinds.md#outcomes) gives each kind's counters.
`complete: false` is a successful result, not an error. Per-object failure
text is not returned; read the objects with the read tools. A report whose
counters overflow or pass the planned count is not mapped: the plan becomes
`unknown` with no outcome, and the call returns `apply_outcome_unknown`.

### Errors

Errors use the [MCP error object](MCP.md#errors). Each code has a fixed
message that never includes a plan id, an object id, or stack text.

| Code | Kind | Meaning |
| --- | --- | --- |
| `plan_not_found` | `not_found` | No plan with that id in this process |
| `plan_expired` | `conflict` | The plan's life ended |
| `plan_stale` | `conflict` | The target changed after the plan was made |
| `plan_declined` | `permission` | A person declined, or the prompt limit was reached |
| `plan_discarded` | `conflict` | The plan was discarded |
| `plan_not_open` | `conflict` | `plan_discard` on a plan that is applying |
| `plan_too_large` | `unsupported` | The plan or its consent text exceeds a limit |
| `too_many_plans` | `error` | Eight plans are open or applying |
| `not_confirmed` | `permission` | The form was not accepted with `apply: true` |
| `confirmation_unavailable` | `unsupported` | The client cannot show a form |
| `confirmation_pending` | `error` | Another confirmation is waiting (`2025-11-25`) |
| `confirmation_timeout` | `timeout` | No answer in 240 seconds (`2025-11-25`) |
| `credential_unsuitable` | `permission` | The credential cannot perform this kind of change |
| `case_sync_alerts` | `unsupported` | A case in the plan has `syncAlerts` on or unreadable; see [alert sync refusal](MCP-Mutation-Kinds.md#alert-sync-refusal) |
| `apply_pending` | `timeout` | The write was sent; the call ended before its answer |
| `apply_outcome_unknown` | The error's kind | The write was sent; its result is not known |

The codes of [MCP errors](MCP.md#errors) also apply. A write the stack refuses
with a status from 400 to 499, including 429, is `failed` and returns
`elastic_<kind>` with `http_status`. Nothing changed.

The write uses one HTTP attempt on a fresh connection with no redirects, so
it is never sent twice. Two codes need you to check the stack:

- **`apply_pending`:** the `--timeout` deadline passed after the write was
  sent. The write keeps running, bounded by the profile's request timeout.
  Call `plan_get` later; it shows `applied`, `failed`, or `unknown`.
- **`apply_outcome_unknown`:** the write was sent and the answer does not say
  whether it landed: a status of 500 or more (in `http_status`), a timeout, a
  lost connection, or a response that does not decode. Read the objects with
  the read tools and decide. To try again, make a new plan; the person is
  asked again.

Cancelling `plan_apply` before the write stops it with nothing written and the
plan open. After the write is sent it runs to its response and its outcome is
recorded; `plan_get` shows it. When the server stops, it waits up to five
seconds for a write in flight. A plan still applying after that gets an
`apply_interrupted` audit line, and its outcome is lost with the process.

## Audit trail

Each step writes one JSON line to stderr; stdout carries only protocol
messages. Every line has `ts` (seconds since the Unix epoch), `event`,
`plan_id`, `hash`, `kind`, `class`, `profile`, `host`, `space`, `credential`,
and `protocol`.

```json
{"audit":{"ts":1794300000,"event":"apply_finished","plan_id":"pln_<32 hex>","hash":"<64 hex>","kind":"rules_set_enabled","class":"rules-toggle","profile":"analyst","host":"kibana.example.test","space":"default","credential":"<12 hex>","protocol":"2026-07-28","state":"applied","outcome":{"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true},"http_status":null}}
```

| Event | When | Extra fields |
| --- | --- | --- |
| `plan_created` | A planner stored a plan | `targets` |
| `confirmation_requested` | A question was sent to the client | `prompt`, 1 to 3 |
| `confirmation_answered` | An answer, timeout, or refusal was handled | `result`: `confirmed`, `not_confirmed`, `declined`, `timeout`, or `unavailable` |
| `apply_started` | The plan moved to `applying` | None |
| `apply_finished` | The write's outcome was recorded | `state`, `outcome`, `http_status` |
| `apply_interrupted` | The server stopped with a plan applying | None |
| `plan_closed` | A plan became `stale`, `expired`, `discarded`, or `declined` | `state` |

`targets` holds object ids, JSON-escaped; they are the only text from the
stack in the trail. Rule names, case titles, tags, messages, rule bodies,
queries, usernames, API key ids, URLs, and error messages never appear.
elasticctl writes no audit file: the trail lasts as long as you keep the
server's stderr, and `plan_list` shows up to 32 final records while the
process runs. The trail records what this process did; it is not proof
against someone who controls the process.

## Limits of the model

The server can check that an answer came through the client's form channel.
It cannot check that a person gave it.

- **A client can answer for the person.** A Claude Code `Elicitation` hook can
  accept a form with content
  ([hooks](https://code.claude.com/docs/en/hooks#elicitation)). A hook is
  operator configuration; when it accepts, that configuration consents. The
  Claude Code permission prompt on `plan_apply` still needs a person.
- **A model with a shell does not need MCP.** A coding client can let the
  model run `elkctl ... --yes` with the same profile. The client's command
  approval is the control there.
- **The form shows text from the stack.** Rule names and case titles appear
  as data. They cannot change the fixed lines, the target line, or the number
  of objects listed.
- **A person can be asked often.** A model can plan again after a decline. A
  declined plan is closed, each plan prompts at most three times, and at most
  eight plans are open. That bounds the rate; it does not stop it.
- **The last check is not atomic.** A change between the last read and the
  write is not seen.
- **A rule without a key takes the server's credential.** Kibana gives a rule
  an API key on its first enable. Enabled through MCP, such a rule then runs
  with this credential's privileges and stops if the key is deleted; a later
  disable keeps the key. A rule that already has a key keeps it. A rule
  created through MCP has no key until its first enable.
- **No kind is exactly reversible.** See
  [what a second call leaves](MCP-Mutation-Kinds.md#what-a-second-call-leaves).

MCP deletes nothing, edits no existing rule's content or any exception list,
and never runs `state push`. To limit what the server can change, start it
with a credential that holds only the privileges you intend it to use.
