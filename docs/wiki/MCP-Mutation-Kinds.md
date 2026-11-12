# MCP Mutation Kinds

Each mutation class adds planner tools to the MCP server. A planner reads the
stack, stores a plan, and writes nothing; `plan_apply` applies the plan after a
person confirms it. [MCP Mutations](MCP-Mutations.md) covers starting the
server, the confirmation form, plan states, and errors. Each plan sends one
write request:

| Class | Planner tools | Write per plan |
| --- | --- | --- |
| `rules-toggle` | `rules_set_enabled_plan` | `POST /api/detection_engine/rules/_bulk_action` |
| `alerts-triage` | `alerts_set_status_plan`, `alerts_set_tags_plan` | `POST /api/detection_engine/signals/status` or `POST /api/detection_engine/signals/tags` |
| `cases` | `cases_create_plan`, `cases_comment_plan`, `cases_set_status_plan` | `POST /api/cases`, `POST /api/cases/<id>/comments`, or `PATCH /api/cases` |
| `rules-create` | `rules_create_plan` | `POST /api/detection_engine/rules` |

## Rules for every planner

- Unknown input keys fail. String inputs must contain non-whitespace text and
  are used unchanged. Limits count UTF-8 bytes. A value outside a limit is
  `invalid_argument` before any request.
- A plan names each object by identity: `rule_id`, alert `_id`, or case id. It
  holds at most 20 objects and never lists one twice.
- Text the plan writes must show in the form exactly as it is stored. A case
  title, description, or comment, or a tag, that holds a control character
  other than a line feed (a tab, for example), DEL, a Unicode line or
  paragraph separator, or a bidirectional control is `invalid_argument`.
- An organization-level Elastic Cloud API key (realm `_cloud_api_key`) is
  refused with `credential_unsuitable` for every kind, before any other read.
  It reaches the whole organization and its role scope cannot be read, so a
  plan cannot show what it may do. Use a scoped key
  ([which key](Configuration.md#which-api-key-to-use)).
- The form's action line holds one line. A case title read from the stack
  shows each line break there as U+FFFD, and a new case title with a line break
  is `invalid_argument`. The first three lines always hold the action, the
  target, and the first object.
- No kind is exactly reversible.
  [What a second call leaves](#what-a-second-call-leaves) lists what each
  kind does not restore.

## rules-toggle

`rules_set_enabled_plan` enables or disables named rules.

| Input | Value |
| --- | --- |
| `selectors` | 1 to 20 unique strings, each a `rule_id` or exact rule name of at most 1,024 bytes |
| `enabled` | Boolean, required |

- Each selector resolves to a `rule_id` as `rules_get` does; see
  [Selectors](CLI.md#selectors). Two selectors that resolve to the same rule
  fail with `invalid_argument`.
- A read that returns a rule with another `rule_id` than the one asked for
  fails with `elastic_conflict`, and no plan is stored.
- Each detail line is `<rule_id>  <name>  <from> -> <to>`. A rule already in
  the requested state stays in the plan as `enabled -> enabled` or
  `disabled -> disabled`.
- `cli_equivalent` is `rules enable` or `rules disable` with the `rule_id`
  values.
- A drift check compares each rule's content. Fields the server maintains,
  such as `revision`, update times, and execution status, do not count.

The `Note:` line of a rule toggle:

```text
Note: Kibana runs each rule listed with the credential it already has. A rule that has none gets this server's credential (<12 hex>) when it is enabled, and then runs with that credential's privileges.
```

## alerts-triage

`alerts_set_status_plan` sets the workflow status of alerts named by id.

| Input | Value |
| --- | --- |
| `alert_ids` | 1 to 20 unique alert `_id` strings, each at most 1,024 bytes |
| `status` | `open`, `acknowledged`, or `closed` |
| `reason` | Optional, only with `closed`: `false_positive`, `duplicate`, `true_positive`, `benign_positive`, `automated_closure`, or `other` |

`alerts_set_tags_plan` adds and removes workflow tags on alerts named by id.

| Input | Value |
| --- | --- |
| `alert_ids` | As above |
| `add`, `remove` | 0 to 10 unique strings each, each at most 256 bytes. At least one tag in total, and no tag in both lists |

- The class cannot select alerts by query and cannot assign alerts. Use
  `alerts close --query` and `alerts assign` in the CLI for those.
- A status plan shows `<_id>  <rule name>  <from> -> <to>` per alert, or
  `already <status>`, then `reason: <reason>` when set. A tags plan shows
  `<_id>  <rule name>  +<tag> -<tag>` per alert. It names the edit, not the
  alert's full tag set.
- `cli_equivalent` is `alerts ack`, `alerts open`, or `alerts close` with the
  ids and `--reason`, or `alerts tag` with the ids and `--add` or `--remove`
  per tag.
- A status plan is stale when an alert's status changed or the alert no
  longer resolves. A tags plan is stale only when an alert no longer resolves.
  Both checks read through a search, so a change made within one index refresh
  may be missed.

## cases

`cases_create_plan` creates one case.

| Input | Value |
| --- | --- |
| `title` | Required, at most 160 bytes, without a line break |
| `description` | Optional, at most 4,096 bytes |
| `tags` | 0 to 10 unique strings, each at most 256 bytes |
| `severity` | Optional: `low`, `medium`, `high`, or `critical` |

`cases_comment_plan` adds one comment to a case.

| Input | Value |
| --- | --- |
| `id` | The case id, at most 1,024 bytes |
| `message` | At most 4,096 bytes |

`cases_set_status_plan` closes or reopens cases.

| Input | Value |
| --- | --- |
| `ids` | 1 to 20 unique case ids, each at most 1,024 bytes |
| `status` | `open` or `closed` |

- A new case has no assignees: `assignees` is an unknown input key. It is
  created with `settings.syncAlerts` set to `false`, and `settings` and
  `syncAlerts` are unknown input keys too.
- A create plan shows the title on the action line. Its detail lines are
  `severity:`, `tags:`, and `description:` with the full text, each when set,
  then the line `syncAlerts: false`.
- A comment plan's first detail line is `case_id: <case id>`, then the full
  message. Case titles are not unique, so the id names the case.
- A status plan shows `<id>  <title>  <from> -> <to>` per case, or
  `already <status>`, then the line
  `attached alerts: not changed (syncAlerts is off for every case listed)`.
- `cli_equivalent` is `cases create --title <title>` with `--description`,
  `--tag` per tag, and `--severity` when set; `cases comment <id> --message
  <message>`; or `cases close` or `cases open` with the ids.
- A comment plan is stale when the case's title or status changed. Another
  comment on the case does not make it stale. A status plan sends the case
  `version` it read; Kibana answers a changed case with 409, and the plan
  becomes `stale` with `plan_stale`.

### Alert sync refusal

`cases_set_status_plan` refuses with `case_sync_alerts` when any case's
`settings.syncAlerts` is not the JSON value `false`: on, missing, or another
type. With alert sync on, Kibana also closes or reopens the alerts attached to
the case, and those alerts are not in the plan. No plan is stored and nothing
is written. The message is `The case syncAlerts setting must be false.`

Both drift checks repeat the test. If a case's `syncAlerts` is no longer
`false` at either check, the plan closes as `stale` and the call returns
`case_sync_alerts` without a write.

## rules-create

`rules_create_plan` creates one rule, always disabled. Its one input, `rule`,
is a JSON object of at most 65,536 bytes when serialized.

- `rule_id`, `name`, and `type` are required non-blank strings.
- `enabled` must be absent or `false`. The plan stores `enabled: false`, so
  the class cannot create an enabled rule.
- These keys are refused: `id`, `created_at`, `created_by`, `updated_at`,
  `updated_by`, `revision`, `version`, and `execution_summary`. A non-empty
  `actions` or `response_actions` is refused because it calls connectors or
  acts on hosts when the rule fires. A non-empty `exceptions_list` is refused
  because its pointers are stack-specific and only `state push` resolves them.
- A `rule_id` that already exists is `elastic_conflict`, and no plan is
  stored. A rule with that `rule_id` that appears after planning makes the
  plan `stale`, and so does a 409 answer to the write.
- The form shows every field of the stored rule on its own line as
  `<key>: <JSON value>`, whole: the `rule_id` line first, then the other fields
  in byte order of the key. A query with line breaks or tabs shows them as
  `\n` and `\t`. A string with DEL, a C1 control, a Unicode line or paragraph
  separator, or a bidirectional control is `invalid_argument`.
- There is no separate query limit. A rule whose form text passes 8,192 bytes
  is `plan_too_large`. Create a larger rule with `rules import`.
- `cli_equivalent` is `null`: no CLI command takes a rule inline. Use
  `rules import` with a file.
- A response that shows another `rule_id` or an enabled rule makes the plan
  `unknown`, never `applied`.

The `Note:` line of a rule create names no credential:

```text
Note: Kibana creates the rule disabled and without an API key. The credential that first enables it gives it a key, and the rule then runs with that credential's privileges.
```

The created rule has no API key while it stays disabled. Enabling it takes a
separate `rules_set_enabled_plan` with its own confirmation, or the CLI. The
credential that first enables it gives it its key.

## Outcomes

An applied plan's `outcome` counts objects as follows. `complete` is `true`
when `updated + unchanged` equals `requested` and `failed` is 0.

| Kind | `requested` | `updated` | `unchanged` | `failed` | `created` |
| --- | --- | --- | --- | --- | --- |
| `rules_set_enabled` | Rules in the plan | Rules reported changed | 0 | Rules reported failed or skipped, plus rules not reported | `null` |
| `alerts_set_status`, `alerts_set_tags` | Alerts in the plan | Alerts reported updated | Alerts reported unchanged | Alerts reported failed or in version conflict, plus alerts not reported | `null` |
| `cases_set_status` | Cases in the plan | Cases reported updated | Cases already in the requested status | Cases reported failed | `null` |
| `cases_comment` | 1 | 1 | 0 | 0 | `null` |
| `cases_create` | 1 | 1 | 0 | 0 | `{"case_id": "<id>"}` |
| `rules_create` | 1 | 1 | 0 | 0 | `{"rule_id": "<rule_id>"}` |

## What a second call leaves

| Kind | Set back by | Not restored |
| --- | --- | --- |
| `rules_set_enabled` | The same tool with the opposite value | The API key of a rule that had none: it keeps the key of the credential that enabled it |
| `alerts_set_status` | The same tool with the earlier status | The workflow user, time, and reason |
| `alerts_set_tags` | A second plan that adds or removes the named tags | Prior membership. The plan does not record which tags an alert had, so adding a tag that was present and then removing it loses it |
| `cases_set_status` | The same tool with the opposite status | The close time and the closing user |
| `cases_comment` | Nothing in elasticctl removes a comment | The comment stays |
| `cases_create` | `cases delete` in the CLI | Nothing once deleted |
| `rules_create` | `rules delete` in the CLI | Nothing once deleted |

A create or a comment is sent once. If its answer is lost, the plan is
`unknown`, and planning again would add a second case or comment. Read the
case first.
