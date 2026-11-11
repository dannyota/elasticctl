[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 4. Mutation set

A mutation enters 0.9 only if all six conditions hold:

| Id | Condition | Reason |
| --- | --- | --- |
| S1 | Its apply is one write request. | A sent write is whole or absent from the client's side. Cancellation and timeout stay simple. |
| S2 | The caller names every object by identity: `rule_id`, alert `_id`, or case id. | A plan can list what it touches and re-check each object. |
| S3 | Its direct effect is one field set back by another 0.9 tool, or it only adds a new object or an appended record. Any effect that is not set back is listed below, and one that changes how a rule runs is stated in the consent text. | A wrong confirmation is cheap to correct, and what it cannot correct is disclosed. |
| S4 | It uses a public route that already has a plan function in `-api`, or a single public route that needs one. | No internal Kibana route enters MCP. |
| S5 | Its whole effect fits in 8,192 bytes of consent text. | The person sees everything or the plan is refused. |
| S6 | It reads and writes no local file. | 0.7 gave tools no path input. |

### In, ranked

Rank is by how completely a wrong apply is corrected and how surely a change
made by someone else is caught before the write. No kind is exactly
reversible. The "not restored" column says what a second call leaves behind.

| Rank | Mutation | Class | Since | Corrected by | Not restored | Re-check |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Rule enable and disable | `rules-toggle` | 0.9.0 | The same tool with the opposite value sets `enabled` back | The rule's API key, for a rule that had none. Kibana gives a rule the enabler's key on its first enable, and a later disable or enable by another credential keeps that owner (M13). Such a rule then runs with this credential's privileges and stops if that key is deleted | Real-time read by `rule_id` |
| 2 | Alert status by id (open, acknowledged, closed) | `alerts-triage` | 0.9.1 | The same tool sets the status back | The workflow user, time, and reason | Search; can lag by a refresh |
| 3 | Alert tags by id | `alerts-triage` | 0.9.1 | A second plan can add or remove named tags | Prior membership. The plan does not record which tags an alert already had. Adding a tag that was present and then removing it loses it | Presence only, through a search |
| 4 | Case status (close, reopen) | `cases` | 0.9.1 | The same tool sets the status back | Close time and closing user | Kibana rejects a stale `version` |
| 5 | Case comment | `cases` | 0.9.1 | Nothing in elasticctl removes a comment | The comment stays | Case status and title |
| 6 | Case create (no assignees) | `cases` | 0.9.1 | `cases delete` in the CLI removes it | Nothing once deleted. A retry would add a second case, so a plan applies once | None needed |
| 7 | Rule create, always disabled | `rules-create` | 0.9.1 | `rules delete` in the CLI removes it | Nothing once deleted. While it exists, it carries this credential's key and model-written content | The `rule_id` must be absent |

Impact is a separate question. Disabling a rule stops a detection, and
enabling one starts query load and alerts. That is the highest impact in the
set.

`rules-toggle` ships first. This is an owner decision of 2026-11-10, made with
the API key effect known. The reasons: its re-check is the strongest, its
route and identity rules are the oldest and best measured in the project, and
it needs no alert or case fixtures. The consent text for every rule toggle and
rule create carries the key note of
[section 6.1](06-confirmation-protocol.md#61-consent-text).

### Out

| Candidate | Why out of 0.9 |
| --- | --- |
| Rule update | It changes the content of a live detection. A field-level diff of a rule does not fit S5, and a toggle cannot undo it (S3). Content changes go through `state push` with review in version control. |
| Rule delete | Destructive (S3) and one request per rule (S1). The CLI covers it. |
| Rule import | File input (S6). |
| Exception item create, update, delete | An item silences detections the moment it exists, so it is not additive in effect (S3). The CLI has no command that removes one item. A mirrored container's next `state push` would delete an item made here ([shared design 5.4](../elasticctl-design/05-state-engine.md#54-exceptions-in-the-mirror)). It needs its own design. |
| Exception container delete and import | Destructive, or file input. |
| Alert status by query | The set is resolved again at apply and the preview count is advisory. A plan cannot list or re-check it (S2). |
| Alert assignment, case assignees | Username lookup uses an internal Kibana route on Serverless, which 0.7 kept out of MCP (S4). A uid-only input has no MCP lookup behind it. |
| Case attach | One request per rule group (S1). A retry attaches twice. |
| Case delete | Permanent (S3). |
| Data view import, delete, default set and unset | Artifacts are file-shaped (S6). Overwrite replaces content (S3). The default data view changes what every user of the space sees. |
| Dashboard import and bundle import | File-shaped (S6). Bundles are opaque, so their effect cannot be shown (S5). |
| Fleet agent and integration policy changes | They change what agents run on hosts and carry secret references. The widest blast radius in the product, and multi-request (S1). |
| Prebuilt rule install | One request changes hundreds of rules. The effect cannot be listed (S5). |
| `state push` | It reads a local mirror (S6), sends many writes (S1), and removes items in mirrored containers (S3). Its review belongs in version control. |
| Rule preview | It creates preview alerts and is not a guarded CLI mutation. It stays a CLI command. |

Because `state push` and both delete commands stay out, the shared safety
contracts hold without new code: MCP deletes nothing, and `state push` is
never reached from MCP.

Identity rules are unchanged. A rule selector resolves to a `rule_id` when the
plan is made, exactly as `rules_get` resolves it. The plan stores `rule_id`
values and the apply targets `rule_id` values. No tool accepts or returns a
saved-object `id` as identity. No 0.9 tool touches an exception list.

### 4.1 Planner inputs

All 0.7 input rules apply: unknown keys fail, strings must contain
non-whitespace text, values are never trimmed or rewritten, and every check
that needs no I/O runs before I/O. A limit below is in UTF-8 bytes.

| Tool | Inputs | `-api` planner |
| --- | --- | --- |
| `rules_set_enabled_plan` | `selectors`: 1 to 20 unique strings, each at most 1,024. `enabled`: boolean, required | `rules_ops::plan_set_enabled_observed` |
| `alerts_set_status_plan` | `alert_ids`: 1 to 20 unique strings, each at most 1,024. `status`: `open`, `acknowledged`, or `closed`. `reason`: optional, one of `false_positive`, `duplicate`, `true_positive`, `benign_positive`, `automated_closure`, `other`; allowed only with `closed` | `alerts_ops::plan_status_by_ids_observed` |
| `alerts_set_tags_plan` | `alert_ids` as above. `add` and `remove`: 0 to 10 unique strings each, at most 256; at least one entry in total; no string in both | `alerts_ops::plan_tags_observed` |
| `cases_create_plan` | `title`: at most 160. `description`: optional, at most 4,096. `tags`: 0 to 10 unique strings, at most 256. `severity`: optional `low`, `medium`, `high`, or `critical` | `cases_ops::plan_create` with no assignees |
| `cases_comment_plan` | `id`: at most 1,024. `message`: at most 4,096 | `cases_ops::plan_comment_observed` |
| `cases_set_status_plan` | `ids`: 1 to 20 unique strings, each at most 1,024. `status`: `open` or `closed` | `cases_ops::plan_status_observed` |
| `rules_create_plan` | `rule`: one JSON object, at most 65,536 when serialized | `rules_ops::plan_create` |

Further rules:

- Two selectors that resolve to the same `rule_id` fail with
  `invalid_argument`. A plan never lists an object twice.
- An object already in the requested state stays in the plan and shows as
  such in the preview, as in the CLI.
- `cases_set_status_plan` refuses with `case_sync_alerts` when any case has
  `settings.syncAlerts` other than a JSON `false`. Kibana would otherwise
  close or reopen that case's attached alerts, which the plan does not list
  (S2, S5). `cases_create_plan` creates with `syncAlerts: false` and the
  consent text says so.
- A rule selector whose read returns a different `rule_id` after
  `selection::to_rule` is refused with `elastic_conflict`.
- Free text reasons are not accepted for alert close. The enum is the
  documented set.
- `rules_create_plan` requires a string `rule_id`, `name`, and `type`. It
  rejects `enabled: true`, any key in `VOLATILE_FIELDS`, a non-empty
  `exceptions_list`, a non-empty `actions`, and a non-empty
  `response_actions`. It sets `enabled: false` in the stored rule. It refuses
  a `rule_id` that already exists.
  - `actions` and `response_actions` are refused because they call connectors
    or act on hosts when the rule fires.
  - `exceptions_list` is refused because its pointers are stack-specific and
    are resolved only by `state push`.
  - Every other field is accepted only because the consent text shows its
    whole value. A rule whose rendering does not fit the consent text is
    refused with `plan_too_large`. There is no separate query limit and no
    field that is accepted without being shown. A larger rule goes through
    `rules import`.
- Text that will be written must display exactly as it is stored. A case
  title, description, comment, or tag that holds a character the consent
  text would replace
  ([section 6.1](06-confirmation-protocol.md#61-consent-text), rule 1) is
  `invalid_argument` before I/O. For a new rule the check runs on the
  rendered detail lines. JSON already escapes C0 controls there, so a query
  with line feeds or tabs is accepted and shown as `\n` and `\t`; a string
  with DEL, a C1 control, U+2028, U+2029, or a bidirectional control is
  refused.
- The caps of 20 objects, 10 tags, and the text sizes are product choices
  sized so the consent text always fits
  ([section 6.1](06-confirmation-protocol.md#61-consent-text)). A value over
  a cap is `invalid_argument` before I/O.
