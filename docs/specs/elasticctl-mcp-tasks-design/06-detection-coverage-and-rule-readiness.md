[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 6. `detection_coverage` and `rule_readiness`

Shared shapes are defined in [section 4](04-composition-contract.md#4-composition-contract).

### 6.1 `detection_coverage`

Question: "What do our rules cover, and where is coverage installed but
switched off?" Description text, exact:

> Detection coverage across Elastic Security rules, grouped by MITRE ATT&CK
> technique, tactic, index pattern, or integration package. Each row counts
> enabled and disabled rules. Use rules_list with technique or tactic to see
> the rules behind a row. Reads at most 4,000 rules; near that size a call
> can need a longer server --timeout. Read-only.

**Input**

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `group_by` | `"technique"`, `"tactic"`, `"index_pattern"`, `"integration"` | no | Default `"technique"`. |
| `enabled` | boolean | no | Restrict the corpus to enabled or disabled rules. Absent reads both. |
| `source` | `"custom"`, `"customized"`, `"prebuilt"`, `"all"` | no | Default `"all"`. Same vocabulary as `rules_list`. |
| `tag` | string | no | Exact rule tag. Non-whitespace text, at most 1,024 UTF-8 bytes, used unchanged. |
| `limit` | integer 1 to 200 | no | Default 50. Rows returned. |

**Request plan**

One primary read: the bounded corpus read of section 7.1,
`rules::find_window`, with the `enabled`, `source`, and `tag` filters. It
sends `ceil(total / 500)` requests, at most 8, and at most 16 when its one
verification retry runs. A corpus above 4,000 matching rules fails with
`elastic_unsupported` after the first page; narrow it with `enabled`,
`source`, or `tag`. There are no parts.

**Grouping**

A rule counts as enabled when `enabled` is `true`, otherwise as disabled.
Each rule adds at most one to a group, however often the key repeats in it.

| `group_by` | Keys taken from each rule | `name` | `tactics` |
| --- | --- | --- | --- |
| `technique` | Each `threat[].technique[].id` where `threat[].framework` is `MITRE ATT&CK`. Subtechniques count toward their parent technique only. | The smallest `technique[].name` in byte order seen for the id | Sorted distinct `threat[].tactic.id` values under which the id appeared |
| `tactic` | Each `threat[].tactic.id` with the same framework | The smallest `tactic.name` in byte order | absent |
| `index_pattern` | Each string in `index[]`, unchanged. When `index` is absent or empty and `data_view_id` is a string, the single key `data_view:<id>`. | absent | absent |
| `integration` | Each `related_integrations[].package` | absent | absent |

A rule with no key for the chosen grouping adds one to
`summary.unmapped_rules`. A missing or null field yields no key. A present
field of the wrong type fails the call with kind `http`.

**Edge cases**

- A `technique[].id` is used as is. An id that already has the subtechnique
  shape, such as `T1059.001`, keys its own row.
- A `null` or wrong-typed element inside the `index`, `threat`,
  `threat[].technique`, or `related_integrations` array fails the call with
  kind `http`. An absent or `null` field yields no key.
- Only the fields the chosen grouping reads are type-checked. `tactic` never
  reads `technique`, and `index_pattern` and `integration` never read
  `threat`.
- `data_view_id` is read only when `index` gives no pattern: it is absent,
  `null`, or empty. Beside a non-empty `index`, its type is not checked.
- Technique rows always carry `tactics`, possibly empty. Rows of the other
  groupings never carry it.
- `name` is omitted when no name was seen for the key.
- An explicit `null` for `group_by` or `source` is `invalid_argument`. Omit
  the field to get its default.

Rows sort by `enabled_rules` descending, then `disabled_rules` descending,
then `key` ascending in byte order.

**Output `data`**

| Field | Type |
| --- | --- |
| `group_by` | string; the effective grouping |
| `summary.rules` | integer; rules read |
| `summary.enabled_rules`, `summary.disabled_rules` | integers |
| `summary.unmapped_rules` | integer |
| `summary.groups` | integer; groups before the row limit |
| `rows[]` | `{key, name?, tactics?, enabled_rules, disabled_rules}` |

`page` is `{limit, returned, total, has_more, truncated}` with `total` equal
to `summary.groups`. Rows are trimmed between complete rows to fit the byte
caps, as in every 0.7 list. `summary` always describes the whole corpus read.

Measured on both trial stacks: 2,263 rules, 2,189 with a threat mapping, 170
distinct techniques, 15 tactics, at most 11 index patterns and 7 related
integrations on one rule, and 426 rules with no index (320 ES|QL, 106 machine
learning). A full technique matrix fits in one call at `limit: 200`.

There is no gap verdict. A row with `enabled_rules: 0` and `disabled_rules`
above zero is coverage that is installed and off; the model or the user draws
that conclusion.

### 6.2 `rule_readiness`

Question: "Can this rule see data, and are its integrations in place?"
Description text, exact:

> Data readiness of one Elastic Security rule: whether each index pattern
> resolves to indices, aliases, or data streams (counts only), whether its
> data view exists, and whether its related Fleet integration packages are
> installed and used by an integration policy. Read-only.

**Input**

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `selector` | string | yes | Exact `rule_id` or display name, the `rules_get` rule. Non-whitespace text, at most 1,024 UTF-8 bytes, used unchanged. |

**Request plan**

| Step | Read | API | Requests | Role |
| --- | --- | --- | --- | --- |
| 1 | Rule by selector | `compose::snapshot_by_selector` | 1 to 3 | primary |
| 2 | Data views in the space | `data_views::list` | 0 or 1 | part `data_views` |
| 3 | Each of the first 16 patterns | `GET /_resolve/index/{pattern}` on Elasticsearch | 0 to 16 | part `patterns` |
| 4 | Integration policies, first page only | `fleet::integration_policy_ops::list_first_page` | 0 or 1 | part `integrations` |
| 5 | Each of the first 8 distinct packages | `fleet::agent_policies::package_status` | 0 to 8 | rows of `integrations` |

Maximum 29 requests: 3, 1, 16, 1, and 8. No step pages further.

`index_source` is decided from the rule alone:

| Value | Condition |
| --- | --- |
| `index` | `index` is a non-empty array of strings. |
| `data_view` | Otherwise, `data_view_id` is a string. |
| `none` | Otherwise. ES\|QL and machine learning rules land here. |

Part rules:

- `data_views` is `skipped` with `not_applicable` when `index_source` is
  `none`. Otherwise step 2 runs. For `data_view` the rule's data view is
  looked up by id in the list; its `title` split on `,` gives the patterns.
- `patterns` is `skipped` with `not_applicable` when `index_source` is
  `none`, with `not_configured` when the profile has no `es_url`, and with
  `dependency_unavailable` when `index_source` is `data_view` and the data
  view was not found or `data_views` is not `ok`.
- Patterns are taken in order, without deduplication, up to 16. A pattern
  that starts with `-` is an `exclusion` row and sends no request. A pattern
  that is empty, whitespace-only, above 1,024 UTF-8 bytes, exactly `.` or
  `..`, or holds a control character is `unresolved` with no `error` and
  sends no request. Every other pattern is percent-encoded as one path
  segment.
- A 200 response must hold arrays `indices`, `aliases`, and `data_streams`;
  only their lengths are kept. The row is `matches` when the sum is above
  zero, otherwise `no_match`. A `not_found` error is `no_match` with zero
  counts. Any other non-fatal error is `unresolved` with `error`.
- `integrations` is `ok` with no rows and no request when the rule has no
  `related_integrations`. Otherwise step 4 runs first. It reads one page of
  at most 1,000 integration policies. When the server total is above the
  rows returned, the part is `unavailable` with `elastic_unsupported` and no
  package is read: a count from an incomplete list would be wrong. A failed
  read also makes the part `unavailable`.
- Entries are deduplicated by `package` in order, up to eight. A package
  name must be 1 to 128 characters from `a-z`, `0-9`, `_`, and `-`. A name
  outside that grammar makes its row `unavailable` with `elastic_unsupported`
  and sends no request. Each other package gets one status read; a failed
  read makes that row `unavailable`. `policies` counts the listed
  integration policies whose `package.name` equals the package, and is exact
  because the list is complete.

**Edge cases**

- An `index` array that holds a non-string counts as no index list;
  `index_source` is then decided by `data_view_id`.
- A data view `title` splits on `,` with no trimming. Each component,
  spaces included, is one pattern, and `data_view_ids` matches a pattern
  against whole components the same way.
- `data_view_ids` appears on every pattern row, `exclusion` and
  `unresolved` rows included, whenever the data view list was read.
- A `related_integrations` value other than an array or `null`, an entry
  without a string `package`, or a `version` that is neither a string nor
  `null` makes `integrations` `unavailable` with kind `http`. No Fleet
  request is sent.
- Packages are deduplicated by name, keeping the first eight distinct names
  in rule order. A row's `version` comes from the first entry with that
  name. `integrations.value.total` counts distinct names.
- When several skip reasons apply to `patterns`, `not_applicable` wins, then
  `not_configured`, then `dependency_unavailable`.

**Output `data`**

| Field | Type |
| --- | --- |
| `rule` | `{rule_id, name?, type?, enabled?}` |
| `index_source` | `"index"`, `"data_view"`, or `"none"` |
| `data_views` | part; `value` is `{count, rule_data_view?}` |
| `data_views.value.count` | integer; data views in the space |
| `data_views.value.rule_data_view` | `{id, found, title?, name?}`; present only when `index_source` is `data_view` |
| `patterns` | part; `value` is `{total, truncated, rows[]}` |
| `patterns.value.rows[]` | `{pattern, state, indices?, aliases?, data_streams?, error?, data_view_ids?}` |
| `patterns.value.rows[].state` | `"matches"`, `"no_match"`, `"exclusion"`, or `"unresolved"` |
| `patterns.value.rows[].data_view_ids` | sorted ids of data views whose `title`, split on `,`, holds the pattern exactly; present only when `data_views` is `ok` |
| `integrations` | part; `value` is `{total, truncated, rows[]}` |
| `integrations.value.rows[]` | `{package, version?, status, error?, install_status?, installed_version?, policies?}` |
| `partial` | boolean |
| `findings` | array of codes |

`total` counts entries before the cap and `truncated` is `true` when the cap
removed any. `indices`, `aliases`, and `data_streams` are integers present
for `matches` and `no_match`. `version` is the rule's required version
string. `install_status`, `installed_version`, and `policies` are present
only when the row `status` is `ok`. `page` is `null`.

No index, alias, or data stream name is returned. The only index text in the
result is the rule's own pattern.

**Findings**, in this order:

| Code | Condition |
| --- | --- |
| `rule_disabled` | `enabled` is `false`. |
| `no_index_source` | `index_source` is `none`. |
| `data_view_missing` | `index_source` is `data_view` and `rule_data_view.found` is `false`. |
| `no_pattern_matches` | `patterns` is `ok` and not truncated, at least one row is not an exclusion, and every such row is `no_match`. |
| `pattern_unresolved` | A row is `unresolved`. |
| `integration_not_installed` | A row is `ok` and `install_status` is not `installed`. |
| `integration_without_policy` | A row is `ok`, `install_status` is `installed`, and `policies` is zero. |
| `patterns_truncated` | `patterns.value.truncated` is `true`. |
| `integrations_truncated` | `integrations.value.truncated` is `true`. |

A single `no_match` row is not a finding. Prebuilt rules list patterns for
many shippers, and most of them match nothing on any one deployment.

`no_pattern_matches` is a claim about every pattern, so it needs every
pattern to have been resolved. One `unresolved` row, or a truncated list,
withholds it. A rule whose patterns all return 403 therefore reports
`pattern_unresolved` and `partial: true`, never `no_pattern_matches`.

A match means names exist, not that documents arrive. The tool does not
search data; the opt-in query tools do.
