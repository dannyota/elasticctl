[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 5. `alert_context` and `rule_health`

Shared shapes (part, rule context, exception coverage, alert activity,
`since`) are defined in [section 4](04-composition-contract.md#4-composition-contract).
Field rules follow 0.7: always-written fields are required, fields omitted
when absent are optional, and a present field of the wrong type fails
projection with kind `http`.

### 5.1 `alert_context`

Question: "What is this alert, what fired it, and what already exists around
it?" Description text, exact:

> Triage context for one Elastic Security alert: the alert, the rule that
> fired it with its last execution, the rule's exception lists, cases that
> contain the alert, and the rule's alert volume in a time window. Read-only.

**Input**

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `alert_id` | string | yes | Exact alert document id. Non-whitespace text, at most 1,024 UTF-8 bytes, not exactly `.` or `..`, used unchanged. |
| `since` | string | no | Default `"24h"`. Grammar in section 4.2. |

**Request plan**

| Step | Read | API | Requests | Role |
| --- | --- | --- | --- | --- |
| 1 | Alert by id | `alerts_ops::get_one` | 1 | primary |
| 2 | Rule by the alert's `kibana.alert.rule.rule_id` | `compose::snapshot_by_id` | 1 | part `rule` |
| 3 | Exception coverage of that rule | `compose::exception_coverage` | 0 to 10 | part `exceptions` |
| 4 | Cases that contain the alert | `GET /api/cases/alerts/{alert_id}`, then `cases::get` for the first five | 1 to 6 | part `cases` |
| 5 | Alert activity for the rule, `size: 0` | `compose::alert_activity` | 1 | part `activity` |

Maximum 19 requests. The alert id is percent-encoded as one path segment in
step 4.

Part rules:

- `rule` is `skipped` with `not_applicable` when the alert has no string
  `kibana.alert.rule.rule_id`, read flat or nested as `alerts_get` does.
- `exceptions` and `activity` are `skipped` with `dependency_unavailable`
  when `rule` is not `ok`. `activity` needs only the `rule_id`, but a missing
  rule makes its window count misleading, so both follow the same rule.
- `cases` does not depend on `rule`.
- The cases route must return an array of objects that each hold a string
  `id` that is not empty and not exactly `.` or `..`. `title` is an optional
  string. Any other shape is an `http` error for the part. Rows keep the route's order. Each of the first five rows gets one
  `cases::get`; a failed get makes that row `unavailable` and keeps its `id`
  and `title`.

**Output `data`**

| Field | Type |
| --- | --- |
| `alert` | object; exactly the `alerts_get` projection: `id`, optional `index`, `source` |
| `rule` | part; `value` is the rule context |
| `exceptions` | part; `value` is exception coverage |
| `cases` | part; `value` is `{total, truncated, cases[]}` |
| `cases.value.total` | integer; rows the route returned |
| `cases.value.truncated` | boolean; `true` when `total` is above five |
| `cases.value.cases[]` | `{id, title?, status, error?, case?}`; `case` is the `cases_get` projection, present only when `status` is `ok` |
| `activity` | part; `value` is alert activity without `recent` |
| `partial` | boolean |
| `findings` | array of codes |

`page` is `null`.

**Findings**, in this order:

| Code | Condition |
| --- | --- |
| `alert_not_open` | The alert has `kibana.alert.workflow_status` and it is not `open`. |
| `rule_missing` | `rule` is `unavailable` with kind `not_found`. |
| `rule_disabled` | `rule` is `ok` and `enabled` is `false`. |
| `rule_last_execution_failed` | `rule` is `ok` and `execution.status` is `failed`. |
| `exception_list_missing` | A list row is `unavailable` with kind `not_found`. |
| `has_related_case` | `cases` is `ok` and `total` is above zero. |

**Example**, shortened:

```json
{
  "target": {"profile": "analyst", "host": "kibana.example.test", "space": "default"},
  "data": {
    "alert": {"id": "a1", "source": {"kibana.alert.rule.rule_id": "r1", "kibana.alert.workflow_status": "open"}},
    "rule": {"status": "ok", "value": {"rule_id": "r1", "name": "Example", "enabled": true,
      "execution": {"status": "succeeded", "date": "2026-11-10T03:00:00.000Z", "message_truncated": false, "metrics": {}}}},
    "exceptions": {"status": "ok", "value": {"referenced": 1, "truncated": false, "lists": [
      {"list_id": "l1", "namespace_type": "single", "type": "detection", "status": "unavailable",
       "error": {"kind": "not_found", "http_status": 404, "code": "elastic_not_found", "message": "The selected resource was not found."}}]}},
    "cases": {"status": "unavailable",
      "error": {"kind": "permission", "http_status": 403, "code": "elastic_permission", "message": "The selected credential cannot read this data."}},
    "activity": {"status": "ok", "value": {"window": "24h", "total": 12, "by_status": {"open": 10, "acknowledged": 1, "closed": 1, "other": 0}}},
    "partial": true,
    "findings": ["exception_list_missing"]
  },
  "page": null
}
```

### 5.2 `rule_health`

Question: "Is this rule running, is it producing alerts, and what narrows
it?" Description text, exact:

> Health of one Elastic Security rule: its definition, last execution status
> and message, alert counts by workflow status with the five newest alerts in
> a time window, and its exception lists with item counts. Read-only.

**Input**

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `selector` | string | yes | Exact `rule_id` or display name, the `rules_get` rule. Non-whitespace text, at most 1,024 UTF-8 bytes, used unchanged. |
| `since` | string | no | Default `"24h"`. Grammar in section 4.2. |

**Request plan**

| Step | Read | API | Requests | Role |
| --- | --- | --- | --- | --- |
| 1 | Rule by selector | `compose::snapshot_by_selector` | 1 to 3 | primary |
| 2 | Alert activity, `size: 5` | `compose::alert_activity` | 1 | part `alerts` |
| 3 | Exception coverage | `compose::exception_coverage` | 0 to 10 | part `exceptions` |

Maximum 14 requests. Selector ambiguity stays a `conflict` failure of the
call, as in `rules_get`. Neither part depends on the other.

**Output `data`**

| Field | Type |
| --- | --- |
| `rule` | object; the rule context, with `execution` required and nullable |
| `alerts` | part; `value` is alert activity with `recent` |
| `exceptions` | part; `value` is exception coverage |
| `partial` | boolean |
| `findings` | array of codes |

`page` is `null`.

**Findings**, in this order:

| Code | Condition |
| --- | --- |
| `rule_disabled` | `enabled` is `false`. |
| `never_executed` | `enabled` is `true` and `execution` is `null`. |
| `last_execution_failed` | `execution.status` is `failed`. |
| `last_execution_partial_failure` | `execution.status` is `partial failure`. |
| `execution_gap` | `execution.metrics.execution_gap_duration_s` is above zero. |
| `no_alerts_in_window` | `alerts` is `ok` and `total` is zero. |
| `exception_list_missing` | A list row is `unavailable` with kind `not_found`. |

Status strings are compared exactly. Both trial stacks returned
`partial failure` for enabled prebuilt rules whose index patterns matched
nothing, with a message of 185 to 190 bytes. An unknown status string emits
no finding and is still returned in `execution.status`.

The execution message is remote text. It often names index patterns and
privileges, which is why it is returned. It is data, never instructions, and
it is cut at 2,048 bytes so one rule cannot crowd out the rest of the answer.

Internal routes are not used. Execution history, gap ranges, and the rule
monitoring dashboards behind `/internal/` stay out of scope, as in 0.7.
