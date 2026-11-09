[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 4. Command surface

```
elasticctl alerts list   [--status open|acknowledged|closed] [--severity S]
                         [--rule <name|rule_id>] [--tag T] [--assignee USER]
                         [--since DUR|ISO] [--search TEXT] [--limit N]
                         [--format ...] [--fields ...] [--out FILE] [--with-meta]
elasticctl alerts get <alert_id>
elasticctl alerts ack    (<alert_id>... | --query <dsl|@file>)             [guarded]
elasticctl alerts open   (<alert_id>... | --query <dsl|@file>)             [guarded]
elasticctl alerts close  <alert_id>... [--reason R]                         [guarded]
elasticctl alerts close  --query <dsl|@file> [--conflicts abort|proceed]
                         [--reason R]                                       [guarded]
elasticctl alerts tag    <alert_id>... [--add T]... [--remove T]...        [guarded]
elasticctl alerts assign <alert_id>... [--add USER]... [--remove USER]...  [guarded]

# 0.4.1 — the complete cases surface
elasticctl cases list    [--status open|in-progress|closed] [--severity S]
                         [--tag T] [--search TEXT] [--limit N]
elasticctl cases get <case_id>
elasticctl cases create --title T [--description D] [--tag T]... [--severity S]
                        [--assignee USER]...                               [guarded]
elasticctl cases close|open <case_id>...                                   [guarded]
elasticctl cases delete <case_id>...                                       [guarded]
elasticctl cases attach <case_id> --alert <alert_id>...                    [guarded]
elasticctl cases comment <case_id> --message TEXT                          [guarded]
```

`alerts list` filters compose into one boolean query over the measured
`kibana.alert.*` fields: `--status` → `kibana.alert.workflow_status`,
`--severity` → `kibana.alert.severity`, `--rule` → `kibana.alert.rule.rule_id`
after the standard name-or-id resolution, `--tag` →
`kibana.alert.workflow_tags`, `--assignee` →
`kibana.alert.workflow_assignee_ids` after username resolution (section 7),
`--since` → `@timestamp` range. `--search` matches the rule name and reason
text, consistent with the 0.3.1 `--search` semantics. Default sort is
`@timestamp` descending. A peek caps at `--limit` (default 100) and reports
when it truncates; `--out` pages with `sort` plus `search_after` through the
same route. `alerts get` is a `_id`-filtered search returning one document.

