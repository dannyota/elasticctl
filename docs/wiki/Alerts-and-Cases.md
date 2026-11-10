# Alerts and Cases

Triage detection alerts and track investigations as cases.

## Alerts

```bash
elkctl alerts list --status open --severity critical --since 24h
elkctl alerts list --rule 'Suspicious PowerShell' --search encoded
elkctl alerts get <alert_id>
```

| Flag | Filters by |
| --- | --- |
| `--status open\|acknowledged\|closed` | Workflow status |
| `--severity <SEVERITY>` | Severity |
| `--rule <NAME-or-rule_id>` | Rule |
| `--tag <TAG>` | Workflow tag |
| `--assignee <USER>` | Username, or `uid:<profile_uid>` |
| `--since <DURATION-or-ISO>` | Age: `90m`, `24h`, `7d`, or a timestamp |
| `--search <TEXT>` | Substring of the rule name and reason |

`list` shows at most 100 alerts; `--out` exports all of them, and `--limit`
sets a cap. `--with-meta` merges `_id` into each alert.

Change the workflow status by id, or by a Query DSL selection:

```bash
elkctl alerts ack <alert_id>... --yes
elkctl alerts close <alert_id>... --reason false_positive --yes
elkctl alerts open <alert_id>... --yes
elkctl alerts close --query @stale.json --yes
```

`--query` takes inline JSON or `@file`. On a version conflict a query-selected
close stops; `--conflicts proceed` continues past it.

Tag and assign:

```bash
elkctl alerts tag <alert_id>... --add triaged --remove noise --yes
elkctl alerts assign <alert_id>... --add alice --yes
elkctl alerts assign <alert_id>... --remove uid:<profile_uid> --yes
```

An assignee must have logged in to Kibana at least once, so that a user
profile exists.

## Cases

```bash
elkctl cases list --status open --severity high
elkctl cases get <case_id>
elkctl cases create --title "Suspicious PowerShell activity" --severity high --yes
elkctl cases attach <case_id> --alert <alert_id> --yes
elkctl cases comment <case_id> --message "Confirmed benign, closing." --yes
elkctl cases close <case_id> --yes
elkctl cases open <case_id> --yes
elkctl cases delete <case_id> --yes
```

`list` filters by `--status open|in-progress|closed`, `--severity`, `--tag`,
and `--search` over the title and description. `create` accepts
`--description`, repeatable `--tag` and `--assignee`, and `--severity`.
`attach` takes a repeatable `--alert`.

`cases delete` is permanent. Alerts cannot be deleted through the public API;
close them instead.

Every change previews without `--yes`.
