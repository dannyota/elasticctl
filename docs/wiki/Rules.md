# Rules

Inspect and change individual detection rules. To manage many rules as files,
see [Rules as Code](Rules-as-Code.md).

## List and get

```bash
elkctl rules list
elkctl rules list --source custom --enabled --severity high
elkctl rules list --search powershell
elkctl rules get <rule_id-or-name>
```

| Flag | Filters by |
| --- | --- |
| `--enabled`, `--disabled` | State |
| `--type <TYPE>` | Rule type |
| `--severity <SEVERITY>` | Severity |
| `--tag <TAG>` | Exact tag |
| `--search <TEXT>` | Name substring, case-insensitive, or exact tag |
| `--filter <KQL>` | Raw KQL, combined with the other filters |
| `--source custom\|customized\|prebuilt\|all` | Rule source; defaults to `all` |

`--search` and `--filter` are mutually exclusive. `--search` does not look at a
rule's description or query; the public API cannot filter on them.

## Validate

```bash
elkctl rules validate --path rule.yaml
```

Checks a rule file locally and contacts no server.

## Enable, disable, delete

```bash
elkctl rules enable <rule_id-or-name>... --yes
elkctl rules disable <rule_id-or-name>... --yes
elkctl rules delete <rule_id-or-name>... --yes
```

Each previews without `--yes`. Enabling a rule needs an Elasticsearch API key
created in Kibana; see
[which key to use](Configuration.md#which-api-key-to-use).

## Export and import

```bash
elkctl rules export --tag my-corpus --out rules.ndjson
elkctl rules export my-rule-id --format-file yaml > rule.yaml
elkctl rules import --path rules.ndjson --yes
```

`export` takes rule ids or names and `--tag`; given both, it exports the
union, and given neither, every rule in the `--source` scope. A selector or tag
that matches nothing fails with `not_found`. It is never widened to "export
everything".

`import` fails on a rule that already exists unless you choose:

| Flag | Existing rule |
| --- | --- |
| `--overwrite` | Replaced |
| `--skip-existing` | Left alone and reported as skipped |

## Preview

```bash
elkctl rules preview my-rule-id --sample 3
elkctl rules preview rule.yaml --invocations 2
```

Runs a rule against existing data without writing alerts and reports how many
events matched. `--sample N` also returns up to N matched documents. The
source is a file, a `rule_id`, or a rule name.

## Prebuilt rules

```bash
elkctl rules prebuilt status
elkctl rules prebuilt install --yes
```

`status` reports installed, missing, outdated, and customized prebuilt rules.
`install` installs every missing rule and updates every outdated one in one
call; the server route takes no selection, so there is no per-rule upgrade.
