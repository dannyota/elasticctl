# Rules as Code

`state` keeps detection rules in a directory you can commit to Git: pull the
live rules, review drift, and push approved changes.

```bash
elkctl state pull --dir state   # writes state/rules/ and state/exceptions/
# edit rules, or add new ones
elkctl state diff --dir state   # field-level drift, no changes made
elkctl state push --dir state   # preview; add --yes to apply
```

## Pull

`pull` reads the rules, normalizes them, fetches the exception lists they
reference, and writes one file per rule under `rules/` and per list under
`exceptions/`. `--format-file` selects `ndjson` (the default) or `yaml`.

The write is a local transaction: an interrupted pull leaves the previous tree
in place. Two `rule_id` values that would map to one filename are refused
before anything is written, naming every colliding pair.

## Diff

`diff` compares the directory with the stack and prints field-level drift.
Server-applied defaults and volatile fields are normalized away on both sides,
so an unchanged rule shows no drift. It also reports a rule whose stored
exception-list pointer does not match the live list; `push` repairs it.

## Push

`push` computes the same diff and applies it through the dry-run guard.

- It creates and updates rules. **It never deletes a remote rule or an
  exception list.** A rule missing from the directory is not a delete
  instruction; use `rules delete` or `exceptions delete`.
- Items inside a mirrored exception list reconcile exactly, including deletes,
  because a list's item set is written in full.
- `--report FILE` writes a change-evidence report: each change's before and
  after values and whether it was applied. The report path is checked before
  the first remote change, so an unwritable path cannot leave an unreported
  change.

```bash
elkctl state push --dir state --report change-1234.json --yes
```

## Scope

Without selectors, a state command works on the rules matching `--source`:

| `--source` | Rules |
| --- | --- |
| `custom` (default) | Rules you authored |
| `customized` | Prebuilt rules edited on the stack |
| `prebuilt` | Elastic's prebuilt rules |
| `all` | The whole corpus |

Positional selectors, `--tag`, and `--search` replace that scope: they resolve
rule ids first, then read those rules.

```bash
elkctl state diff --dir state my-rule-id      # one rule
elkctl state push --dir state --tag prod      # one tag
```

`diff` and `push` resolve a selector against the directory first, so a rule you
have only written locally is selectable by name before it exists on the stack.
A scoped run reports how many rules it selected next to the local total, so it
cannot be mistaken for a clean tree. A local file outside the active scope is
reported as out of scope.

## Identity

A rule is matched by `rule_id`, never by its name or the server's internal
`id`. An exception list is matched by `list_id` plus its namespace. This is
what makes a directory portable: pull from one stack, push to another, and the
references resolve against the target.

## Promote between stacks

```bash
elkctl --profile dev  state pull --dir state --tag prod-ready
git diff                                   # review
elkctl --profile prod state diff --dir state --tag prod-ready
elkctl --profile prod state push --dir state --tag prod-ready --report r.json --yes
```

The design gives the full rules:
[state engine](https://github.com/dannyota/elasticctl/blob/master/docs/specs/elasticctl-design/05-state-engine.md).
