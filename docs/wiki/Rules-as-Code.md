# Rules as Code

`state` keeps detection rules, the exception lists they use, and the value
lists those exceptions use in a directory you can commit to Git: pull the live
rules, review drift, and push approved changes.

```bash
elkctl state pull --dir state   # writes rules/, exceptions/, and value-lists/
# edit rules, or add new ones
elkctl state diff --dir state   # field-level drift, no changes made
elkctl state push --dir state   # preview; add --yes to apply
```

## Pull

`pull` reads the rules, normalizes them, fetches the exception lists they
reference, and writes one file per rule under `rules/` and per list under
`exceptions/`. `--format-file` selects `ndjson` (the default) or `yaml`. It
also writes the value lists those exception lists use under `value-lists/`;
see [Value lists](#value-lists).

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

- It creates and updates rules. **It never deletes a remote rule, exception
  list, or value list.** A rule missing from the directory is not a delete
  instruction; use `rules delete`, `exceptions delete`, or
  `value-lists delete`.
- Items inside a mirrored exception list reconcile exactly, including deletes,
  because a list's item set is written in full.
- `--report FILE` writes a change-evidence report: each change's before and
  after values and whether it was applied. The report path is checked before
  the first remote change, so an unwritable path cannot leave an unreported
  change.

```bash
elkctl state push --dir state --report change-1234.json --yes
```

## Value lists

An exception entry of type `list` names a [value list](Value-Lists.md). The
directory holds every value list that a mirrored exception item references,
as a pair under `value-lists/`: `<stem>.yaml` for the container and
`<stem>.txt` for the values. [Value Lists](Value-Lists.md#files) describes
both files. A value list nothing in the directory references is not mirrored;
use `value-lists export` and `value-lists import` for it.

- **Pull** writes each referenced list in full. If a referenced list is
  missing from the stack, has a type `elkctl` does not manage, or has a type
  other than the entry's, `pull` refuses and writes nothing. Fix the stack or
  narrow the pull to rules that do not use the list.
- **Diff** adds a `value_lists` block when the directory holds
  `value-lists/`. Each list is `local_only`, `remote_only`, `changed`, or
  `unchanged`; a change names the container fields and lists every value to
  add and to remove. `clean` is true only when the rules, exceptions, and
  value lists are all clean. A condition `push` would refuse makes `clean`
  false; duplicates, size warnings, and a pair no exception references
  (`unreferenced`) are warnings only.
- **Push** writes value lists first, then exception lists, their items, and
  rules, so an exception item is never written before the list it names holds
  its checked values. Values in a mirrored list are reconciled exactly,
  including removals, with the rules in
  [How values change](Value-Lists.md#how-values-change). An `unreferenced`
  pair is reported and never written.

`push` refuses before any write when:

- an exception entry names a value list that is neither in the directory nor
  on the stack (`not_found`), or whose type differs from the entry's
  (`conflict`). With `is not in list`, a missing list would suppress every
  event that has the field;
- a write would break a [safety rule](Value-Lists.md#safety-rules);
- one run would change a list's values and also what uses it: an exception
  item that references the list, another list such an item references, or
  which rules a container holding such an item is attached to. Push the two
  changes in separate runs, each previewed. A new list may be created in
  the same run as the first exceptions that reference it.

A list that ends `unknown` stops the push; see
[When the outcome is unknown](Value-Lists.md#when-the-outcome-is-unknown).
With `--report`, the report records each value-list write and the summary
counts lists created, updated, unknown, and not reached, and values added and
removed.

### Older versions

elasticctl 0.9 cannot read `value-lists/`. 0.9.4 refuses `state pull`,
`state diff`, and `state push` on a directory that holds it. 0.9.0 to 0.9.3
do not: they would push the exceptions without the value lists, or pull and
leave the value lists stale. Use 0.10 or later with such a directory.

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
`id`. An exception list is matched by `list_id` plus its namespace, and a
value list by its `id` within the space. This is what makes a directory
portable: pull from one stack, push to another, and the references resolve
against the target.

## Promote between stacks

```bash
elkctl --profile dev  state pull --dir state --tag prod-ready
git diff                                   # review
elkctl --profile prod state diff --dir state --tag prod-ready
elkctl --profile prod state push --dir state --tag prod-ready --report r.json --yes
```

The design gives the full rules:
[state engine](https://github.com/dannyota/elasticctl/blob/master/docs/specs/elasticctl-design/05-state-engine.md).
