# Exceptions

Exception lists hold the conditions under which a rule does not alert.
`elkctl` manages a list and its items together.

```bash
elkctl exceptions list --search trusted
elkctl exceptions get <list_id>
elkctl exceptions validate --path exceptions.ndjson
elkctl exceptions export <list_id> --out exceptions.ndjson
elkctl exceptions import --path exceptions.ndjson --yes
elkctl exceptions delete <list_id> --yes
```

## Identity and namespaces

A list is identified by its `list_id` plus its namespace, `single` (one space)
or `agnostic` (all spaces). The same `list_id` can exist in both.

- `list` reads both namespaces and merges them. Narrow with `--namespace`,
  `--type`, `--tag`, or `--search`.
- `get`, `export`, and `delete` take `--namespace single|agnostic`. Without it,
  a `list_id` that exists in both namespaces fails with `conflict` instead of
  picking one.

## Authoring

There is no `create` verb. Write a file and `import` it, or keep lists in a
[state directory](Rules-as-Code.md) and `state push`. Attaching a list to a
rule is a change to the rule, so it is also made through the rule file.

`import` fails on a list that already exists unless you pass `--overwrite` or
`--skip-existing`.

`export` writes NDJSON by default; `--format-file yaml` is available. Without
selectors it exports every list, and `--tag` adds every list carrying that tag.

## In a state directory

`state pull` writes the lists that the pulled rules reference under
`exceptions/`. `state push` creates and updates lists and reconciles the items
of a mirrored list exactly, including deleting items removed from the file. It
never deletes a list.

Exception lists need Kibana 9.5.1 or newer; see [Limitations](Limitations.md).
