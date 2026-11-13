[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 4. Command surface

```
elasticctl value-lists list [--type T] [--search TEXT]
elasticctl value-lists get <id> [--values]
elasticctl value-lists validate --path FILE         Local check, no server contact
elasticctl value-lists export <id>... [--dir DIR]
elasticctl value-lists import --path FILE [--overwrite]               [guarded]
elasticctl value-lists delete <id>...                                  [guarded]
elasticctl value-lists init                                            [guarded]
```

Every command acts on the profile's space and takes the global flags of
shared design 4.2.

- **`list`** reads containers through `_find` with `cursor` (D19), starting
  with `GET /api/lists/_find?page=1&per_page=1000` and sending no `filter`. It
  prints `id`, `type`, `name`, and `description`, ordered by `id`. After the
  read, `--type` keeps one of the four types and `--search` matches `id` and
  `name` as substrings, ignoring case for both, as shared design 4.7 does for
  rule names. A
  container of an unsupported type is listed with its type and marked
  `unsupported`, so the operator sees it rather than a silent gap.
- **`get`** prints one container, its distinct value count, its stored
  value count, and the warnings of section 5. `--values` adds the set. The
  values come from `_export`.
- **`validate`** checks a container file and its sibling values file, or a
  values file and its sibling container file, by sections 3 and 5, and sends
  nothing.
- **`export`** writes the container and values files of each `id` in the
  mirror's form and with its file stem (section 7.2), into `--dir` (default:
  the current directory). It refuses to overwrite an existing file: it checks
  every destination of every `id` first and, if any exists, writes nothing and
  names each existing file. Without
  `--dir` and with one `id`, `--json` prints the container and its values as
  one object instead.
- **`import`** reads `FILE` (the `.yaml` or the `.txt` of a pair) and creates
  the list with its values. An existing `id` is refused with `conflict`
  unless `--overwrite` is given; then the container is updated and the
  values are reconciled exactly (section 6). There is no `--skip-existing`: a
  single list either exists or not, so skipping is a no-op the caller can
  see from `get`.
- **`delete`** deletes each list and its values with no reference flags
  (section 6.5).
- **`init`** bootstraps the space's list data streams (section 6.6).

There is no `create` or `add` verb. Authoring is a file, as for exceptions
(shared design 4): a flag surface for thousands of values would be worse than
a file, and `import` and `state push` already create.

### 4.1 The guard

`import`, `delete`, and `init` preview before they apply and need `--yes`,
with the banner of shared design 6.1. A value preview shows, per list, the
container action, every value to add and every value to remove in byte order
(D10), the phase order and why (D22), and the warnings of section 5. Under
`--json` the preview is one object with the same arrays, not rendered text,
so a reviewer or a script sees the complete change. It goes to stderr, as the
text preview does (shared design 6.1), and its keys are, in this order:
`dry_run`, `profile`, `host`, `space`, `command`, and `lists`. For `import`,
each entry of `lists` holds `id`, `type`, `container_action` (`create`,
`update`, or `none`), `adds`, `removes`, `phase_order` (`adds_first`,
`removes_first`, or `none`), `phase_reason`, and `warnings`. For `delete`, each
entry holds `id` and `type`. For `init`, `lists` is empty and the object adds
`flow` and `already_bootstrapped`. A preview reads the
list's current state; the apply reads it again and stops with `conflict` if
it changed (section 6.1).

### 4.2 Output

Table output is the default and `--json` is explicit, as for every command.
`--format`, `--fields`, and `--out` shape the report only, never an exported
file. Under `--json`, `list` prints an array of `id`, `type`, `name`,
`description`, and `supported`; `get` prints `id`, `type`, `name`,
`description`, `meta` when present, `distinct_values`, `stored_values`,
`warnings`, and, with `--values`, `values`; `export` with `--dir` reports the
files it wrote; and single-`id` `export --json` prints `{"container": ...,
"values": [...]}`, the values in the order of the values file (section 3.3).
Values are data, never rendered through a format that could reshape them:
`export` writes the files byte for byte in the form of section 3.3.
