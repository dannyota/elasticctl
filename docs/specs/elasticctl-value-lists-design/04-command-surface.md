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

- **`list`** reads containers through `_find` with `cursor` (D19) and prints
  `id`, `type`, `name`, and `description`, ordered by `id`. `--type` filters on
  one of the four types; `--search` matches `id` and `name` as substrings, as
  shared design 4.7 does for other objects. A container of an unsupported
  type is listed with its type and marked `unsupported`, so the operator sees
  it rather than a silent gap.
- **`get`** prints one container, its distinct value count, its stored
  value count, and the warnings of section 5. `--values` adds the set. The
  values come from `_export`.
- **`validate`** checks a container file and its sibling values file, or a
  values file and its sibling container file, by sections 3 and 5, and sends
  nothing.
- **`export`** writes the container and values files of each `id` in the
  mirror's form and with its file stem (section 7.2), into `--dir` (default:
  the current directory). It refuses to overwrite an existing file. Without
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
so a reviewer or a script sees the complete change. A preview reads the
list's current state; the apply reads it again and stops with `conflict` if
it changed (section 6.1).

### 4.2 Output

Table output is the default and `--json` is explicit, as for every command.
Values are data, never rendered through a format that could reshape them:
`export` writes the files byte for byte in the form of section 3.3.
