[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 7. State engine

### 7.1 The selected set

The mirror covers the rules in scope, the exception lists they reference
(shared design 5.4), and the value lists those exception lists reference
(D2). A reference is an entry of type `list` in an exception item; nested
entries cannot be lists, so the top-level entries are the complete set.

The **selected set** is the value lists referenced by the exception items of
the selected exception containers, for `pull` on the stack side, and for
`diff` and `push` on the local side (D24). Every value-list step uses that
one set: the reads, the checks of 7.4, the `diff` block, the preview, and
the apply. A scoped run selects fewer containers and so fewer value lists. A
list shared with containers outside the scope is in the set, because `pull`
writes a list's values in full whenever it writes the list, so the local set
is never a partial view (shared design 5.4).

A local pair outside the selected set is reported as `unreferenced` by
`diff` and `push`, and is never written. A list nothing in the mirror
references is not part of a rules-as-code mirror; `value-lists export` and
`value-lists import` cover it.

### 7.2 Layout and file names

```
config/
  rules/<rule_id>.yaml
  exceptions/<list_id>.yaml
  value-lists/<stem>.yaml
  value-lists/<stem>.txt
```

A value list's `<stem>` is its `id` when the `id` is at most 64 bytes, uses
only lowercase ASCII letters, digits, `-`, `_`, and `.`, and does not start
with `.`. Any other `id` gets the stem `<prefix>-<hash>`: `<prefix>` is the
first 48 bytes of the `id` passed through the rule-file sanitizer and
lowercased, and `<hash>` is the first 12 hex digits of the SHA-256 of the
`id`. The container file always carries the true `id`. Stems are compared
without regard to case. Names are planned for every rule, exception list,
and value list before the first file is written, and a collision is refused
naming every colliding pair at once (shared design 5). `export`, `import`,
and `validate` use the same stem rule.

The pull transaction and its journal cover `value-lists/` like the other
roots. Mirror reads fail closed (shared design 6.3): `value-lists/` must be a
real directory, each file a regular file, and every `.yaml` must have its
`.txt` and the reverse. A pair with one half missing refuses `diff` and
`push` before any request.

### 7.3 `pull` and `diff`

`pull` reads each list of the selected set (D19) and writes it in full. If a
referenced list is missing, has an unsupported type, or has a type other than
the entry's `list.type`, `pull` refuses and writes nothing (D23). The message
names each such list and each referencing item, and suggests fixing the
stack or narrowing the pull to rules that do not use it.

`diff` gains a `value_lists` block beside `rules` and `exceptions`. Per list
of the selected set it reports `local_only`, `remote_only`, or `changed`. A
change names the container fields that differ and lists every value to add
and remove (D10). `clean` is true only when all three blocks are clean (D20).

The block also reports, per list, the conditions push would refuse (7.4): a
dangling reference, a type mismatch, and a dash count above 200. Each makes
`clean` false. Duplicates, size warnings, and `unreferenced` pairs are
warnings and leave `clean` alone.

### 7.4 `push`

`push` validates every pair in the selected set by section 5 before any
request. Then it checks every `list` entry of every local exception item in
the selected containers, whether `push` would write the item or not:

- the list must be in the selected set or exist on the stack, or `push`
  refuses with `not_found` naming the list and the item (D4);
- the list's type, from the local file or the stack, must equal the entry's
  `list.type`, or `push` refuses with `conflict` naming both types (D4);
- an `ip_range` list's final stored dash count must pass D12, including a
  list that is only on the stack.

These refusals replace the 0.9 behavior, which printed a preview line for a
missing list and applied anyway (shared design 7.7). Before it writes the
exception items, `push` reads each referenced list's container once more and
stops with `conflict` if its `id` or `type` changed since the preview.

The fixed apply order grows by one step: value-list containers, then values,
then exception containers, exception items, and rules. An exception item is
never written before the list it names exists with its verified values.
`push` never deletes a value-list container; values inside a selected list
are reconciled exactly (D8), with the phases of section 6.

### 7.5 The report

The change-evidence report records value-list mutations with the actions
`create_value_list`, `update_value_list`, `remove_values`, and `add_values`,
in the order they ran. Each entry carries:

- `rule_id`: the list `id`, as exception entries already reuse that field,
  and `name`: the list name;
- `outcome`: `applied`, `failed`, `unknown`, or `not_reached` (section 6.7);
- for the value actions, `values`: every value written, and `verified`: the
  read-back result;
- for `unknown`, `missing` and `extra`: the counts the last read-back saw.

The `-api` apply returns this evidence for every outcome, including when a
list stops the run. The report is written before the command exits, so a
partial apply is never unreported (shared design 5).

### 7.6 Older binaries

A 0.9 binary reads only `rules/` and `exceptions/`. It would push a 0.10
mirror's exceptions without its value lists and print a preview line for each
missing one. 0.9.4 refuses `state diff` and `state push` on a mirror that
holds `value-lists/`, naming 0.10 as the version that can read it (D21). A
binary from 0.9.0 to 0.9.3 cannot be changed; the 0.10 CHANGELOG, the README,
and the state wiki page record that a mirror with `value-lists/` needs 0.9.4
to refuse it and 0.10 to push it.
