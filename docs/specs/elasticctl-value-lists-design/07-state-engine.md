[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 7. State engine

### 7.1 The closure

The mirror covers the rules in scope, the exception lists they reference
(shared design 5.4), and exactly the value lists those exception lists
reference (D2). A reference is an entry of type `list` in an exception item;
nested entries cannot be lists, so the top-level entries are the complete
set. A value list nothing in the mirror references is not part of a
rules-as-code mirror; `value-lists export` covers it.

`pull` reads each referenced list's container and values (D19) and writes
them in full. A referenced list that does not exist, that has an unsupported
type, or whose type differs from the entry's `list.type` is written as no
file and reported as a warning naming the list and the referencing item. The
pull still succeeds: it records the stack as it is, and `push` refuses that
mirror until it is fixed (section 7.4).

### 7.2 Layout

```
config/
  rules/<rule_id>.yaml
  exceptions/<list_id>.yaml
  value-lists/<id>.yaml
  value-lists/<id>.txt
```

A value-list file name is the list `id` passed through the rule-file
sanitizer of shared design 5. Names are planned for every rule, exception
list, and value list before the first file is written, and a collision is
refused naming every colliding pair at once, as shared design 5 already does.
The pull transaction and its journal cover `value-lists/` like the other
roots.

Mirror reads fail closed (shared design 6.3): `value-lists/` must be a real
directory, each file a regular file, and every `.yaml` must have its `.txt`
and the reverse. A pair with one half missing refuses `push` before any
request.

### 7.3 `diff`

`diff` gains a `value_lists` block beside `rules` and `exceptions`, and
`clean` is true only when all three are (D20). Per list it reports one of
`local_only`, `remote_only`, or `changed`. A change names the container
fields that differ and counts the values to add and remove, with the first
twenty of each in byte order; `--json` lists them all. The warnings of
sections 3.4 and 5 (dash values, duplicates, size) appear per list and do not
make a tree unclean.

The remote side is every list the remote in-scope exception items reference
plus every list in the local mirror. A list present locally and referenced by
nothing is still managed: it is in the mirror, so `push` writes it.

### 7.4 `push`

`push` validates every value-list pair by section 5 before any request. Then
it checks every `list` entry of every local exception item that `push` would
write:

- the list must be in `value-lists/` or exist on the stack, or `push` refuses
  with `not_found` naming the list and the item (D4);
- the list's type, from the local file or the stack, must equal the entry's
  `list.type`, or `push` refuses with `conflict` naming both types (D4).

These refusals replace the 0.9 behavior, which printed a preview line for a
missing list and applied anyway (shared design 7.7).

The fixed apply order grows by one step: value-list containers, then values,
then exception containers, exception items, and rules. An exception item is
never written before the list it names exists with its values. `push` never
deletes a value-list container; values inside a mirrored list are reconciled
exactly (D8), with the writes and read-back of section 6.

A scoped run reconciles the value lists its in-scope exception lists
reference, including a list shared with exception lists outside the scope.
That is sound for the reason shared design 5.4 gives for exception items:
`pull` writes a list's values in full whenever it writes the list, so the
local set is never a partial view.

### 7.5 The report

The change-evidence report records value-list mutations with
`create_value_list`, `update_value_list`, `add_values`, and `remove_values`.
The existing `rule_id` field carries the list `id` and `name` the list name.
`add_values` and `remove_values` carry the values written and a `verified`
flag from the read-back. A list whose read-back did not match carries
`verified: false` and its missing and extra counts.

### 7.6 Older binaries

A 0.9 binary reads only `rules/` and `exceptions/`. It would push a 0.10
mirror without its value lists and print a preview line for each missing one.
The 0.10 CHANGELOG and the state wiki page say that a mirror with
`value-lists/` needs 0.10 or later.
