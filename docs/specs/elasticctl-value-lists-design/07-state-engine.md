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

`push` also checks the **retained** references: an in-scope local rule may
point at an exception container that is on the stack but not in the mirror,
which `push` leaves as it is. The `list` entries of that container's remote
items are dependencies of the rule, so `push` reads them and checks them by
7.4. They are read and checked only: a list they name that is not in the
selected set is never written.

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
only lowercase ASCII letters, digits, `-`, `_`, and `.`, does not start or end
with `.`, and is not a Windows device name (`con`, `prn`, `aux`, `nul`, `com1`
to `com9`, `lpt1` to `lpt9`, alone or before a `.`). Any other `id` gets the
stem `<prefix>-<hash>`. `<prefix>` is the `id` passed through the rule-file
sanitizer, then lowercased, then cut to at most 48 bytes at a character
boundary, with a trailing `.` removed. `<hash>` is the first 12 hex digits of
the SHA-256 of the `id`'s UTF-8 bytes. The container file always carries the
true `id`. Stems are compared without regard to case. Names are planned for
every rule, exception list, and value list before the first file is written,
and a collision is refused naming every colliding pair at once (shared design
5). `export`, `import`, and `validate` use the same stem rule.

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
dangling reference, a type mismatch, a dash count above 200, and an empty
list that a reference uses. Each makes `clean` false. Duplicates, size
warnings, and `unreferenced` pairs are warnings and leave `clean` alone.

### 7.4 `push`

`push` validates every pair in the selected set by section 5 before any
request. Then it checks every `list` entry of every local exception item in
the selected containers, whether `push` would write the item or not, and of
every remote item of a retained container (7.1):

- the list must have a source: a local pair that passed validation and that
  this run writes, or a container that `GET /api/lists?id=` returned and that
  decoded. Membership in the selected set is not enough. Otherwise `push`
  refuses with `not_found` naming the list and the item (D4);
- that source's type must equal the entry's `list.type`, or `push` refuses
  with `conflict` naming both types (D4);
- an `ip_range` list's final stored dash count, projected as section 5.2
  says, must pass D12;
- a list that any reference uses must not be empty, finally or between
  phases, and a list that an installed reference names must not be created
  (D28).

`push` also refuses with `conflict` a run that changes a list's values and
also changes its references, any exception item that references it, or the
values of another list such an item references (D27). The references of a list
are every (container, item, field, operator) entry that names it: installed
ones from the scan of D26, and desired ones from the local items the run would
leave in place or write, with retained and out-of-scope installed references
kept as they are. If the two sets differ in any way, an added, removed,
replaced, or changed entry, and the list's values or type also change, `push`
refuses and names both changes. The one exception is a list that does not
exist and has no installed reference: `push` creates it with its values and
then writes its first references, in the order of this section.

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
in the order they ran. `remove_values` has one entry per value and
`add_values` one entry per import request, so a partial phase is visible.
Each entry carries:

- `rule_id`: the list `id`, as exception entries already reuse that field,
  and `name`: the list name;
- `values`: the values that request carried, in byte order;
- `sent`: `accepted` (2xx), `refused` (4xx, with its status), `uncertain`
  (section 6.4), or `not_sent`;
- `phase_verified`: whether the read-back of that phase observed its
  expected set;
- `outcome`: the list's outcome of section 6.7, the same on every entry of
  the list.

A list that ends `unknown` adds one `read_back` entry with `of`: `values` or
`container`, naming what the last read looked at. Its `observed` is true when
that read completed. A completed values read carries `missing` and `extra`,
the counts of the exported set against the expected one. A completed container
read carries `mismatched`, the container fields that differed from the plan.
When no read completed, for example because every export failed, `observed` is
false, those fields are absent rather than zero or empty, and `read_error`
carries the last read's error kind and status. A `not_reached` list adds one
entry with its planned counts and no values.

The push summary gains `value_lists_created`, `value_lists_updated`,
`values_added`, `values_removed`, `value_lists_unknown`, and
`value_lists_not_reached`, each omitted when zero, so a mirror without value
lists reports exactly what 0.9 reported. `value_lists_created` and
`value_lists_updated` count lists that ended `applied`; `values_added` and
`values_removed` count only values in a verified phase. For a run where list
`a` applies with 1,200 adds and 3 removes, list `b` sends two import chunks
and the second times out without a match, and list `c` is not reached, the
summary is:

```json
{"value_lists_updated": 1, "values_added": 1200, "values_removed": 3,
 "value_lists_unknown": 1, "value_lists_not_reached": 1}
```

The report holds `a`'s entries, `b`'s first chunk as `accepted`, its second
as `uncertain` and its third as `not_sent`, `b`'s `read_back` entry, and
`c`'s `not_reached` entry. If every export of `b` failed, its `read_back`
entry would be:

```json
{"action": "read_back", "rule_id": "b", "outcome": "unknown",
 "of": "values", "observed": false, "read_error": {"kind": "timeout"}}
``` The `-api` apply returns this evidence for every
outcome, and the report is written before the command exits, so a partial
apply is never unreported (shared design 5).

### 7.6 Older binaries

A 0.9 binary reads only `rules/` and `exceptions/`. It would push a 0.10
mirror's exceptions without its value lists and print a preview line for each
missing one. 0.9.4 refuses `state diff` and `state push` on a mirror that
holds `value-lists/`, naming 0.10 as the version that can read it (D21). A
binary from 0.9.0 to 0.9.3 cannot be changed; the 0.10 CHANGELOG, the README,
and the state wiki page record that a mirror with `value-lists/` needs 0.9.4
to refuse it and 0.10 to push it.
