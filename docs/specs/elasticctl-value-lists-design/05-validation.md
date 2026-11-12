[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 5. Validation

`value-lists validate`, `value-lists import`, and `state push` run the same
checks on local files before any request. A failed check refuses the whole
command; no list is written while another is invalid.

### 5.1 Checks

| Check | Refusal |
| --- | --- |
| The container file has exactly `id`, `type`, `name`, `description`, and optional `meta`, with string values and an object `meta` | `error`, naming the key |
| `id` is valid (section 3.1) and its stem (section 7.2) equals the file's stem | `error` |
| `type` is one of the four types | `unsupported`, naming the type and the four supported ones |
| The values file exists beside the container file and is UTF-8 | `error` |
| Each line passes the parsing order of section 3.4 and is readable for the type (section 3.5) | `error`, with the line number and the value |
| A value the command would add is canonical (section 3.5) | `push` and `import`: `error`, with the canonical spelling. `validate`: a warning, since it does not know what is already stored |
| No single value, with its line feed, is larger than 8,000,000 bytes | `error`: an import request carries whole values only (section 6.3) |

A value that canonicalizes to one already seen is not an error: the set
collapses it.

### 5.2 Dash values in `ip_range` lists

D12 is checked on three stored states of each `ip_range` list a command would
write: the current state on the stack, the state between the two phases
(section 6.3), and the final state. A state's dash count is the number of its
stored values in dash form, duplicates included (section 3.6). The states are
projected from the current stored values: a kept value keeps every stored
copy, a removed value loses every copy, and an added value is stored once.
The local file's distinct count is never used for this check.

- A final state above 200 refuses the write with `unsupported`.
- A between-phases state above 200 refuses the write, unless it is no higher
  than the current state: a write that only lowers an existing count is a
  repair, and is allowed, with any container update it carries.

The message says that Kibana 9.5.1, 9.5.6, and 9.7.0 suppress every event
for an exception on such a list, with either operator (V11, V12), and gives
the remedy: write a single address as `a/32` or `a/128` and a range as CIDR
blocks. V12 measured the boundary: exactly 200 stored dash values behave
correctly, 201 stored values of which 200 are distinct do not, and CIDR
values do not count.

Reads (`get`, `pull`, `diff`) report a list above 200 as a warning, and `diff`
counts it as not clean (section 7.3).

### 5.3 Empty lists

D28 is checked on the same three states for every list that an installed
reference (D26) or a desired reference uses, of every type. A final state or
a between-phases state with no values refuses the write with `unsupported`,
and so does creating a list that an installed reference already names. The
message says that an empty list under `is in list` suppresses every event
(V12) and names the references. A values file may be empty only for a list
that nothing references, such as one written by `value-lists import`.

### 5.4 Size warnings

Kibana documents that a list with 65,536 or more `keyword` or `ip` values,
65,536 or more `ip_range` values in CIDR form, or any `text` list works only
with custom query, saved query, machine learning, and indicator match rules.
`validate`, `get`, and the push preview report these as warnings, never
refusals: the list is valid, and the rule type is the rule's concern.
