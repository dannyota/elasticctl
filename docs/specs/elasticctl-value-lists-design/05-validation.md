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
| Each line passes the parsing order of section 3.4 | `error`, with the line number and the value |
| No single value, with its line feed, is larger than 8,000,000 bytes | `error`: an import request carries whole values only (section 6.3) |

A value that canonicalizes to one already seen is not an error: the set
collapses it.

### 5.2 Dash values in `ip_range` lists

D12 is checked on three stored states of each `ip_range` list a command would
write: the current state on the stack, the state between the two phases
(section 6.3), and the final state. A state's dash count is the number of its
stored values in dash form, duplicates included (section 3.6).

- A final state above 200 refuses the write with `unsupported`.
- A between-phases state above 200 refuses the write, unless it is no higher
  than the current state: a write that only lowers an existing count is a
  repair, and is allowed, with any container update it carries.

The message says that Kibana 9.5.1, 9.5.6, and 9.7.0 suppress every event
for an `is in list` exception on such a list (V11), and gives the remedy:
write a single address as `a/32` or `a/128` and a range as CIDR blocks.

Reads (`get`, `pull`, `diff`) report a list above 200 as a warning, and `diff`
counts it as not clean (section 7.3). Whether exactly 200 is safe, whether
Kibana counts stored or distinct values, and how the `is not in list`
operator behaves are V12 measurements. Until they are in, the stored count
and the limit of 200 stand.

### 5.3 Size warnings

Kibana documents that a list with 65,536 or more `keyword` or `ip` values,
65,536 or more `ip_range` values in CIDR form, or any `text` list works only
with custom query, saved query, machine learning, and indicator match rules.
`validate`, `get`, and the push preview report these as warnings, never
refusals: the list is valid, and the rule type is the rule's concern.
