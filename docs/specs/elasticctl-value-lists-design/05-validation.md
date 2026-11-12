[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 5. Validation

`value-lists validate`, `value-lists import`, and `state push` run the same
checks on local files before any request. A failed check refuses the whole
command; no list is written while another is invalid.

### 5.1 Checks

| Check | Refusal |
| --- | --- |
| The container file has exactly `id`, `type`, `name`, `description`, and optional `meta`, with string values and an object `meta` | `error`, naming the key |
| `id` is non-empty, at most 512 bytes, and its file name under section 7.2 equals the file's stem | `error` |
| `type` is one of the four types | `unsupported`, naming the type and the four supported ones |
| The values file exists beside the container file and is UTF-8 | `error` |
| No empty line | `error`, with the line number |
| Each value is valid for the type (section 3.4) | `error`, with the line number and the value |
| The request for any one import chunk stays under 9,000,000 bytes (section 6.2) | Never refused: chunking handles size |

A value that canonicalizes to one already seen is not an error: duplicates
collapse.

### 5.2 Dash values in `ip_range` lists

An `ip_range` list holding more than 200 values in dash form is refused for
every write with `unsupported` (D12). The message says that Kibana 9.5.1,
9.5.6, and 9.7.0 then suppress every event for an `is in list` exception
(V11), and names the remedy: write a single address as `a/32` or `a/128` and
a range as CIDR blocks. Reads (`get`, `pull`, `diff`) report the same
condition as a warning on the list and write nothing.

The count is of values in dash form after canonicalization. A bare address
written by the operator is already CIDR (D11) and does not count. A pulled
`a-a` value does count, because that is what the stack holds.

### 5.3 Size warnings

Kibana documents that a list with 65,536 or more `keyword` or `ip` values,
65,536 or more `ip_range` values in CIDR form, or any `text` list works only
with custom query, saved query, machine learning, and indicator match rules.
`validate`, `get`, and the push preview report these as warnings, never
refusals: the list is valid, and the rule type is the rule's concern.
