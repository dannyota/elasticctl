[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 3. Model, identity, and canonical values

### 3.1 Identity

A value list is identified by its caller-supplied `id` inside the profile's
space. The list data streams are per space, and the same `id` in two spaces is
two lists (V10). elasticctl always sends `id` on create and never lets Kibana
pick one, because Kibana's default is a random UUID.

An `id` is a non-empty string of at most 512 bytes, the limit of an
Elasticsearch `_id`, with no control character. Its file name follows
section 7.2.

Volatile container fields are `_version`, `version`, `tie_breaker_id`,
`created_at`, `created_by`, `updated_at`, and `updated_by`. Item `id`,
`_version`, `tie_breaker_id`, timestamps, and `meta` are volatile too: an item
is its value.

### 3.2 The container file

`value-lists/<stem>.yaml` holds the container:

```yaml
id: blocked-ranges
type: ip_range
name: Blocked ranges
description: Ranges the SOC never wants alerts from
meta:
  owner: soc
```

`id`, `type`, `name`, and `description` are required. Kibana requires `name`
and `description` on create. `meta` is optional and round-trips as an object.
No other key is read or written, and an unknown key is refused by `validate`
rather than dropped, so a typo cannot pass as a change.

### 3.3 The values file

`value-lists/<stem>.txt` holds the values: UTF-8, one value per line, LF line
endings, a trailing newline, sorted by byte order, each value once. An empty
file is valid only for a list no reference uses (D28). `pull` writes this
form. `validate` and `push` accept CRLF and unsorted input and normalize it.

A line is one value. There are no CSV columns: Kibana stores `10.0.0.13,x` as
one keyword (V5).

### 3.4 Parsing order

Each line is processed in this order, and the first failing step refuses the
file with the line number:

1. Remove a trailing CR.
2. Trim leading and trailing spaces and tabs. Kibana trims them (V4).
3. Refuse an empty result. A blank or whitespace-only line is not a value,
   and Kibana drops it on import without an error (V5).
4. Refuse a control character.
5. Parse by type (3.5) and produce the canonical form.

### 3.5 Canonical values per type

A value is canonical when it is the exact string elasticctl sends and Kibana
returns. The codec has two levels:

- **readable**: any value Kibana accepts and stores for the type, in any
  spelling, such as uppercase IPv6, a CIDR with host bits, or a mixed-family
  range (V12). A pulled file holds readable values, and `validate` accepts
  them;
- **canonical**: the one spelling of the table below. elasticctl writes only
  canonical values. A readable value that is not canonical is a warning in
  `validate` and `diff`, and `push` and `import` refuse to add one, naming
  the canonical spelling. A non-canonical value already stored on the stack
  and kept unchanged is not refused, so pull, validate, and push round-trip.

| Type | Accepted | Canonical form |
| --- | --- | --- |
| `keyword` | Any text | The trimmed text. Commas and Unicode are kept (V4). |
| `text` | Any text | The trimmed text. |
| `ip` | One IPv4 address in dotted-quad form, or one IPv6 address in RFC 5952 form | As written. Any other spelling, a CIDR, or other text is refused; Kibana answers 400 for a CIDR (V4). |
| `ip_range` | One address, a CIDR block with no host bits set, or a dash range `a-b` of one family with `a <= b` | A bare address becomes `a/32` or `a/128` (D11). A CIDR block and a dash range are kept as written, with each address in the spelling the `ip` row requires. |

V12 showed that Kibana stores each spelling as sent: IPv6 case and
compression are kept, host bits are kept, and a mixed-family range is stored.
The same address in two spellings is then two stored values, so elasticctl
adds only one spelling: RFC 5952 for IPv6, no host bits, and only
same-family, ascending ranges. A reversed range is a 400 from the item API
and is dropped silently by import (V12), so it is not readable and is refused
everywhere. A pulled value in another spelling stays as stored, as `a-a`
does.

### 3.6 What the stack holds

A read keeps two views of a list:

- the **stored values**: every line of `_export`, in the stored spelling,
  duplicates included (V8);
- the **set**: the distinct stored values.

Comparison uses the set. Safety checks use the stored values: the dash count
of D12 counts every stored line in dash form, duplicates included. A pulled
`a-a` stays `a-a` in the mirror, because that is what the stack holds; only a
bare address that someone writes becomes CIDR.

A remote duplicate does not change the set, so `diff` reports it as a warning
and leaves it. Removing it by value would delete every copy (V9).
