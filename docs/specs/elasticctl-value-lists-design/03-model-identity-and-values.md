[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 3. Model, identity, and canonical values

### 3.1 Identity

A value list is identified by its caller-supplied `id` inside the profile's
space. The list data streams are per space, and the same `id` in two spaces is
two lists (V10). elasticctl always sends `id` on create and never lets Kibana
pick one, because Kibana's default is a random UUID.

An `id` is a non-empty string of at most 512 bytes, the limit of an
Elasticsearch `_id`. Its file name follows section 7.2.

Volatile container fields are `_version`, `version`, `tie_breaker_id`,
`created_at`, `created_by`, `updated_at`, and `updated_by`. Item `id`,
`_version`, `tie_breaker_id`, timestamps, and `meta` are volatile too: an item
is its value.

### 3.2 The container file

`value-lists/<id>.yaml` holds the container:

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

`value-lists/<id>.txt` holds the values: UTF-8, one value per line, LF line
endings, a trailing newline, sorted by byte order, each value once. A list
with no values has an empty file. `pull` writes this form. `validate` and
`push` accept CRLF and unsorted input, normalize it, and refuse an empty
line, because a blank line is not a value and Kibana drops it on import
without an error (V5).

A line is one value. There are no CSV columns: Kibana stores `10.0.0.13,x` as
one keyword (V5).

### 3.4 Canonical values per type

The diff compares canonical values on both sides. A value is canonical when
it is in the form Kibana returns for it.

| Type | Accepted | Canonical form |
| --- | --- | --- |
| `keyword` | Any text without a line break | Leading and trailing spaces removed; Kibana trims them (V4). Inner text, commas, and Unicode are kept. |
| `text` | Any text without a line break | As for `keyword`. |
| `ip` | One IPv4 or IPv6 address | Trimmed. A CIDR or other text is refused; Kibana answers 400 (V4). |
| `ip_range` | One address, a CIDR block, or a dash range `a-b` | A single address becomes `a/32` or `a/128` (D11). A CIDR block and a dash range are kept as written. |

Kibana reads a single address in an `ip_range` list back as `a-a` (V4). On
read, elasticctl keeps `a-a` as it is stored, so a pulled list shows what the
stack holds and section 5.2 can count its dash values. On write, a local
`a-a` is sent as written: the canonical `/32` form applies only to a bare
address, and a mirror moves to CIDR only when someone edits it.

Duplicates collapse. Kibana stores the same value twice when it arrives in two
requests or two imports (V4, V5), and its export keeps both copies (V8). The
remote set is the set of distinct canonical values. A remote duplicate does
not change what the list matches, so it is reported as a warning and left
alone: removing it by value would delete every copy (V9).
