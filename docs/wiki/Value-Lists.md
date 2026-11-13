# Value Lists

A value list is a named set of values stored in Kibana: IP addresses, IP
ranges, keywords, or text. An exception entry of type `list` matches an event
field against a value list, with `is in list` or `is not in list`. The list's
values therefore decide what a rule suppresses, and removing a value is how a
detection is un-suppressed. `elkctl` treats a value list as policy: every
change is previewed value by value and reconciled exactly.

```bash
elkctl value-lists init                          # preview; add --yes to apply
elkctl value-lists list --type ip_range --search blocked
elkctl value-lists get blocked-ranges --values
elkctl value-lists validate --path lists/blocked-ranges.txt
elkctl value-lists export blocked-ranges --dir lists
elkctl value-lists import --path lists/blocked-ranges.yaml --yes
elkctl value-lists delete blocked-ranges --yes
```

Every command acts on the profile's space. The same `id` in two spaces is two
lists.

## Types

`elkctl` manages four types: `keyword`, `ip`, `ip_range`, and `text`. `list`
shows a container of any other type with `supported: false`; every other
command refuses it with `unsupported`.

## Commands

| Command | What it does |
| --- | --- |
| `list` | Lists containers by `id`. `--type` keeps one type; `--search` matches `id` and name by substring, ignoring case |
| `get <id>` | Shows one container, its distinct and stored value counts, and its warnings. `--values` adds the values |
| `validate --path FILE` | Checks a local pair, given its `.yaml` or its `.txt`. Sends nothing |
| `export <id>...` | Writes each list's pair into `--dir`, or the current directory. Refuses, writing nothing, if any destination file exists |
| `import --path FILE` | Creates the list from a local pair. An existing `id` fails with `conflict` unless `--overwrite` updates the container and reconciles the values exactly |
| `delete <id>...` | Deletes each list and its values |
| `init` | Bootstraps the space's list data streams |

With one `id` and no `--dir`, `export --json` prints the container and its
values as one JSON object instead of writing files.

There is no `create` or `add` verb. Write a file pair and `import` it, or keep
lists in a [state directory](Rules-as-Code.md#value-lists) and `state push`.

## Bootstrap

A space has no value lists until its list data streams exist. Until then,
`import`, `delete`, and a `state push` whose exceptions use value lists refuse
with `unsupported` and name `value-lists init`. `init` previews the
space-wide change and, with `--yes`, runs Kibana's `create-list-indices` flow.
On a space that is already bootstrapped it reports so and writes nothing.
`state push` never bootstraps.
`elkctl doctor` reports the state as its `value_list_index` check.

## Files

A list is two files with one stem: a container file and a values file.

```yaml
# blocked-ranges.yaml
id: blocked-ranges
type: ip_range
name: Blocked ranges
description: Ranges the SOC never wants alerts from
meta:
  owner: soc
```

```text
# blocked-ranges.txt
10.20.0.0/16
192.0.2.10/32
198.51.100.0-198.51.100.99
```

- The container file has exactly `id`, `type`, `name`, `description`, and an
  optional `meta` object. An unknown key is refused, so a typo cannot pass as
  a change. Without `meta`, the stack's `meta` is left as it is.
- The values file is UTF-8 with one value per line. `export` and `state pull`
  write it sorted by byte order, each value once, with LF line endings and a
  trailing newline. `validate`, `import`, and `state push` also accept CRLF
  and unsorted lines.
- Leading and trailing spaces and tabs are trimmed. A blank line or a control
  character is refused with its line number. A line is one value: there are
  no CSV columns.
- The stem is the `id` when the `id` is at most 64 bytes of lowercase ASCII
  letters, digits, `-`, `_`, and `.`, and is not a Windows device name such as
  `con`. Any other `id` gets a stem made of a cleaned prefix and a hash. The
  container file always holds the true `id`.

### Value spelling

`elkctl` adds values in one spelling only: IPv4 as a dotted quad, IPv6 in
RFC 5952 form (lowercase, shortest), a CIDR block with no host bits set, or a
range `a-b` of one family with `a <= b`. A bare address in an `ip_range` file
is written as `a/32` or `a/128`. `validate` warns about another spelling, and
`import` and `state push` refuse to add one, naming the spelling to use.

A value the stack already holds in another spelling is kept as it is, so a
pulled list pushes back unchanged. Values are compared by their exact text:
`2001:DB8::1` and `2001:db8::1` are two values, as Kibana stores them. An
`ip` list does not accept a CIDR block.

## Preview and apply

`import`, `delete`, and `init` print a preview and change nothing. Pass
`--yes` to apply. The preview names the profile, host, and space, and for each
list shows the container action, every value to add and to remove, the order
of the two phases and why, and any warnings:

```text
$ elkctl --profile prod value-lists import --path lists/blocked-ranges.yaml --overwrite
[DRY RUN] value-lists import (profile: prod @ kibana.corp.internal:5601, space: default)
  blocked-ranges (ip_range)
  container: update
  add: 192.0.2.10/32
  remove: 192.0.2.5/32
  phase order: removes_first
  phase reason: every installed reference is included and removing values keeps the list non-empty
Pass --yes to apply.
```

The preview is never shortened: a change of 5,000 values lists 5,000 values.
With `--json`, the preview is one JSON object on stderr with the keys
`dry_run`, `profile`, `host`, `space`, `command`, and `lists`.

With `--yes`, the command reads each list and every exception that references
it again. If anything changed since the preview, it stops with `conflict`
before its first write; run it again to see the new preview.

## How values change

Adds and removes run as two phases. Each phase ends when a read of the list
shows its expected values, so a success answer alone never counts as done.

- Values are added by importing only the missing ones. A full set is never
  imported again, because Kibana would store a second copy of each value.
- Values are removed by deleting each stored copy by its item id. A delete by
  value is never sent: on an `ip_range` list it would also delete every range
  that contains the value.
- Adds go first, so the list never holds less than it does now or will after.
  Removes go first only when every exception that uses the list says
  `is in list` and the list stays non-empty between the phases.

## Safety rules

These refusals come before any write, from `import` and `state push` alike.

- **A list in use is never empty.** Under `is in list`, an existing empty
  list suppresses every event. A write that would leave a referenced list
  empty, at the end or between the phases, is refused. So is creating a list
  that an existing exception already names, because the list is empty until
  its values arrive. An empty values file is valid only for a list nothing
  references.
- **At most 200 dash ranges in an `ip_range` list.** On Kibana 9.5.1, 9.5.6,
  and 9.7.0, an exception on an `ip_range` list that stores more than 200
  values in dash form (`a-b`) suppresses every event, with either operator.
  A write that would leave more than 200 stored dash values, duplicates
  counted, is refused. A write that only lowers a count already above 200 is
  allowed as a repair. CIDR values do not count, so write a single address as
  `a/32` or `a/128` and a range as CIDR blocks. `get`, `state pull`, and
  `state diff` warn about a list above the limit.
- **No type change.** Kibana accepts a new `type` and ignores it, so a changed
  `type` fails with `conflict`, naming both types. To change it, `delete` the
  list and `import` it again.
- **`delete` keeps references.** A list that exception items use fails with
  `conflict` and names each item by `list_id`, `item_id`, and namespace.
  Remove those entries first.

`validate`, `get`, and the push preview also warn when Kibana limits the rule
types a list works with: 65,536 or more `keyword` or `ip` values, 65,536 or
more CIDR values in an `ip_range` list, or any `text` list. Such a list works
only with custom query, saved query, machine learning, and indicator match
rules.

## When the outcome is unknown

A list ends `unknown` when a write's answer is a 5xx, a timeout, a lost
connection, or a body that cannot be read, and a read of the list does not
settle it within 120 seconds. It also ends `unknown` when a phase's read-back
does not show the expected values within that time. `elkctl` then sends
nothing more to that list or any list after it, and never sends the write
again. The command exits `1`; with `state push --report`, the report records
what the last read saw.

Kibana may still apply an import it accepted, later. Running the command again
at once could add the same values twice, and duplicates count toward the
200-range limit. To recover:

1. Wait.
2. Run `elkctl state diff`, or `elkctl value-lists get <id> --values`.
3. Push or import again only when the preview shows the change you expect.

## Concurrency

Nothing locks a value list. Kibana does not move a list's version when its
values change, and an import can become visible after `elkctl` has checked
the list. Coordinate outside `elkctl` so that one writer at a time changes a
list, and so that no one edits an exception that references a list while
`elkctl` writes it.

## Not covered

- Value list types other than the four above.
- Item `meta`.
- Copying a list between spaces in one command. Export from one profile or
  space and import into the other.
- MCP tools. The MCP server has none for value lists.
- Endpoint exceptions, which Kibana does not allow to use value lists.

The design gives the full rules:
[value lists design](https://github.com/dannyota/elasticctl/blob/master/docs/specs/elasticctl-value-lists-design.md).
