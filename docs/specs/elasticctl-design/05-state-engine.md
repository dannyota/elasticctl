[Back to elasticctl-design](../elasticctl-design.md)

## 5. State engine

- **`pull`** — read the corpus through `_find`, map to `Rule`, normalize, fetch
  the exception lists those rules reference, and write the tree in the requested
  format. Filenames are planned for every object before
  the first file is written. A `rule_id` pair that sanitises to one filename is
  refused with `conflict`, naming **every** colliding pair at once, before the
  directory is created. Reporting one collision per run hides the next until a
  re-run. Writing files up to a collision leaves a mirror that is neither the
  old state nor the new one. The write is a recoverable local-file transaction:
  a sibling lock and journal preserve or restore the prior tree if replacement
  is interrupted.
- **`diff`** — read local, fetch remote, normalize both, emit field-level
  drift. NDJSON lines are not readable by eye, so `diff` is the human view and
  `git diff` is the fidelity record.
- **`push`** — read local, compute the diff, apply each change through the
  guard, then write a change-evidence report of per-rule before and after
  values plus an applied flag, suitable for attaching to a change ticket.
  The same report records every exception mutation with `create_list`,
  `update_list`, `create_item`, `update_item`, or `delete_item`. For those
  entries the existing `rule_id` field carries the stable `list_id` or
  `item_id`; `name` carries the list name or the item's parent `list_id`.
  Successful creates have no `before`, deletes have no `after`, and successful
  updates carry both. A failed write has no `after`.
  Its report path is preflighted and recoverably replaceable before the first
  remote apply, so an unwritable report cannot leave an unreported mutation.

`push` **never deletes remote rules.** A rule missing locally is not a delete
instruction. Deletion is always the explicit `rules delete`.

### 5.0 Pull path identity and locking

Before it acquires a lock or begins transaction recovery, `pull` resolves the
requested mirror path to one filesystem identity. An existing mirror is fully
canonicalized. For a new mirror, its immediate parent must already exist and
is canonicalized before the one final mirror-name component is appended.
`pull` never creates a missing parent chain; a missing immediate parent returns
the existing typed filesystem error that names that parent.

This resolves `.` and existing `..` components and follows existing symlink
aliases without lexically rewriting a path across a symlink. The resolved root
is used for the sibling lock and every transaction filesystem operation. The
requested spelling is retained only for user-facing output and errors.

The sibling lock is `.<mirror-name>.elasticctl-pull.lock`. A filesystem root
has no safe sibling lock and is refused with `ErrorKind::Error`; its message
contains `filesystem root has no safe sibling lock`. This applies to Unix `/`,
Windows drive roots, and UNC share roots.

### 5.0.1 Report path identity and locking

Before locking or recovery, `state push --report FILE` canonicalizes FILE’s existing immediate parent, following existing symlink aliases, then appends its final filename. It never creates parents or canonicalizes the final target. The resolved destination determines the sibling lock, transaction directory, journal, and every filesystem operation through preparation, publication, rollback, and recovery. Requested spelling is retained only for messages. Final symlinks, non-regular targets, and symlinked locks are refused. Alias spellings share one lock and transaction identity. Canonicalization does not provide atomic protection against concurrent replacement of canonical ancestors.

### 5.1 Server-applied defaults

Creating a rule with 13 fields returns 36. The server adds 16 defaults and 7
volatile fields. The defaults include `max_signals: 100`, `to: "now"`,
`rule_source: {"type":"internal"}`, and `actions: []`. Normalization also
strips `execution_summary` when other responses include it, bringing the full
volatile-field set to 8.

That means a hand-authored rule file omitting `max_signals` would diff against
its pulled counterpart forever. Two modes resolve it:

- A rule written by `pull` already carries the full field set, so the diff is
  symmetric and exact.
- A hand-authored rule is passed through default-filling before comparison, so
  an omitted field reads as "accept the server default", not as drift.

`rules validate` applies the same default-filling, so an engineer can see
exactly what a sparse file will become before pushing it.

Serverless also appends the tag `Missing Elastic Cloud API Key` to a rule that
a project-scoped key enables (section 7.2). Normalization treats it as
server-applied state, like the volatile fields: it removes every `tags`
element that equals that exact string, case-sensitive, and keeps the other
tags in order. An emptied array stays `[]`; an absent or non-array `tags` is
left as it is. `pull` never writes the tag, `diff` never reports it, and `push`
never sends it, so a rule cannot carry this exact tag through the mirror.
`rules get`, MCP `rules_get`, and `rules export` return the same normalized
rule, so they omit the tag as well. `rules list` and `rules import` do not
normalize.

### 5.2 Reading the corpus

`_find` is read in one request, not paged. `per_page` is bounded by
Elasticsearch's result window — `from + size` must not exceed 10,000. A page
size at that window returns every corpus that `_find` can serve.
Measured against 2,066 rules: 21 sequential pages of 100 cost 8.4-11 s; one
request costs 2.4 s.

A corpus larger than 10,000 rules cannot be read through one `_find` by any
combination of `page` and `per_page`, because the limit applies to their sum
rather than to either one. Paging smaller does not evade it and neither does
concurrency. Above the window the corpus is read by partitioning instead.

Every rule `_find` response is decoded as a strict envelope: a JSON object
with array `data`, unsigned integer `total`, positive integer `page`, and
positive integer `perPage`. `perPage` is the spelling in every recorded rule
response. Exception-list `_find` keeps its separate `per_page` contract. Rule
decoding requires the exact `perPage` field: `per_page` cannot substitute when
`perPage` is absent. Unknown fields remain accepted, so a present `per_page`
field is ignored when `perPage` is also present.

Malformed envelopes are not converted to an empty result. Missing or mistyped
fields, `data.len() > total`, and `data.len() > perPage` return
`ErrorKind::Http` messages beginning `decoding rule _find response field` and
naming the invalid field or relationship. Transport JSON-number parse failures
remain transport `ErrorKind::Http` errors rather than envelope errors. All
callers share this decoder, so source-partition verification and prebuilt
customized counts also fail closed on API drift.

`rules export` must not be offered as an escape hatch. It has its own 10,000
cap from `xpack.securitySolution.maxRuleImportExportSize` and returns `Can't
export more than 10000 rules` with a 400. The generic saved-objects export
cannot serve either: the security rule types register `isExportable: false`, so
detection rules are not exportable through that interface. No public API reads
past the window in one call.

#### Partitioned reads above the window

When `total` exceeds the window, the corpus is read as one `_find` per rule
type, filtered on `alert.attributes.params.type`. Every rule has exactly one
type, so the slices are disjoint and together exhaustive — measured against
2,066 rules, the seven types sum to exactly the corpus:

| Type | Rules |
|---|---|
| `query` | 455 |
| `eql` | 1,022 |
| `esql` | 208 |
| `threshold` | 28 |
| `threat_match` | 6 |
| `machine_learning` | 106 |
| `new_terms` | 241 |
| **Total** | **2,066** |

A single type larger than the window is split again on
`alert.attributes.enabled`, which is likewise disjoint and exhaustive (measured
2 enabled, 2,064 disabled). Fourteen slices put the ceiling near 140,000.

Exhaustiveness is enforced, not assumed: the slice totals must sum to the
corpus `total` or the read is refused as a short read, the same rule that
already covers a server returning fewer rules than it counted. This is why the
partition is on type rather than on tags — a rule may carry many tags or none,
so tag slices both double-count and drop rules, and no sum check would hold.

A slice still above the window after both partitions is refused with an error
naming the limit. Returning the first 10,000 rules as though they were the
corpus would make `state diff` report every unread rule as remote-only and
`state pull` write a mirror missing them — silent truncation is the one outcome
worse than failing.

The single-request path is unchanged for a corpus under the window, which
includes every real corpus today. Partitioning is a fallback, not the default.
Seven requests for a 2,066-rule read would forfeit 5.2's result.

Kibana exposes `search_after` on
`POST /internal/detection_engine/rules/_search`, which would remove the ceiling.
It is deliberately rejected. The route is `access: 'internal'` and unversioned,
and this tool spans three deployment flavors whose internal routes need not
agree or survive an upgrade.

### 5.3 Scoped state operations

`pull`, `diff`, and `push` take the same positional selectors and `--tag`
filter as `rules export` (4.3), plus `--search` (4.7). Given neither, they act on
everything inside the active `--source` scope, which from 0.2 is the space's
custom rules rather than the whole space. Section 5.5 covers that change.

Selection narrows both sides before drift is computed, so the remote read
becomes one `rule_id`-filtered `_find` instead of a corpus read. Resolution
differs by command because the commands face opposite directions:

- `pull` reads from the stack, so its selectors name stack rules and resolve
  remotely.
- `diff` and `push` act on the local directory, so a selector matching a local
  `rule_id` or `name` wins and only an unmatched one falls through to a remote
  lookup. Without local-first resolution, a locally added rule that is not yet
  in a remote index could not be selected. Scoped `push` could then not perform
  its principal use.

A selector resolving to nothing is refused, naming the selector, as in 4.3. A
name matching two local rules is refused, naming both `rule_id`s. Identity is
`rule_id`; a display name that is no longer unique is not resolved by guessing.

`RemoteOnly` keeps its meaning inside a selection — `--tag prod` can select a
remote rule with no local file — and `push` still never deletes it.

Scoped runs report what narrowed them. Unscoped runs produce their previous
output. `diff` and `push` report `selected` alongside `local_total`, so a scoped
run cannot be mistaken for a clean tree. `pull` reports `selected` only because
it reads from the stack and has no local set to count against.

The guard banner names the selection. A scoped apply that looked identical to a
full one would defeat the purpose of the banner.

### 5.4 Exceptions in the mirror

The mirror covers the rules in scope plus exactly the exception lists those
rules reference. A list nothing references is not part of a rules-as-code
mirror; `exceptions export` covers it. That closure is what keeps `pull` and
`push` symmetric: `push` manages the set `pull` wrote and never meets a list it
was not told about.

```
config/
  rules/<rule_id>.yaml
  exceptions/<list_id>.yaml
```

A `rule_default` list belongs to exactly one rule and is written inline in that
rule's file. Its own file would be an object whose only consumer is one rule
and whose lifetime is that rule's.

Filenames are planned for every rule and list before the first file is written,
and collisions are refused naming every colliding pair at once — section 5's
existing contract, extended to lists. A `single` and an `agnostic` list sharing
a `list_id` collide on filename and are refused the same way.

`push` applies in a fixed order: containers, then items, then rules. A rule is
never written before the list it points at exists.

A scoped run reconciles items the same way, including in a container shared with
rules outside the scope. That is sound for the same reason the deletion itself
is: `pull` writes a container's items in full whenever it writes the container
at all, and the item read is scoped by `list_id`, never by rule. So a mirror
produced by `state pull r1 --dir config/` holds the complete item set of every
container `r1` references, even one that `r2` also references. The local set is
never a partial view, so an item missing from it is still an instruction.

What a scoped run does *not* do is touch a container no in-scope rule
references — that container is not in the mirror, and its items are never even
read.

**Containers and rules are never deleted. Items inside a mirrored container are
reconciled exactly, deletes included.** The asymmetry follows from what is
mirrored rather than from a softened contract. A rule or a list absent locally
may simply never have been pulled, so its absence carries no instruction. A
container's item set is always written in full — there are no item-level
selectors — so an item present remotely and absent locally *is* an instruction,
in the way a removed entry in a rule's `tags` array is. Removing an exception
is how a detection is un-suppressed. A mirror that cannot express it cannot
converge.

That deletion contract requires a complete, readable local item set. An
exception file may contain one NDJSON object. An omitted `items` field means an
empty hand-authored set, but a present `items` field must be an array. Multiple
objects or a non-array value are refused before remote reconciliation, so
malformed input cannot widen into item deletion.

A standalone top-level exception item in a rule file or export bundle must
have readable, non-empty string `item_id` and `list_id` values. Its absent
`namespace_type` retains the `single` default; if present it must be a
non-empty string. Unknown non-empty namespace strings remain valid so a future
server value can round-trip without being treated as `single`. NDJSON bundle
items and YAML top-level items are validated before they enter the mirror.

This stricter rule is contextual. A nested item inside a container may omit
`list_id`, because splitting the container assigns the authoritative parent
`list_id` and `namespace_type`. Item grouping validates the same identity again
before item reconciliation, so a malformed item returns
`ErrorKind::Error` instead of planning a remote item deletion. Empty fields use
the messages `exception item field item_id must be a non-empty string`,
`exception item field list_id must be a non-empty string`, and `exception item
field namespace_type must be a non-empty string`.

`diff` gains an `exceptions` block mirroring the rules block, and `clean` is
true only when both are.

### 5.5 Scoping by rule source

`--source custom|customized|prebuilt|all` scopes `rules list`, `rules export`,
and the state commands.

| Value | Server-side filter |
|---|---|
| `custom` | `alert.attributes.params.immutable: false` |
| `prebuilt` | `alert.attributes.params.immutable: true` |
| `customized` | `alert.attributes.params.ruleSource.isCustomized: true` |
| `all` | none |

`immutable` carries the custom/prebuilt split rather than
`params.ruleSource.type` because it is present in the measured fixtures. On
Serverless 9.6.0, the fields agreed exactly: 2,066 prebuilt and 0 custom. Its
presence on versions older than 9.5.1 is unmeasured.

The state commands default to `custom`; `rules list` and `rules export` default
to `all`. The defaults differ because the commands differ. A mirror should hold
what the operator authored, and `state pull` writing 2,066 Elastic-owned rules
into a repository is the behavior 0.2 removes. A query command that hid 2,066
rules demonstrably present on the stack would be lying instead.

Section 5.2's exhaustiveness check extends: custom and prebuilt must sum to the
corpus, and when `--source` is active a partitioned read checks its slices
against the filtered total rather than the corpus total.

A local file outside the active scope is reported as `out_of_scope`, naming the
flag, not as `local_only`. A 0.1 mirror holding 2,066 prebuilt rules would
otherwise read as catastrophic drift on the first `state diff` after upgrading.

An empty `custom` or `prebuilt` source is valid when their totals together
exhaust the corpus: then zero is a measured partition result, not a missing
`immutable` field. If the totals do not exhaust the corpus, the source query is
refused naming `alert.attributes.params.immutable`; an older stack could
otherwise silently report "no custom rules" merely because it lacks that
field. `state diff` and `state push` still express excluded local files as
`out_of_scope`.

### 5.6 Mirrors from a newer version

From 0.9.4, `state pull`, `state diff`, and `state push` refuse a mirror
directory that holds `value-lists/`, an entry of any kind, with
`unsupported` and the message `this mirror holds value-lists/, which needs
elasticctl 0.10 or later`. The refusal comes before any request, lock, or
file write. 0.10 writes value lists there (the 0.10 value lists design),
and a 0.9 binary would otherwise push such a mirror's exceptions without its value
lists, or pull into it and leave its value lists stale. If the entry cannot
be inspected, for example because the mirror is not searchable, the command
fails closed with `error` and a message beginning `checking the mirror for
value-lists/:`, rather than treating the mirror as free of value lists. 0.9.0
to 0.9.3 do not have this check.

