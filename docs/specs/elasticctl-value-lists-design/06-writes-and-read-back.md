[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 6. Writes, read-back, and outcomes

Every route is under the profile's space and sends `kbn-xsrf: true` and
`elastic-api-version: 2023-10-31`. Reads may retry as other reads do. A write
is sent once, on a transport without retries: a retried import duplicates
values (V5), and a retried delete can answer for a request that already ran.

### 6.1 Preconditions

Before a preview, a write command reads `GET /api/lists/index`. Unless both
`list_index` and `list_item_index` are true, it refuses with `unsupported`
and names `value-lists init` (D6). It then reads each target list: the
container with `GET /api/lists?id=` and the stored values with
`POST /api/lists/items/_export?list_id=`. The preview is computed from these
reads.

Before the preview the command also runs the scan of installed references
(D26) once. A container or item it cannot read, a result past the read
window, or a `list` entry whose `id` or `type` does not decode refuses the
command before any write; an unread container is never counted as "no
references".

At apply, after `--yes`, the command reads each list again and runs the scan
again. If a container's `id`, `type`, or `_version`, its stored values, or
its installed references differ from the preview's read, it stops with
`conflict` before its first write and asks for a re-run.

**Concurrency limit.** Nothing locks a list. Item writes do not move the
container's `_version` (V6), and another writer's import can become visible
after this command's read-back matched (V5). Two writers to one list must be
coordinated outside elasticctl, and so must anyone who edits an exception
that references a list while elasticctl writes it. The design says so in the
wiki and does not present the read-back or the second scan as proof that no
one else wrote.

### 6.2 Create

`POST /api/lists` with `id`, `type`, `name`, `description`, and `meta` when
present. A 409 means the `id` exists and is reported as `conflict`. The
values are then added as the add phase of 6.3, with nothing to remove. The
list is empty until they land, so creating a list that an installed
reference already names is refused (D28); with no installed reference, no
exception reads the list yet, because exception items are written after its
values verify (section 7.4).

### 6.3 Update and exact reconciliation

The container's `name`, `description`, and `meta` are updated with
`PATCH /api/lists`, carrying the `_version` from the apply-time read (D16).
A 409 is `conflict`. A changed `type` never reaches the stack: it is refused
before the preview (D15), with `conflict` naming both types. Recreating the
list under the new type is a `delete` and an `import`, each asked for by
name.

Values are compared as sets (section 3.6). The change runs in two phases
(D14), in the order of D22:

- **Remove phase.** The phase first reads every item of the list with
  `GET /api/lists/items/_find?list_id=<id>` by `cursor` (D19). The values it
  returns must equal, duplicates included, the stored values of the last read
  before the phase: the apply-time read when removes run first, or the add
  phase's verified read-back when adds ran first. Otherwise the list stops
  with `conflict` before its first delete. Then, for
  each stored copy of each value in the remote set and not in the local set:
  `DELETE /api/lists/items?id=<item id>`. A delete by value is never sent
  (D13): Kibana runs it as a query on the list's field, which on `ip_range`
  matches every range that contains the value (V13). A 404 means the
  item is already gone: it is the one 4xx that is not a failure, and the
  phase goes on to its next item and its read-back.
- **Add phase.** For the values in the local set and not in the remote set:
  `POST /api/lists/items/_import?list_id=<id>`, with the multipart field
  `file`, the file name `<stem>.txt`, and the values joined by LF with a
  trailing LF. Values are packed into requests of at most 8,000,000 bytes of
  body, split only between whole lines; section 5.1 refuses a single value
  that cannot fit. The bound keeps each request under Kibana's 9,000,000-byte
  limit (V5) with room for the multipart framing. Requests go one at a time.

D22 picks the order from the references installed on the stack: adds first,
unless every installed reference is `included` and the remote set less the
removes is non-empty, in which case removes first. With adds first, the
between-phases set is the remote set plus the adds: never empty when the
final set is not, and never suppressing more than the list does now or will
after. `state push` and `value-lists import --overwrite` use the same scan.
`state push` writes values before exception items, so the installed
references are the ones in force while the values change; D27 refuses a run
that would change both a list's values and its references. The
between-phases state of sections 5.2 and 5.3 is the remote set less the
removes, or the remote set plus the adds.

### 6.4 Read-back

Each phase ends with a read-back before the next phase or the next list
starts. The command exports the list until the remote set equals the
phase's expected set: after a remove phase, none of the removed values; after
an add phase, all of the added values, and after the last phase, exactly the
local set.

Each phase has a budget of 120 seconds on a monotonic clock. The budget
covers every export request, its retries, and the pauses between them. An
export starts at least one second after the previous one ended, and its
request timeout is capped at the time left. V5 measured 100,000 imported
values settling in 6 to 9 seconds, and V9 a 100,000-value export taking 9 to
15 seconds.

A match ends the phase as verified. No match within the budget ends it as
`unknown`, with the counts of values still missing and still present, and
the command sends nothing further for that list or any list after it. The
read-back only reads: it never sends a second import, which could duplicate
values.

**Uncertain writes.** A write whose answer is a 5xx, a timeout, a connection
loss after sending, or an undecodable body is uncertain (D17). The command
sends no further write for that list and settles the uncertain write by a
read, within the same 120-second budget:

- a value write goes to its phase's read-back. If the read-back observes the
  phase's expected set, the write evidently applied: the phase is verified
  and the run continues. If not, because the write did not apply or because
  later chunks were never sent, the list ends `unknown`;
- a container create or update reads `GET /api/lists?id=`. If the container
  exists with the planned `type`, `name`, `description`, and `meta`, the
  write is verified and the run continues; anything else ends the list
  `unknown`.

A 4xx other than the item-delete 404 is not uncertain: Kibana refused the
request, and the list ends `failed` without a read-back.

**Recovery.** A list that ended `unknown` may still change: an import Kibana
accepted can become visible later (V5). Re-running `push` at once could add
the same values again, and duplicates count toward D12 (V12). After
`unknown`, wait, run `diff`, and push again only when its preview is what
you expect. The wiki says so.

### 6.5 Delete

`DELETE /api/lists?id=<id>` with no reference flags. Kibana deletes the
values with the container; they can stay visible to item reads for about two
seconds after the 200 (V13).

- A 409 means exception items use the list. Its body, the same on 9.5.1,
  9.5.6, and 9.7.0 (recorded fixture `container_delete_referenced`), is
  `{"message":{"error":{"message", "references", "value_list_id"}},
  "status_code":409}`, where each entry of `references` pairs the full
  `exception_item` with its `exception_list`. The command reports `conflict`
  with Kibana's status and names each referencing item by its `list_id`,
  `item_id`, and `namespace_type`. A 409 whose body lacks
  `message.error.references` is still `conflict`, with Kibana's message and
  no names. It never sends `deleteReferences` or `ignoreReferences`. The body
  comes through `delete_once_response` (section 8.1), since the shared error
  path drops it.
- A 404 before the preview is `not_found`.
- A 5xx, a timeout, or an undecodable answer is `unknown` (D17). The command
  then reads `GET /api/lists?id=`: a 404 records the delete as applied, and
  anything else ends with an `http` error saying the outcome is unknown.

### 6.6 Init

`value-lists init` reads `GET /api/lists/index`. When both streams exist it
reports "already bootstrapped" and writes nothing. Otherwise it previews the
space-wide change and, with `--yes`, sends
`POST /api/security_solution/initialize` with
`{"flows":["create-list-indices"]}` (D18). Success needs a 2xx whose body
reports that flow as `ready`, and a following `GET /api/lists/index` with
both streams true. Anything else is an `http` error with the flow's status.

### 6.7 Outcomes

| Answer to a write | Outcome of that list |
| --- | --- |
| Every phase verified by read-back, whatever the answers to its writes | `applied` |
| 409 | `failed`, kind `conflict` |
| Other 4xx | `failed`, with Kibana's message and status |
| A phase or a container write not verified within its budget | `unknown`, with what the last read observed (section 7.5) |
| Not attempted because an earlier list failed or is unknown | `not_reached` |

A command that writes several lists stops at the first `failed` or `unknown`
list. It still returns the outcome of every list: applied, the one that
stopped it, and every `not_reached` one. The CLI renders and publishes that
evidence (section 7.5), then exits 1 with the error of the list that stopped
it.
