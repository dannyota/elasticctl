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

At apply, after `--yes`, the command reads each list again. If a container's
`id`, `type`, or `_version`, or its stored values, differ from the preview's
read, it stops with `conflict` before its first write and asks for a re-run.

**Concurrency limit.** Nothing locks a list. Item writes do not move the
container's `_version` (V6), and another writer's import can become visible
after this command's read-back matched (V5). Two writers to one list must be
coordinated outside elasticctl. The design says so in the wiki and does not
present the read-back as proof that no one else wrote.

### 6.2 Create

`POST /api/lists` with `id`, `type`, `name`, `description`, and `meta` when
present. A 409 means the `id` exists and is reported as `conflict`. The
values are then added as the add phase of 6.3, with nothing to remove.

### 6.3 Update and exact reconciliation

The container's `name`, `description`, and `meta` are updated with
`PATCH /api/lists`, carrying the `_version` from the apply-time read (D16).
A 409 is `conflict`. A changed `type` never reaches the stack: it is refused
before the preview (D15), with `conflict` naming both types. Recreating the
list under the new type is a `delete` and an `import`, each asked for by
name.

Values are compared as sets (section 3.6). The change runs in two phases
(D14), in the order of D22:

- **Remove phase.** For each value in the remote set and not in the local
  set: `DELETE /api/lists/items?list_id=<id>&value=<stored value>`. The
  answer is an array of the deleted items, every copy of the value (V9). A 404
  means the value is already gone and is left to the read-back.
- **Add phase.** For the values in the local set and not in the remote set:
  `POST /api/lists/items/_import?list_id=<id>`, with the multipart field
  `file`, the file name `<stem>.txt`, and the values joined by LF with a
  trailing LF. Values are packed into requests of at most 8,000,000 bytes of
  body, split only between whole lines; section 5.1 refuses a single value
  that cannot fit. The bound keeps each request under Kibana's 9,000,000-byte
  limit (V5) with room for the multipart framing. Requests go one at a time.

D22 picks the order from the references installed on the stack, found by
the scan of D26 before the preview: removes first when every installed
reference is `included`, adds first when every one is `excluded`, and removes
first when both are in use or none is, in which case the preview names each
`excluded` reference that may briefly suppress more. `state push` and
`value-lists import --overwrite` use the same scan. `state push` writes
values before exception items, so the installed references are the ones in
force while the values change; D27 refuses a run that would change both a
list's values and a reference to it. The between-phase state of section 5.2
is the remote set less the removes, or the remote set plus the adds.

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
sends no further write in that phase and goes straight to the phase's
read-back. If the read-back observes the phase's expected set, the uncertain
write evidently applied: the phase is verified and the run continues. If it
does not, because the write did not apply or because later chunks were never
sent, the list ends `unknown`. A 4xx is not uncertain: Kibana refused the
request, and the list ends `failed` without a read-back.

### 6.5 Delete

`DELETE /api/lists?id=<id>` with no reference flags. Kibana deletes the
values with the container.

- A 409 carries `references`, the exception items that use the list. The
  command reports `conflict` with Kibana's status and names each referencing
  item by `list_id` and `item_id`. It never sends `deleteReferences` or
  `ignoreReferences`. This needs the 409 body, which the shared error path
  drops; section 8.1 adds the transport call that keeps it.
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
| A phase not verified within its budget, after an uncertain write or not | `unknown`, with the observed set's missing and extra counts |
| Not attempted because an earlier list failed or is unknown | `not_reached` |

A command that writes several lists stops at the first `failed` or `unknown`
list. It still returns the outcome of every list: applied, the one that
stopped it, and every `not_reached` one. The CLI renders and publishes that
evidence (section 7.5), then exits 1 with the error of the list that stopped
it.
