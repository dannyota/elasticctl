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
container with `GET /api/lists?id=` and the values with
`POST /api/lists/items/_export?list_id=`. The preview is computed from these
reads.

At apply, after `--yes`, the command reads each list again. If a container's
`_version` or its distinct value set differs from the preview's read, it
stops with `conflict` before its first write and asks for a re-run.

### 6.2 Create

`POST /api/lists` with `id`, `type`, `name`, `description`, and `meta` when
present. A 409 means the `id` exists and is reported as `conflict`. The
values are then added as in 6.3.

### 6.3 Update and exact reconciliation

The container's `name`, `description`, and `meta` are updated with
`PATCH /api/lists`, carrying the `_version` from the apply-time read (D16).
A 409 is `conflict`. A changed `type` never reaches the stack: it is refused
before the preview (D15), with `conflict` naming both types. Recreating the
list under the new type is a `delete` and an `import`, each asked for by
name.

Values are compared as distinct canonical sets (section 3.4):

- **Add** the local values missing remotely with
  `POST /api/lists/items/_import?list_id=<id>`. The multipart field is `file`,
  its file name `<id>.txt`, its body the missing values joined by LF with a
  trailing LF. A body that would pass 8,000,000 bytes is split into several
  imports, which keeps each request under Kibana's 9,000,000-byte limit (V5)
  with room for the multipart framing.
- **Remove** each remote value missing locally with
  `DELETE /api/lists/items?list_id=<id>&value=<value>`, one request per value.
  The answer is an array of the deleted items (V9); a 404 means the value is
  already gone and is left to the read-back.

Adds go before removes, so a list being replaced never passes through empty
while an exception points at it.

### 6.4 Read-back

After its writes to a list, the command exports the list again, once per
second, until the distinct remote set equals the planned set, for at most 120
seconds. V5 measured 100,000 imported values settling in 6 to 9 seconds.

A match records the list as verified. No match at the deadline records it as
`unknown`, with the counts of values still missing and still present, and
the command ends with an `http` error naming the list and both counts. The
read-back only reads: it never sends a second import, which could duplicate
values.

### 6.5 Delete

`DELETE /api/lists?id=<id>` with no reference flags. Kibana deletes the
values with the container.

- A 409 with `references` means an exception item uses the list. The command
  reports `conflict` and names each referencing item by `list_id` and
  `item_id`. It never sends `deleteReferences` or `ignoreReferences`.
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

| Answer to a write | Outcome |
| --- | --- |
| 2xx, then a matching read-back | applied |
| 409 | `conflict`, nothing further sent for that list |
| Other 4xx | failed with Kibana's message and status; nothing further sent for that list |
| 5xx, timeout, connection loss after sending, or an undecodable body | `unknown`; the read-back or a read of the container decides |

A command that writes several lists stops at the first failed or unknown
list and reports the lists it did not reach as not applied.
