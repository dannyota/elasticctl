[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 2. Decisions

D1 to D10 are the owner's answers of 2026-11-12 to the research questions,
and D21 the owner's answer on older binaries. The rest follow from the
measurements and from the design review of the first draft.

| Id | Decision | Reason |
| --- | --- | --- |
| D1 | The command group is `value-lists`. | `lists` already names exception containers in code and docs. |
| D2 | `state pull` writes every value list a mirrored exception item references, by default. | A mirror that references a list it cannot restore cannot be promoted to another stack. |
| D3 | A list's values live in `value-lists/<stem>.txt`, one per line, sorted and unique, beside `value-lists/<stem>.yaml`. | It diffs well in git and is Elastic's own import format. |
| D4 | `state push` refuses when an exception entry names a list that is in neither the mirror nor the stack, or whose type differs from the entry's `list.type`. | With `is not in list`, a dangling reference suppresses every event that has the field (V7). The rule engine queries by the entry's type. |
| D5 | Live probes on the Cloud trial targets restore "not bootstrapped" when they started that way. | Runs end at baseline. |
| D6 | Bootstrap is a guarded `value-lists init`. `state push` never bootstraps. | It is a space-wide change and should be asked for by name. |
| D7 | Four types only: `keyword`, `ip`, `ip_range`, `text`. | The documented UI types, and the only ones exceptions use in practice. |
| D8 | Values are reconciled exactly, deletes included. | A value list is suppression policy; the mirror must express every change. |
| D9 | No MCP tools in 0.10.0. | Keeps the release to the CLI and the state contract. |
| D10 | No cap on value diffs. The preview lists every value to add and to remove. | The owner's answer: a value hidden from the preview is a change made without review. |
| D11 | An `ip_range` value that is one address is written in CIDR form, `/32` or `/128`. | Kibana stores a bare address as `a-a` (V4), and more than 200 dash entries make an `is in list` exception suppress every event on 9.5.1, 9.5.6, and 9.7.0 (V11). CIDR avoids it (V11, control d). |
| D12 | No write may leave, or pass through, an `ip_range` list holding more than 200 stored dash values, counting duplicates. Reads flag such a list. | The over-suppression is silent (V11). Whether Kibana counts stored items or distinct values is not yet measured, so the stored count is the safe one. |
| D13 | Values are added through `_import` with only the missing values, and removed by value. A full set is never re-imported. | Import appends and duplicates a value on a second import (V5). |
| D14 | A value change runs in two phases, removes and adds, and each phase is verified by read-back before the next starts. | Import is asynchronous (V5) and delete by value is not read-after-write (V9). A 200 proves nothing about stored values. |
| D15 | A type change is refused locally and never sent. | PUT with a new `type` answers 200 and ignores it (V6). |
| D16 | Container updates send the `_version` read at apply time. Concurrent value writers are not detected; the design states it. | PATCH with a stale `_version` is 409 (V6), but item writes do not move the container version, and import is asynchronous, so no read proves the absence of another writer. |
| D17 | A 5xx, timeout, or undecodable answer to a write is `unknown` until a read settles it. | Deleting a 100,000-value list answered 500 after 30 s on Serverless and still completed (V9). |
| D18 | Bootstrap uses `POST /api/security_solution/initialize` with the `create-list-indices` flow. | `POST /api/lists/index` is deprecated and answers with a `Warning: 299` pointing to it (V2). The flow is 200 and idempotent for a scoped key on all three flavors. |
| D19 | Content is read through `_export`; containers through `_find` with `cursor`. | Export returns every value in one response (V8); offset paging fails at page 101 (V9). |
| D20 | `diff` gains a `value_lists` block, and `clean` requires it. | The same shape as the 0.2 `exceptions` block. Narrowing `clean` is a break under shared design 11.1, so it lands in a minor version. |
| D21 | 0.9.4 refuses `state diff` and `state push` on a mirror that holds `value-lists/`. 0.9.0 to 0.9.3 cannot be changed, which is a recorded known limit. | The owner's answer. An older binary pushes the exceptions of a 0.10 mirror and skips its value lists, leaving stale values on the stack. |
| D22 | The phase order follows how the mirror uses the list: removes first when every reference is `is in list`, adds first when every reference is `is not in list`. Mixed or unknown use is removes first, and the preview says which references may briefly suppress more. | The transient between phases then suppresses less, never more: a detection fires rather than hides. |
| D23 | `state pull` refuses, writing nothing, when a referenced list is missing, has an unsupported type, or does not match the entry's type. | Writing "no file" would keep an older pair in an existing mirror, and a later push could recreate a deleted list from stale values. |
| D24 | One selected set of value lists drives `diff`, the preview, the checks, and the apply: the lists referenced by the selected exception containers. A local pair outside it is reported and never written. | A scoped run must not change suppression outside its selection (shared design 5.4). |
| D25 | A value-list file stem is bounded and unique without regard to case (section 7.2). | A 512-byte `id` passes the file name limit of common file systems, and `A` and `a` collide on case-insensitive ones. |
