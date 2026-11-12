[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 2. Decisions

D1 to D10 are the owner's answers of 2026-11-12 to the research questions.
The rest follow from the measurements V1 to V11.

| Id | Decision | Reason |
| --- | --- | --- |
| D1 | The command group is `value-lists`. | `lists` already names exception containers in code and docs. |
| D2 | `state pull` writes every value list a mirrored exception item references, by default. | A mirror that references a list it cannot restore cannot be promoted to another stack. |
| D3 | A list's values live in `value-lists/<id>.txt`, one per line, sorted and unique, beside `value-lists/<id>.yaml`. | It diffs well in git and is Elastic's own import format. |
| D4 | `state push` refuses when an exception entry names a list that is in neither the mirror nor the stack, or whose type differs from the entry's `list.type`. | With `is not in list`, a dangling reference suppresses every event that has the field (V7). The rule engine queries by the entry's type. |
| D5 | Live probes on the Cloud trial targets restore "not bootstrapped" when they started that way. | Runs end at baseline. |
| D6 | Bootstrap is a guarded `value-lists init`. `state push` never bootstraps. | It is a space-wide change and should be asked for by name. |
| D7 | Four types only: `keyword`, `ip`, `ip_range`, `text`. | The documented UI types, and the only ones exceptions use in practice. |
| D8 | Values are reconciled exactly, deletes included. | Removing a value is how an exception narrows, as for exception items (shared design 5.4). |
| D9 | No MCP tools in 0.10.0. | Keeps the release to the CLI and the state contract. |
| D10 | No cap on large value diffs in 0.10.0; the guard shows adds and deletes per list. | V9: a 100,000-value list exports in 9 to 15 s. Revisit if a real mirror needs it. |
| D11 | An `ip_range` value that is one address is written in CIDR form, `/32` or `/128`. | Kibana stores a bare address as `x-x` (V4), and more than 200 dash entries make an exception suppress every event on 9.5.1, 9.5.6, and 9.7.0 (V11). CIDR avoids it (V11, control d). |
| D12 | An `ip_range` list with more than 200 dash-form values is refused for writes and flagged on reads. | The over-suppression is silent: no preview warning and no error (V11). |
| D13 | Values are added through `_import` with only the missing values, and removed by value. A full set is never re-imported. | Import appends and duplicates a value on a second import (V5). |
| D14 | Every value write is followed by a bounded read-back until the remote set equals the planned set. | Import is asynchronous (V5) and delete by value is not read-after-write (V9). A 200 proves nothing about stored values. |
| D15 | A type change is refused locally and never sent. | PUT with a new `type` answers 200 and ignores it (V6). |
| D16 | Container updates send the `_version` read before the preview. | PATCH with a stale `_version` is 409 (V6), so a change made between the preview and the apply is caught. Item writes do not move the container version, so values are protected by the read-back instead. |
| D17 | A 5xx, timeout, or undecodable answer to a write is `unknown` until a read settles it. | Deleting a 100,000-value list answered 500 after 30 s on Serverless and still completed (V9). |
| D18 | Bootstrap uses `POST /api/security_solution/initialize` with the `create-list-indices` flow. | `POST /api/lists/index` is deprecated and answers with a `Warning: 299` pointing to it (V2). The flow is 200 and idempotent for a scoped key on all three flavors. |
| D19 | Content is read through `_export`; containers through `_find` with `cursor`. | Export returns every value in one response (V8); offset paging fails at page 101 (V9). |
| D20 | `diff` gains a `value_lists` block, and `clean` requires it. | The same shape as the 0.2 `exceptions` block. Narrowing `clean` is a break under shared design 11.1, so it lands in a minor version. |
