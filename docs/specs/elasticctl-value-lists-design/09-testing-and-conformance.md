[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 9. Testing and conformance

### 9.1 Fixtures

Every offline test copies a recorded response ([testing](../../../instructions/testing.md)).
The recorder gains a value-list pass on Serverless, Hosted, and the lab,
using marker lists with the `elasticctl-live-vl-` prefix. It records the
bootstrap state before and after `init`, container create, read, PATCH with
current and stale `_version`, the ignored type change, `_find` pages by
cursor, `_export` with duplicates and an `a-a` value, `_import` (the list
body), delete by value (the array), container delete with and without
references, and the 413, 415, and 409 refusals. It restores "not
bootstrapped" where it started so (D5). The recorded set replaces the 404
`lists_index.json` fixtures as the only value-list evidence.

### 9.2 Offline tests

Tests drive the real `-api` and CLI code against wiremock, with exact request
assertions:

- validation: each row of section 5.1, the dash-value refusal at 201 and
  acceptance at 200, CIDR conversion of bare addresses, CRLF and unsorted
  input;
- reconciliation: add only, remove only, both, nothing; chunking at the
  8,000,000-byte bound; adds before removes; a 409 and a 5xx at each write;
- read-back: a set that matches on the first read, after several reads, and
  never, with the `unknown` outcome and no second import;
- the guard: the preview's counts and first twenty values, and a list that
  changed between preview and apply;
- state: the closure, the layout and name collisions, a half pair, the
  `value_lists` diff block, `clean`, the D4 refusals, the apply order, scoped
  runs, and the report entries;
- `delete`: the 409 with references, the 5xx followed by a 404 read, and no
  reference flag on any request;
- `init`: already bootstrapped, bootstrapped by the flow, and a flow that is
  not `ready`;
- `doctor`: the new message, byte for byte.

CLI snapshots cover the help and the `commands` tree. Existing snapshots and
tests change only where this design says so.

### 9.3 Live contract

0.10 adds a fourteenth conformance contract, `value_list_round_trip`, an
ignored live test with the same name. On each flavor it:

1. checks the baseline and records whether the list data streams exist;
2. runs `value-lists init` when they do not;
3. imports a marker `ip_range` list and a marker `keyword` list, and an
   exception container whose items reference them with `is in list`;
4. runs `state pull`, edits the values file (adds, removes, a bare address),
   runs `state push`, and checks the read-back and the exact remote set;
5. checks that `state push` refuses a missing list and a type mismatch, and
   that `value-lists delete` reports the 409 for a referenced list;
6. deletes the marker objects by exact id, deletes the data streams when it
   bootstrapped them and no other list exists, and checks the baseline.

The controller and validator gain the contract and a `v0.10` list. The
self-managed leg runs in `live-lab.yml` (mutation design D35).
