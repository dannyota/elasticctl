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
references (the 409 body), and the 413, 415, and 409 refusals. It restores
"not bootstrapped" where it started so (D5). The recorded set replaces the
404 `lists_index.json` fixtures as the only value-list evidence.

### 9.2 Offline tests

Tests drive the real `-api` and CLI code against wiremock, with exact request
assertions:

- parsing and validation: each step of section 3.4 and each row of 5.1, each
  accepted and refused spelling of section 3.5, CRLF and unsorted input, and
  a value too large for one request;
- the dash rule: final and between-phase counts at 200 and 201, duplicates
  counted, and a repair that lowers an existing count;
- reconciliation: remove only, add only, both, and nothing; each D22 order
  for `included`, `excluded`, and mixed references; packing at the
  8,000,000-byte bound; a 409, a 4xx, and a 5xx at each write;
- read-back: a phase verified on the first read, after several reads, and
  never, with `unknown`, no second import, and no later phase or list; a
  slow export that uses the budget;
- the guard: the complete text preview, the JSON preview object, and a list
  that changed between preview and apply;
- state: the selected set in full and scoped runs, `unreferenced` pairs, the
  stem rule and case-insensitive collisions, a half pair, the `pull` refusal
  of D23, the `value_lists` diff block and `clean`, the D4 and D12 refusals
  on unchanged items and stack-only lists, the apply order, the container
  re-read before exception writes, and the report for every outcome;
- `delete`: the 409 with `references`, the 5xx followed by a 404 read, and no
  reference flag on any request;
- `init`: already bootstrapped, bootstrapped by the flow, and a flow that is
  not `ready`;
- `doctor`: the new message, byte for byte.

CLI snapshots cover the help and the `commands` tree. Existing snapshots and
tests change only where this design says so.

### 9.3 Live contract

0.10.0 adds a fourteenth conformance contract, `value_list_round_trip`, an
ignored live test with the same name, registered in the controller, the
validator (a `v0.10` list), and the `live-lab.yml` gate. On each flavor it:

1. checks the baseline and records whether the list data streams exist, and
   runs `value-lists init` when they do not;
2. creates a marker index with controlled events, a marker `ip_range` list
   and a marker `keyword` list, an exception container whose items use them
   with `is in list` and `is not in list`, and a disabled marker rule that
   references the container;
3. runs `state pull` scoped to that rule and checks that the mirror holds
   both value-list pairs with their values;
4. edits the values files (an add, a remove, and a bare address), runs
   `state push`, and checks the read-backs and the exact remote sets;
5. previews the rule over the marker events and checks which events alert,
   for both operators, before and after the edit, because V11 showed stored
   values that look right while suppression is wrong;
6. checks the refusals: a missing list, a type mismatch, and a 201-dash list,
   with no write on the stack;
7. checks that `value-lists delete` reports the 409 and its references for a
   referenced list;
8. deletes every marker object by exact id, deletes the data streams when it
   bootstrapped them and no other list exists, and checks the baseline.

The self-managed leg runs in `live-lab.yml` (mutation design D35).
