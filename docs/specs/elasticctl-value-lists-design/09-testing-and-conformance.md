[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 9. Testing and conformance

### 9.1 Fixtures

Every offline test copies a recorded response ([testing](../../../instructions/testing.md)).
The recorder gains a value-list pass on Serverless, Hosted, and the lab,
using marker lists with the `elasticctl-live-vl-` prefix. It records the
bootstrap state before and after `init`, container create, read, PATCH with
current and stale `_version`, the ignored type change, `_find` pages by
cursor, `_export` with duplicates and an `a-a` value, `_import` (the list
body), item `_find` pages by cursor, item delete by `id` (200 and 404), container
`_find` pages by `filter` and `cursor`, exception items whose `list` entries
use `included` and `excluded`, an `ip_range` list holding `10.0.0.0/8` beside
an address it contains, container delete with and without
references (the 409 body), and the 413, 415, and 409 refusals. It restores
"not bootstrapped" where it started so (D5). The recorded set replaces the
404 `lists_index.json` fixtures as the only value-list evidence.

Recorder cleanup treats 4xx except 408 as definite refusals. A 408 retains
pending creates and imports: an early 404 cannot prove a create absent, and
an import with an unknown final count blocks parent deletion and bootstrap
restoration. A create 409 proves an existing object that the session does
not own.

### 9.2 Offline tests

Tests drive the real `-api` and CLI code against wiremock, with exact request
assertions. Every mock response body is a recorded one, with two exceptions
for answers no stack can be made to give on demand:

- an `initialize` flow that is not `ready`: the test takes the recorded
  `initialize` response and changes only the flow's status value, and its name
  says so;
- faults: a 5xx status, a timeout, a connection reset, or a body that does not
  decode is injected by the test. The status or the failure is synthetic; any
  body it carries is a recorded one, and the test name says it injects a
  fault.

A production request that cannot be filtered to marker objects on a shared
stack, such as the unfiltered scan of D26, is recorded with a marker filter.
Its test asserts the production request and serves the recorded body.

The cases:

- parsing and validation: each step of section 3.4 and each row of 5.1, each
  accepted and refused spelling of section 3.5, CRLF and unsorted input, and
  a value too large for one request;
- the dash rule: final and between-phase counts at 200 and 201, duplicates
  counted, the projection of section 5.2 (199 distinct values stored 200
  times, one removed and two added, refused at 201), and a repair that lowers
  an existing count;
- the two codec levels: pull, then validate, then push of a list holding each
  V12 spelling unchanged, including two spellings of one address, the
  refusal to add a non-canonical value, and a bare `ip_range` address read
  as CIDR;
- the empty rule: a referenced list emptied finally or between phases, the
  `{a}` to `{b}` replacement under `is in list` (adds first, never empty),
  and creating a list that an installed reference names;
- reconciliation: remove only, add only, both, and nothing; each D22 order
  for installed `included`, `excluded`, mixed, and absent references found by
  the D26 scan, including references outside the selection; packing at the
  8,000,000-byte bound; a 409, a 4xx, and a 5xx at each write;
- uncertain writes: a 5xx import or delete followed by a matching read-back
  (verified, run continues) and by a non-matching one (`unknown`, run stops);
  a 5xx create or PATCH settled by the container read either way; an
  item-delete 404 that continues; every export failing after an uncertain
  write, with `observed: false`;
- the remove phase: every stored copy deleted by `id`; an `ip_range` list
  holding `10.0.0.5/32` and `10.0.0.0/8` (the recorded `contain_*` set) where
  only the first leaves, with no request naming a value; an item `_find` that
  disagrees with the last read before the phase, refused as `conflict` before
  any delete;
- the scan of D26: a reference outside the selection, both namespaces, a
  container it cannot read, an undecodable entry, and installed references
  that change between the preview and the apply;
- read-back: a phase verified on the first read, after several reads, and
  never, with `unknown`, no second import, and no later phase or list; a
  slow export that uses the budget;
- the guard: the complete text preview, the JSON preview object, and a list
  that changed between preview and apply;
- state: the selected set in full and scoped runs, `unreferenced` pairs, the
  stem rule with case-insensitive collisions, long and non-ASCII ids, and
  Windows device names, a half pair, the `pull` refusal of D23, the
  `value_lists` diff block and `clean`, the D4 and D12 refusals on unchanged
  items, retained containers, and stack-only lists, a reference whose list
  has no source, the D27 refusal for an added, removed, replaced, and changed
  reference, for another entry of a referencing item, for a second list of
  that item, for an item that references the list twice, and for a rule that
  drops a shared container in the same run, and its allowed first-creation
  case, with the refusal when that run also detaches a rule from a container
  receiving the first reference, the apply order, the
  container re-read
  before exception writes, and the report and summary for every outcome,
  including the example of section 7.5;
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
