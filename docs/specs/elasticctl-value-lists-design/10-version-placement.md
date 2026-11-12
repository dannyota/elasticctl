[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 10. Version placement

| Version | Deliverable | Evidence before it ships |
| --- | --- | --- |
| 0.10.0 | The `value-lists` commands, the state engine changes, the two transport calls, the `doctor` text, the recorded fixtures, and the spec changes of section 8.4 | Fixtures from three flavors; the offline tests of section 9.2; snapshots; an independent adversarial review of the write and reconcile path; one live pass of `value_list_round_trip` on three flavors |
| 0.10.1 | The fourteenth contract registered in the controller, the validator, and `live-lab.yml` | The fourteen-contract matrix on three flavors; a whole-range review |

Read-only MCP tools for value lists, if the owner wants them, are a later
0.10 patch with its own design addendum (D9).

The recorder pass and the live pass need the current trial targets, so they
run first. If the targets end before a release's live evidence is in, that
release waits for replacement targets; the gates are not lowered (shared
design 11).

The `clean` change of D20 and the D4 refusal make 0.10.0 a minor release
under shared design 11.1.
