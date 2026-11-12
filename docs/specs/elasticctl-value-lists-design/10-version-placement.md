[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 10. Version placement

| Version | Deliverable | Evidence before it ships |
| --- | --- | --- |
| 0.9.4 | `state pull`, `state diff`, and `state push` refuse a mirror that holds `value-lists/` (D21) | Offline tests of the refusal; the thirteen-contract matrix is unaffected, because no current mirror holds the directory |
| 0.10.0 | The `value-lists` commands, the state engine changes, the three transport calls, the `doctor` text, the recorded fixtures, the spec changes of section 8.4, and the fourteenth contract | Fixtures from three flavors; the offline tests of section 9.2; snapshots; an independent adversarial review of the write and reconcile path; the fourteen-contract matrix on three flavors; a whole-range review |

0.9.4 ships first, so a team can move its 0.9 users onto a binary that
refuses a 0.10 mirror before anyone writes one.

Read-only MCP tools for value lists, if the owner wants them, are a later
0.10 patch with its own design addendum (D9).

The V12 measurements, the recorder pass, and the live passes need the current
trial targets, so they run first. If the targets end before a release's live
evidence is in, that release waits for replacement targets; the gates are not
lowered (shared design 11).

The `clean` change of D20 and the D4 refusals make 0.10.0 a minor release
under shared design 11.1.
