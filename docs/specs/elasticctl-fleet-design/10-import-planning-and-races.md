[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 10. Import planning and races

Import reads and structurally validates the whole file before any server call.
It rejects duplicate ids and duplicate names in the artifact, then performs
the semantic and dependency reads required by sections 5-8. A dry run performs
the same authenticated reads and builds the same plan as apply; it differs
only by stopping at the guard.

With neither conflict flag, any existing id or conflicting unique name fails
the plan before the guard. `--skip-existing` reports and removes existing ids.
`--overwrite` classifies each row as create, replace, or unchanged. A name
owned by another id is always conflict. An unchanged row counts in `total`, is
rechecked at apply, and is never written.

The plan retains canonical file specs; normalized existing snapshots; parent
flags, ids, attached integration ids, and agent counts; exact package-status
snapshots; implicit installs; and the profile, host, and active space.

Preview reports every action plus affected parent policies and agent count.
Because Fleet distributes changes to enrolled agents, blast radius is part of
the mutation contract.

Apply does not reread the file. Immediately before each write it repeats the
relevant object, parent, count, and package reads:

- planned create refuses if its id or name appeared;
- replace or unchanged refuses if its object, agent count, or attached
  integration ids changed;
- integration refuses if a parent, count, or package version changed; and
- a monitoring transition refuses if the `elastic_agent` package snapshot
  changed, comparing `status` and the installed version only, because the
  registry's `latestVersion` moves on its own; and
- a missing planned replacement is conflict, not create.

The routes expose no conditional-write token, so a change can still race the
final recheck and write. Reports name this unavoidable window.

Rows apply in stable-id order. Create and replace send the complete desired
spec under sections 5.3 and 6. After each decoded mutation success, import GETs
the object, normalizes it, and requires exact equality with the filled desired
spec. A mismatch is failed with `applied: true`. Successful earlier writes are
not rolled back. Multi-object imports continue across independent failures; a
dependency failure blocks only dependent rows.
Affected agents are the sum over the union of parent ids for every row whose
mutation route returned decoded success, including a row that later fails
post-write verification.

After any agent-policy write that could trigger the internal monitoring
package installation, apply re-reads package state. The installation is an
observation, never a requirement: Fleet's create path treats an install error
as non-fatal, and a replace installs only from an absent stored value. A
result that became `installed` must carry a non-empty resolved version, which
is reported as `elastic_agent@<version>`; a package that stays absent is not
an error. A decoded policy success followed by a failed or malformed package
read is failed with `applied: true`. A policy error is still reported as
failed, but the package read records any installation that occurred before
Fleet rejected the policy. elasticctl never swallows the package read or rolls
the package back.

