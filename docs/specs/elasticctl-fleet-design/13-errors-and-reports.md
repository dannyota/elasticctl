[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 13. Errors and reports

- `not_found`: selector, target, parent, or exact package missing.
- `conflict`: ambiguous selector, existing import id, duplicate name, changed
  snapshot, different installed package version, or unsafe delete.
- `unsupported`: hosted agent policy or managed integration, platform flag,
  environment reference, cross-space policy, protected policy, secret, package
  change, or an overwrite that removes a field the update route cannot clear.
- `permission`: a single-object agent-policy read without `agents`, which
  Kibana populates only for a caller with Fleet agents read.
- `http`: malformed success response, paging contradiction, inconsistent
  selector read, or failed post-write invariant.
- `error`: malformed artifact or invalid command combination.

List and get return typed values through `render`. A truncated list emits
`capped at <limit> rows` on stderr while the typed API result retains
`truncated: true`. Validate returns `{valid, total}`. Export with `--out`
returns `{exported, path, failed}`; without it, stdout is the artifact.

Import reports `{applied, succeeded, unchanged, skipped, failed, total,
affected_agents, package_installs}`. Delete reports `{applied, deleted, failed,
total, affected_agents}`; each failed delete row also carries `applied`, with
the same meaning as an import row's. Each agent belongs to one agent policy, so
summing counts across distinct affected parents does not double-count agents.
A non-empty failed collection exits 1.

`package_installs` uses exact `name@version` coordinates for integration
dependencies. A planned internal monitoring installation is reported as
`elastic_agent@server-selected` because the agent-policy API does not accept a
version. Apply rechecks the resolved installed version after create.

A row's `applied` becomes true only after a mutation route returns a decoded
success. It does not claim that a timeout made no remote change. No report
contains a secret, secret-reference id, compiled policy, username, or
unselected integration configuration.

