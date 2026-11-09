[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 14. Fixtures and conformance

Fixtures are recorded from real traffic for Serverless, Hosted, and
self-managed deployments. Every created id and name starts with
`elasticctl-sample-`. Each recording session creates a nonce kept in memory
for ownership proof and embeds it in the live parent and integration
descriptions; the duplicate create probe reuses that nonce. Fixed marker ids
are preflighted as absent. After an ambiguous create error, an exact GET may
claim cleanup only when the live object carries this session's nonce and all
strict marker state matches; another session's nonce is never deleted. Normal
update preserves the session nonce. Fixture reducers replace nonce-bearing
descriptions with fixed public descriptions, so public fixtures stay
deterministic. The recorder deletes integrations before agent policies.
Every integration-policy marker POST, PUT, and DELETE is one-shot, including
its cleanup, and uses an HTTP client with redirects and protocol-level retries
disabled. Connection pooling is also disabled so a canceled request cannot be
retried on a fresh connection after an idle pooled connection fails. A
redirect, 429, 5xx, timeout, connection failure, malformed success response,
or HTTP/2 retry signal never replays the mutation. Create ambiguity uses the
exact nonce-bound GET above. Update and delete ambiguity retains ownership for
cleanup, whose fresh exact GET either proves the same nonce-bearing object,
observes it absent, or refuses mutation. This prevents a retry or redirect
from overwriting or deleting a different object that reused the fixed id after
the first request committed.

The installed-package inventory request uses `perPage=1000`. The recorder
accepts `searchAfter` as the route's last-item sort cursor, not as proof of a
second page. It validates at most two string, number, or boolean sort values
and proves the response is complete by requiring `total <= 1000` and
`items.len() == total`. The cursor never enters a fixture.

The package-metadata reducer retains only the exact coordinate and status,
package variables, template names, optional template data-stream selectors,
input types and variables, and modern or legacy stream input, dataset, and
variable definitions. It normalizes absent variable arrays to empty arrays and
absent `secret` flags to false, sorts every retained collection by its stable
key, and rejects malformed or ambiguous joins. Values and every unrelated
registry, identity, host, space, or secret-reference field are dropped when
the fixture is constructed.

Fleet setup is idempotent and required before the first Fleet read on a fresh
stack. The recorder and the conformance runner call `POST /api/fleet/setup`
once per session. The self-managed lab's Kibana container must reach the
Elastic package registry, or no package can be installed there; `lab/` gains
no other Fleet configuration.

Recording requests are exact-id or exact-marker queries. No unscoped policy
list or full-policy response enters a public fixture. The recorder strictly
decodes responses, requires every policy to be an owned marker, and scrubs
usernames, timestamps, secret references, space ids, deployment details, and
unrelated package inventory. Marker agent policies use empty
`monitoring_enabled`, so recording never installs `elastic_agent`. The 0.6.1
recorder requires the exact `system` package to be preinstalled before it
writes marker objects. It never installs, uninstalls, upgrades, or downgrades
packages; it retains the baseline inventory only to prove the exact status
version is already present and to audit that inventory is unchanged.

Immediately before each package-policy create, including bootstrap and
duplicate-name probes, the recorder rechecks that exact installed `system`
version and the complete baseline inventory. Missing, changed, malformed, or
unreadable package state stops the create. A final read-to-write race remains
because Fleet provides no conditional package-policy create; the post-attempt
inventory audit still runs to detect a change in that window.
The recorded exact package metadata must also report `installed`.

The integration recorder materializes `system` defaults without weakening the
round-trip fixture. After reducing exact package metadata and creating the
marker parent, it creates a nonce-owned bootstrap integration with
`inputs: {}`. A fresh exact GET must preserve the complete marker identity.
The production export path must then accept that exact marker, its parent, and
its exact package metadata, which proves that the materialized simplified
input map is portable and contains no configured secret. The recorder deletes
the bootstrap integration once, proves it absent and the parent detached, then
uses the exported complete input map for the recorded create. The recorded
create response and later reads must equal that map exactly. Bootstrap create
and delete use the same replay-free one-shot transport and nonce ownership as
the recorded lifecycle. Public fixtures retain only this recorder-owned,
production-classified nonsecret configuration; they never retain another
policy's values.

0.6.0 fixtures cover Fleet setup, agent-policy not found, the read-only
`elastic_agent` package status that drives the monitoring preflight,
explicit-id create, get with its agent count, the marker-scoped paginated
list, name conflict, update, the omitted-field update that measures the
merge, delete, and delete not found. The recorded create request and response
prove the normalized round trip and the default table on every flavor.
Attached integrations arrive with the 0.6.1 fixtures. Platform-owned refusals
have offline unit coverage only, because a public fixture never holds a
non-marker policy.

0.6.1 live fixtures cover a simplified integration-policy lifecycle: missing
integration and parent selectors, exact `system` package status and reduced
package metadata, marker-parent creation, explicit-id integration create,
simplified get and list, name-conflict classification, parent attachment
observation, update, normalized round trip, explicit integration delete and
delete-not-found, then parent delete and parent-delete-not-found. The recorder
deletes the integration before the parent and never asks Fleet to delete an
attached parent. It requires preinstalled exact `system` and never mutates
package inventory. Absent-package behavior, managed or hosted refusals, secret
refusals, and package-version conflict remain source-derived with offline
planner coverage unless a safe live recording proves them.

0.6.2 adds the tenth conformance contract,
`fleet_transfers_agent_and_integration_policies_without_residue`, registered as
`fleet` with `features: &[FLEET_POLICIES]`. It:

1. refuses a dirty target with any `elasticctl-live-*` Fleet policy;
2. captures marker counts, installed-package inventory, and prebuilt baseline;
3. ensures a `system` package: when `GET /api/fleet/epm/packages/system` reports
   `installed`, it records that version; otherwise it installs the reported
   `latestVersion` with `POST /api/fleet/epm/packages/system/{version}` and
   claims that install for cleanup;
4. imports, gets, lists, exports, conflicts, skips, overwrites, and exactly
   round-trips a marker agent policy with empty monitoring;
5. performs the same lifecycle for a marker `system` integration attached to
   the agent policy;
6. proves elasticctl refuses parent deletion client-side while the integration
   is attached and sends no parent-delete request to Fleet;
7. deletes the integration, then explicitly deletes the agent policy;
8. imports both again in dependency order and proves the same ids;
9. deletes both again;
10. uninstalls `system` with `DELETE /api/fleet/epm/packages/system/{version}`
    only when step 3 installed it; and
11. requires zero markers, an installed-package inventory equal to the step 2
    capture, and an unchanged prebuilt rule count.

The contract creates no agents and changes no unmarked policy. A package the
contract did not install is never uninstalled. Cleanup owns ids before
mutation. The attached-parent proof is client-side; cleanup deletes a
remaining marker integration before retrying parent cleanup, and a remaining
marker integration blocks the package uninstall. Every cleanup mutation names
an explicit marker id or the claimed package version and omits `force`.

The conformance cleanup lease records the run nonce, exact ids, the allowed
normalized portable form before each create or update, the Fleet marker and
package baseline, and the package-install state. An owned object is deleted
only after a fresh exact read proves its id, name, namespace, nonce-bearing
description, active-space-only visibility, portable form, and deletion safety
facts. Parents also require a readable zero agent count and no attachments.
Integrations require their one owned parent, exact `system` coordinate,
complete nonsecret inputs accepted by production export, and enabled custom
state. An unreadable, malformed, changed, or different-nonce object fails
closed.

Package cleanup has four states: no lease, claimed before install, confirmed
owned after one decoded install response plus exact status and inventory
proof, and cleanup pending before its one-shot delete. A claimed but
unconfirmed install is never removed. A confirmed install is removed only
when no owned policy remains, no policy consumes `system`, the exact version
is still installed, and inventory is the baseline plus that one coordinate.
The guard observes ambiguous bootstrap, package, and cleanup mutations by
exact reads and never replays them. The final audit requires
empty Fleet markers and the exact original package inventory.

The live cleanup guard requires explicit identity, namespace, description,
monitoring, agent-count, attachment, package, enabled, and input fields where
that policy response defines them. It never fills those facts from portable
artifact defaults. Known optional platform and environment fields retain the
recorder's absent/null semantics; present values must prove the same safe
state, and any reported space must be the active space. Package removal reads
all integration policies and refuses any consumer, including unmarked
policies, before its one-shot request.

A registry install success is an asset-list response: `_meta.name` must be
`system`, `_meta.install_source` must be `registry`, and `items` must contain
valid asset references. The response has no package-version field. The exact
version is proved by the requested coordinate, package status, and complete
installed inventory before ownership is promoted. This shape is source-derived
from Kibana v9.5.1's [install schema](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/types/rest_spec/epm.ts)
and [handler](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/routes/epm/handlers.ts).

The 2026-09-05 matrix passed all ten contracts on Serverless 9.6.0, Hosted
9.5.2, and self-managed 9.5.1. Each Fleet lifecycle passed with no marker
policies and an installed-package inventory equal to its captured baseline.
Existing baselines passed, and the self-managed lab was removed with its
containers and volumes. [Reports and findings](../../conformance/v0.6.2/findings.md)
record the measured outcomes.

