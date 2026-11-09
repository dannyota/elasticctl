[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 9. Fixtures and conformance

Fixtures are recorded live via `cargo xtask record`, marker-scoped as always.
The recorder creates a marker rule over a marker index seeded with matching
events (the sample-data scripts already produce these), waits for the rule to
generate alerts, records the triage exchanges, then closes and cleans up.

Scrubbing gains a new class: profile and cases payloads embed user identity
(`username`, `full_name`, `email`, profile `uid`s, realm names, `created_by`,
`updated_by`). All are scrubbed like the existing identity fields. Alert ids
and profile uids are rewritten wherever they appear **inside** a string
value, not only where the whole value equals one: Kibana embeds the real
alert uuid inside `kibana.alert.url` (`.../redirect/<uuid>?index=…&
timestamp=…`), which a whole-string match misses. `kibana.alert.url` is
additionally replaced outright with a fixed placeholder, since its
`timestamp=` query parameter is a live value nothing decodes.

Volatile fields to normalize: alert `_id`s, `@timestamp`, any key ending
`_at` (the general suffix rule — applied to every recorded response, not
scoped to `kibana.alert.*`; it is what normalizes case `created_at`,
`updated_at`, and `closed_at` too, not only alert fields), and any
`kibana.alert.*` key ending `.start` or `.end` (alert documents flatten
`kibana.alert.*` into dotted keys directly on `_source`, so a suffix match on
the key catches the class without naming every occurrence), plus the explicit
fields that don't fit that pattern — `kibana.alert.uuid`, `kibana.alert.url`
(replaced outright, see above), `kibana.alert.last_detected`,
`kibana.alert.original_time`, `kibana.alert.intended_timestamp`,
`kibana.alert.rule.execution.timestamp`, `kibana.alert.rule.execution.uuid`,
`_score`, `max_score` — and `took`, `timed_out`, `_shards` (present on every
triage mutation response, not only `signals/search`), case `id`, `version`,
comment ids, and (from the next recording; current fixtures predate this)
the case workflow-duration numerics `duration`, `time_to_acknowledge`,
`time_to_investigate`, `time_to_resolve` — elapsed real time between the
recorder's own steps, so a re-record's values never match the prior ones.

The conformance contract (eighth in the matrix,
`triage_transitions_alerts_and_cases_and_leaves_only_closed_residue` in
`crates/elasticctl-cli/tests/live.rs`) first refuses to mutate a target with
an open `elasticctl-live-*` alert or an `elasticctl-live-marker` case. It then
seeds three marker documents, creates and enables the marker rule over them,
polls for the alert it generates, transitions it open → acknowledged → closed
by id, re-opens and closes it again by marker-scoped query, tags then untags
it, resolves an assignee, creates a case, attaches the alert to it, comments
on it, closes and deletes the case (verifying it is gone), then runs a final
closing sweep over every alert the marker rule produced and confirms none stay
open before `conclude`'s baseline check runs.

**Assignment refinement.** The contract does not resolve the operator's own
username — it takes the *first activated profile* from
`profiles::suggest(&transport, flavor, "")` and assigns/unassigns that uid,
failing the contract if the list is empty. This also exercises the
per-flavor profile-suggest route switch (section 7). Serverless and Hosted
already carry one activated profile from the operator's own SSO login before
the matrix ever runs; the self-managed lab boots headless with no browser
session ever logging in, so the traditional matrix leg activates one itself
at boot, immediately after installing the prebuilt rule pack and before
spawning the conformance child (`xtask/src/activation.rs`, called from
`conformance_matrix.rs::run_traditional_boot_and_leg`). The Hosted leg calls
the same function before spawning its child whenever
`ELASTICCTL_ECH_USERNAME` and `ELASTICCTL_ECH_PASSWORD` are both set, so a
Hosted deployment that has lost its SSO-activated profile is repaired rather
than failing the contract. Activation logs in as that user via
`POST /internal/security/login` with `x-elastic-internal-origin: Kibana` —
the only call that activates a profile, per the measured fact in section 10.

The login provider's *name* is discovered, not assumed. The route takes a
configured provider name rather than a type, and answers `401 Unauthorized`
for a name the deployment does not configure — indistinguishable from a
wrong password. A self-managed stack names its basic provider `basic`; a
Hosted deployment names it `cloud-basic` (measured 2026-09-01: identical
credentials, `basic` → 401, `cloud-basic` → 200). Activation therefore reads
`GET /internal/security/login_state` first and takes the name of the first
provider of type `basic` with `usesLoginForm: true`, ignoring
`selector.enabled` (the lab reports it `false` while still listing the
provider). A deployment advertising no such provider fails at this step with
a named error instead of a misleading 401.

**Accepted deviation — alert residue (decided).** Generated alerts live in
the shared `.alerts-security.alerts-default` index, the public API has no
alert delete, and none will be built. The conformance contract therefore
closes its marker alerts as its final triage step, and baseline verification
tolerates residual *closed* alerts from `elasticctl-live-*` rule ids instead
of proving absence. The fixture recorder applies the same deviation to its
separate `elasticctl-sample` marker alerts. This is a deliberate deviation
from the strict back-to-baseline rule the other contracts follow: a closed,
marker-tagged alert is inert — it matches no open-alert workflow, belongs to a
deleted marker rule, and is scoped out of every baseline count — whereas
deleting documents from a dot-prefixed system index would depend on privileges
the flavors do not uniformly grant and on behavior Elastic does not contract.
One consequence: the recorded `signals_status_query` fixture's
`updated`/`total` counts include this accumulated closed residue from the
shared index, so they grow across successive recording sessions rather than
staying pinned to the one marker alert each session closes — expected, given
the deviation above, not a regression to chase.

**Cases carry no such deviation.** Unlike alerts, cases delete cleanly
through a public API (`DELETE /api/cases`, section 10), so the recording
session tolerates **no** marker-case residue, closed or otherwise: the cases
probe deletes its marker case as its final step, and baseline verification
proves absence the same way every other conformance contract does. The
alert-residue deviation above does not extend to cases. The live cleanup guard
registers the case's exact unique title and marker tag before creation. If the
POST succeeds but its response cannot supply an id, cleanup finds that exact
scope through `_find` and deletes the returned id instead of leaving residue.

