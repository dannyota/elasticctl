# elasticctl Fleet policy design

`fleet agent-policies` and `fleet integration-policies` form the 0.6
capability area: reviewable Fleet configuration that can be administered and
moved safely between spaces and deployments. An agent policy configures a set
of Elastic Agents. An integration policy is one configured integration inside
one or more agent policies; Elastic's API and source call it a package policy.

These are not detection rules. Detection rules remain under `rules` and search
indexed data to create security alerts. There is no single generic Elastic
"platform policy" resource.

This spec follows `elasticctl-content-design.md`. It defers to
`elasticctl-design.md` for architecture, transport, rendering, error, guard,
fixture, conformance, and release contracts.

## 1. Scope

0.6.0 is the complete agent-policy surface:

```text
fleet agent-policies list | get | validate | export | import | delete
```

0.6.1 is the complete integration-policy surface:

```text
fleet integration-policies list | get | validate | export | import | delete
```

0.6.2 adds the Fleet conformance contract, runs the cross-flavor matrix, and
ships the bounded review patch. Each release tells one complete story: agent
configuration, attached integrations, then proof.

The 0.6 area administers and transfers policy definitions. It does not:

- extend `state pull | diff | push`;
- reconcile a directory or delete policies omitted from a file;
- assign, enroll, unenroll, upgrade, migrate, or diagnose agents;
- create or revoke enrollment API keys, service tokens, or uninstall tokens;
- manage Fleet outputs, Fleet Server hosts, proxies, download sources, cloud
  connectors, or agentless deployments;
- upgrade, downgrade, or uninstall integration packages;
- expose the compiled policy sent to an agent; or
- manage package assets independently of an integration-policy import.

Enrollment-key creation is deferred because its response carries an enrollment
secret. Outputs and hosts are environment infrastructure rather than portable
policy content.

## 2. Transfer is not reconciliation

Agent- and integration-policy files are explicit export/import artifacts.
Their absence never means delete, and importing one file never scans for or
removes remote policies that the file omits.

- `state` remains rule and exception-list state only.
- `export` reads a selected set and writes a portable artifact.
- `import` acts only on stable ids present in its file.
- `delete` is the only deletion instruction.
- Agent and integration policies remain separate artifacts.
- A complete transfer imports agent policies first, then integrations.
- No environment reference is remapped by name or guessed from a default.

## 3. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Command hierarchy | `fleet agent-policies` and `fleet integration-policies` | `policy` is overloaded; the parent names the operational domain |
| Agent-policy identity | Stored agent-policy `id` | Names are mutable; references use the id |
| Integration-policy identity | Stored package-policy `id` | Parent relationships and API mutations use the id |
| API terminology | CLI says integration policy; `-api` may say package policy | It matches Elastic's UI without hiding the wire contract |
| Portable format | Stable JSON array by default, YAML sequence on request | It matches the 0.5 content contract |
| Import conflicts | Refuse by default; `--overwrite` replaces; `--skip-existing` omits | It matches the other transfer surfaces |
| Mutation force | Never send or expose Fleet's `force` field | `force` bypasses hosted, managed, or deletion checks |
| Package version | Exact name and version in each integration artifact | Inputs and variables depend on package version |
| Missing package | Preview it; let Fleet's create path install the exact version | Fleet couples install and policy compilation |
| Different installed version | Refuse | Changing it can affect policies outside the command |
| Integration secrets | Refuse portable export and import in 0.6 | Fleet cannot return the original value; plaintext is not a safe fallback |
| Version floor | `Feature::FleetPolicies` requires 9.5.1 | It matches the measured compatibility floor |

## 4. Command surface

```text
elasticctl fleet agent-policies list [--search TEXT] [--limit N]
elasticctl fleet agent-policies get <id|name>
elasticctl fleet agent-policies validate --path FILE
elasticctl fleet agent-policies export [<id|name>...|--all-custom] [--format-file json|yaml]
elasticctl fleet agent-policies import --path FILE [--overwrite|--skip-existing] [guarded]
elasticctl fleet agent-policies delete <id|name>...                         [guarded]

elasticctl fleet integration-policies list [--search TEXT] [--limit N]
elasticctl fleet integration-policies get <id|name>
elasticctl fleet integration-policies validate --path FILE
elasticctl fleet integration-policies export [<id|name>...|--all-custom] [--format-file json|yaml]
elasticctl fleet integration-policies import --path FILE [--overwrite|--skip-existing] [guarded]
elasticctl fleet integration-policies delete <id|name>...                   [guarded]
```

`import` is the create and update interface. A missing id creates. An existing
id requires `--overwrite` to replace or `--skip-existing` to omit. Separate
imperative create and update commands would duplicate the policy-as-code path.

The global `--out` selects an export destination. Without it, stdout is the
artifact verbatim under every global renderer format. `--format-file` controls
only the portable file and defaults to `json`.

Export requires one or more selectors or `--all-custom`. A bare export is a
local error. `--all-custom` excludes known platform-owned policies: default,
managed, preconfigured, agentless, verifier, and Fleet Server agent policies,
plus managed integrations or integrations whose parent is platform-owned. It
does not silently exclude an unsupported user-owned policy. An environment
reference, protected state, secret, cross-space share, or other unsupported
custom object fails the whole export rather than producing an incomplete
artifact. An explicit selector for a platform-owned object also fails as
`unsupported`.

Mutating commands reject an empty target before building a transport.

## 5. Agent-policy model

An agent policy is the Fleet configuration assigned to Elastic Agents. Its
integration policies supply inputs and streams. Fleet distributes saved
changes to enrolled agents immediately.

A portable artifact is a JSON array, or the same array as a YAML sequence, of
`AgentPolicySpec` objects sorted by `id`:

```json
[
  {
    "id": "production-linux",
    "name": "Production Linux",
    "namespace": "production",
    "description": "Linux server agents",
    "monitoring_enabled": ["logs", "metrics"],
    "global_data_tags": [
      {"name": "environment", "value": "production"}
    ]
  }
]
```

`id`, `name`, and `namespace` are required non-empty strings. The portable
configuration may also carry:

- `description`;
- `monitoring_enabled`;
- `unenroll_timeout` and `inactivity_timeout`;
- `agent_features` and `global_data_tags`;
- `advanced_settings` and `overrides`;
- `keep_monitoring_alive`; and
- `monitoring_pprof_enabled`, `monitoring_http`, and
  `monitoring_diagnostics`.

Unknown top-level fields are rejected locally. Open nested maps remain JSON
values because Fleet's advanced settings evolve independently. Validation
checks their documented outer shapes and preserves nested keys.

Validation canonicalizes absent `monitoring_enabled`, `agent_features`, and
`global_data_tags` to empty arrays. Export writes those arrays. Optional null
and absent values normalize together only when live evidence proves they are
the same reset-to-default state.

Normalization removes server-owned or derived values:

- `status`, `revision`, `schema_version`, and saved-object `version`;
- creation and update timestamps and usernames;
- agent and version counts plus computed minimum-version conditions;
- populated `package_policies` and compiled policy output;
- default/Fleet Server role flags; and
- the active space's `space_ids` entry.

The following states make a live policy unsupported for portable export,
overwrite, or deletion:

- default, managed, preconfigured, protected, agentless, verifier, or Fleet
  Server;
- a non-null data output, monitoring output, download source, or Fleet Server
  host id;
- automatic-upgrade configuration; or
- sharing beyond the active space.

Import never sends those fields. Create uses the explicit artifact id and
`sys_monitoring=false`, so Fleet does not silently attach a System integration.
The artifact's `monitoring_enabled` remains explicit. Non-empty monitoring can
cause Fleet to install its internal `elastic_agent` package when it is absent.
Planning detects and previews that server-selected built-in installation.

## 6. Integration-policy model

An integration policy is Elastic's user-facing name for a Fleet package
policy. It configures one package and attaches it to one or more agent policies.

A portable artifact is a JSON array, or the same array as a YAML sequence, of
`IntegrationPolicySpec` objects sorted by `id`:

```json
[
  {
    "id": "production-system",
    "name": "System integration",
    "namespace": "production",
    "policy_ids": ["production-linux"],
    "package": {"name": "system", "version": "2.5.0"},
    "inputs": {}
  }
]
```

`id`, `name`, `policy_ids`, `package.name`, `package.version`, and `inputs` are
required. `policy_ids` is a non-empty, deduplicated, sorted list. It preserves
reusable integration policies when the target supports them.

The portable configuration may also carry:

- `description`, `namespace`, and `enabled`;
- package-level `vars` and `var_group_selections`;
- simplified input and stream enablement, variables, conditions, and streams;
- top-level `condition`; and
- `additional_datastreams_permissions` and `create_dataset_templates`.

The artifact uses `format=simplified` with object-shaped `inputs`. The legacy
array, generated input ids, compiled inputs, and compiled streams are not
portable. Unknown top-level fields are rejected. Package-owned input, stream,
and variable maps remain open.

Normalization removes:

- revision, saved-object version, latest-revision state, and audit fields;
- generated ids, compiled content, and derived Elasticsearch privileges;
- registry-derived package title and compatibility metadata;
- agent counts; and
- `secret_references`.

The following states make a live integration unsupported for portable export,
overwrite, or deletion:

- managed integration or managed parent;
- hosted, protected, agentless, or Fleet Server parent;
- non-null output or cloud-connector id;
- sharing outside the active space; or
- a secret reference or a configured variable declared secret by the exact
  package version.

Changing `package.name` or `package.version` on an existing id is unsupported.
Package upgrade and rollback use separate Fleet contracts and are deferred.

## 7. Secrets and environment references

Fleet stores integration secret values separately. A later read exposes a
reference or hidden placeholder, not the original value. Export fails closed
if the policy has secret references. Its error names sorted policy and field
paths but never prints reference ids or values.

Offline `validate` checks document structure. Import planning adds server-aware
validation: it loads metadata for the exact package version and rejects every
supplied package, input, or stream variable declared secret. If metadata cannot
prove whether a field is secret, planning fails before the guard. Secret
injection from an environment, file, or secret store is a future capability.

Output, download-source, Fleet Server host, cloud-connector, and extra-space
ids name target-local infrastructure. 0.6 neither exports nor remaps them. A
policy using one is unsupported rather than silently changed to a default.

## 8. Package dependencies

Planning groups integration artifacts by package name and rejects a file that
asks for more than one version of the same package.

- The exact installed version is ready.
- No installed version is a planned package installation.
- A different installed version is `conflict`.
- A missing or incompatible registry version fails before a policy write when
  Fleet exposes that result during preflight, or as the decoded create error.

Kibana's package-policy create service calls its exact-version package install
path before compiling and saving the policy. elasticctl does not add a public
`packages install` command or issue a redundant install request. Preview names
`package@version` as an implicit side effect. Apply lets guarded policy create
perform the installation, then verifies the installed version and stored
policy.

If create fails after an installation attempt, elasticctl reports the result
and re-reads package state. It never uninstalls as rollback. Successful policy
deletion also leaves the package installed.

## 9. Selection and listing

Both list APIs are paginated. elasticctl requests deterministic id ordering,
collects pages until the reported total or `--limit`, then sorts by id. It
rejects a page that makes no progress or contradicts response metadata.

`--search` maps to a safely constructed Fleet KQL query over id and name.
Exact filtering remains local so analyzer differences cannot change selector
semantics.

Resolution tries exact id with the single-object endpoint first. If that
misses, it keeps exact name matches from the list route. Zero matches is
`not_found`; more than one is `conflict`. A name never becomes stored identity.

Selectors are deduplicated by id. Every selector resolves before export or
delete. Mutation planning requests populated integration policies and agent
counts. Ordinary list output does not request compiled full policies.

## 10. Import planning and races

Import reads and structurally validates the whole file before any server call.
It then performs the semantic and dependency reads required by sections 5-8.

With neither conflict flag, any existing id or conflicting unique name fails
the plan before the guard. `--skip-existing` reports and removes existing ids.
`--overwrite` classifies each row as create, replace, or unchanged. A name
owned by another id is always conflict.

The plan retains canonical file specs; normalized existing snapshots; parent
flags, ids, and agent counts; installed package versions; implicit installs;
and the profile, host, and active space.

Preview reports every action plus affected parent policies and agent count.
Because Fleet distributes changes immediately, blast radius is part of the
mutation contract.

Apply does not reread the file. Immediately before each write it repeats the
relevant object, parent, count, and package reads:

- planned create refuses if its id or name appeared;
- replace or unchanged refuses if its object changed;
- integration refuses if a parent, count, or package version changed; and
- a missing planned replacement is conflict, not create.

The routes expose no conditional-write token, so a change can still race the
final recheck and write. Reports name this unavoidable window.

Rows apply in stable-id order. After each decoded mutation success, import GETs
the object in simplified form, normalizes it, and requires exact equality with
the desired spec. A mismatch is failed with `applied: true`. Successful earlier
writes are not rolled back. Multi-object imports continue across independent
failures; a dependency failure blocks only dependent rows.

## 11. Safe deletion

Fleet can delete single-parent integration policies and detach reusable ones
as part of agent-policy deletion. elasticctl refuses that cascade.

Agent-policy delete requires zero assigned agents, zero attached integrations,
no unsupported state from section 5, and active-space-only visibility. Preview
names the id, name, flags, agent count, and attached integration ids. Apply
repeats the snapshot, then sends the single-id delete without `force`.

Integration-policy delete requires portable ownership from section 6. Preview
names every parent and the agent count that can receive the change. Apply
rechecks the policy, parents, counts, and package version before the single-id
DELETE without `force`.

A target that disappears after planning is a failed `not_found`, not a no-op.
Delete never uninstalls a package. Multi-id deletion continues across
independent rows and does not use Fleet bulk or force routes.

## 12. Architecture

Dependency direction remains:

```text
elasticctl-cli  ->  elasticctl-api  ->  elasticctl-core
```

`elasticctl-api` owns the Fleet vertical:

- `fleet::agent_policies` owns route wrappers and response models;
- `fleet::agent_policy_ops` owns selection, normalization, portability,
  planning, apply, and deletion;
- `fleet::integration_policies` owns package-policy route wrappers and
  simplified response models;
- `fleet::integration_policy_ops` owns package validation, portability,
  planning, apply, and deletion; and
- existing `content_codec` owns portable JSON/YAML.

Modules may use package-policy names where they model Elastic's API. Public
types and output use integration-policy names unless a raw server field such as
`policy_ids` must remain compatible.

`elasticctl-cli::cmd::fleet` resolves context, invokes API plans, applies the
guard, serializes typed results, and hands values to `render`. It does not own
multi-request orchestration or parse response bodies.

`elasticctl-core` gains `Feature::FleetPolicies` at floor 9.5.1. No Fleet model
or orchestration enters `-core`.

## 13. Errors and reports

- `not_found`: selector, target, parent, or exact package missing.
- `conflict`: ambiguous selector, existing import id, duplicate name, changed
  snapshot, different installed package version, or unsafe delete.
- `unsupported`: managed or hosted state, environment reference, cross-space
  policy, agentless/protected/Fleet Server policy, secret, or package change.
- `http`: malformed success response or failed post-write invariant.
- `error`: malformed artifact or invalid command combination.

List and get return typed values through `render`. Validate returns
`{valid, total}`. Export with `--out` returns `{exported, path, failed}`;
without it, stdout is the artifact.

Import reports `{applied, succeeded, unchanged, skipped, failed, total,
affected_agents, package_installs}`. Delete reports `{applied, deleted, failed,
total, affected_agents}`. Each agent belongs to one agent policy, so summing
counts across distinct affected parents does not double-count agents. A
non-empty failed collection exits 1.

`package_installs` uses exact `name@version` coordinates for integration
dependencies. A planned internal monitoring installation is reported as
`elastic_agent@server-selected` because the agent-policy API does not accept a
version. Apply rechecks the resolved installed version after create.

A row's `applied` becomes true only after a mutation route returns a decoded
success. It does not claim that a timeout made no remote change. No report
contains a secret, secret-reference id, compiled policy, username, or
unselected integration configuration.

## 14. Fixtures and conformance

Fixtures are recorded from real traffic for Serverless, Hosted, and
self-managed deployments. Every created id and name starts with
`elasticctl-sample-`. The recorder registers ids before create and deletes
integrations before agent policies.

Recording requests are exact-id or exact-marker queries. No unscoped policy
list or full-policy response enters a public fixture. The recorder strictly
decodes responses, requires every policy to be an owned marker, and scrubs
usernames, timestamps, secret references, space ids, deployment details, and
unrelated package inventory.

0.6.0 fixtures cover agent-policy paginated list, get, explicit-id create,
update, delete, name conflict, not found, agent counts, attached integrations,
default and other unsupported-state refusals, the internal monitoring-package
preflight, and normalized round trips.

0.6.1 fixtures cover integration-policy simplified list, get, explicit-id
create, update, delete, parent validation, exact package state, conflicts,
managed/hosted and secret refusals, version conflict, and normalized round
trips. The absent-package behavior remains source-derived unless a recording
can prove the package absent and restore inventory without weakening marker or
residue rules. Planner behavior still has offline unit coverage.

0.6.2 adds the tenth conformance contract,
`fleet_transfers_agent_and_integration_policies_without_residue`, registered as
`fleet` with `features: &[FLEET_POLICIES]`. It:

1. refuses a dirty target with any `elasticctl-live-*` Fleet policy;
2. captures marker counts, installed-package inventory, and prebuilt baseline;
3. imports, gets, lists, exports, conflicts, skips, overwrites, and exactly
   round-trips a marker agent policy;
4. discovers the installed `system` package version;
5. performs the same lifecycle for a marker integration attached to the agent
   policy;
6. proves parent deletion is refused while the integration is attached;
7. deletes the integration, then the agent policy;
8. imports both again in dependency order and proves the same ids;
9. deletes both again; and
10. requires zero markers, unchanged package inventory, and unchanged prebuilt
    rule count.

The contract creates no agents and changes no unmarked policy. Cloud legs use
an already-installed package and never install or uninstall one. Cleanup owns
ids before mutation. A remaining integration blocks parent cleanup until retry.
Every cleanup mutation names an explicit marker id and omits `force`.

Current design targets are Serverless 9.6.x, Hosted 9.5.x, and the self-managed
9.5.1 lab. Reports record actual versions under `docs/conformance/v0.6.2/`.

## 15. Research basis

These facts were verified on 2026-09-03 against Elastic's current docs and
Kibana `v9.5.1` source. They remain source-derived until 0.6 records them on
the supported flavors.

| Fact | Source-derived result |
|---|---|
| Relationship | Agent policies contain integrations; changes reach enrolled agents |
| Hosted restriction | Hosted policies restrict policy and integration operations |
| Space scope | Both policy routes have `/s/{space_id}` forms |
| Identity | Both create schemas accept explicit `id` |
| Pagination | Both list routes return page, per-page, and total |
| Simplified form | Package-policy routes support object-shaped simplified inputs |
| Force bypass | Update and delete routes expose `force` for restricted state |
| Delete cascade | Agent delete can delete or detach integration policies |
| Package dependency | Package-policy create ensures the exact package version |
| Secrets | Fleet stores secrets separately and later exposes references |

Primary references:

- [Elastic Agent policies](https://www.elastic.co/docs/reference/fleet/agent-policy)
- [Fleet API overview](https://www.elastic.co/docs/reference/fleet/fleet-api-docs)
- [Create an agent policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-post-fleet-agent-policies)
- [Update an agent policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-put-fleet-agent-policies-agentpolicyid)
- [Delete an agent policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-post-fleet-agent-policies-delete)
- [Get package policies](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-get-fleet-package-policies)
- [Create a package policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-post-fleet-package-policies)
- [Update a package policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-put-fleet-package-policies-packagepolicyid)
- [Delete a package policy](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-delete-fleet-package-policies-packagepolicyid)
- [Install an exact package version](https://www.elastic.co/docs/api/doc/kibana/v9/operation/operation-post-fleet-epm-packages-pkgname-pkgversion)
- [Kibana agent-policy model](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/common/types/models/agent_policy.ts)
- [Kibana agent-policy service](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/services/agent_policy.ts)
- [Kibana package-policy schema](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/common/types/models/package_policy_schema.ts)
- [Kibana package-policy service](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/services/package_policy.ts)
- [Kibana secret handling](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/services/secrets/package_policies.ts)

## 16. Version placement

| Version | Fleet content |
|---|---|
| 0.6.0 | Complete agent-policy administration and transfer |
| 0.6.1 | Complete integration-policy administration and exact package checks |
| 0.6.2 | Fleet conformance matrix and bounded review patch |

The release target list is unchanged from 0.5.2, whose asset set is complete.
0.6.x needs no release candidate unless packaging or targets change. A release
does not publish to crates.io without explicit approval for that exact version.

## 17. Decisions log

1. Policies mean Fleet agent and integration configuration, not detection rules
   or generic platform governance.
2. Both resource groups sit under `fleet` to remove ambiguity.
3. List, get, validate, export, import, and delete are complete; import owns
   create and update.
4. Artifacts are explicit transfer, not desired-state reconciliation.
5. Target-local infrastructure, cross-space sharing, managed state, and secrets
   fail closed.
6. Exact packages are dependencies; absent packages may be installed by
   guarded create, but 0.6 never upgrades, downgrades, or uninstalls them.
7. Agent-policy delete refuses attached integrations even though Fleet can
   cascade or detach them.
8. The cut line is 0.6.0 agent policies, 0.6.1 integrations, and 0.6.2 proof.
