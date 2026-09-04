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
| Hosted and managed | "Hosted" is an agent policy with `is_managed: true`; "managed" is an integration with `is_managed: true` | Elastic's UI and error text use both words for the same flag on different objects |
| Portable format | Stable JSON array by default, YAML sequence on request | It matches the 0.5 content contract |
| Bare export | A local error; `--all-custom` is the explicit whole-space selector | Fleet spaces hold platform-owned policies, so "everything" is never a safe default. This differs from the 0.5 content surface on purpose |
| Import conflicts | Refuse by default; `--overwrite` replaces; `--skip-existing` omits | It matches the other transfer surfaces |
| List paging | `sortField=created_at&sortOrder=asc`, pages of 1000, then local id sort | Both list routes answer 400 `Unknown sort field id` (measured) |
| `--search` | Local case-insensitive substring over id and name | KQL over `id` is a 400 on package policies and is silently ignored on agent policies (measured) |
| Agent-policy replace | Send the complete desired spec plus an explicit null for each clearable field the artifact omits; refuse every other top-level removal as `unsupported` at planning | The update route merges top-level attributes, so an omitted field survives the write; nested objects are replaced whole |
| Server defaults | Validate fills a fixed default table and export always writes those fields | Fleet fills `inactivity_timeout` on create, so a sparse artifact never round-trips exactly |
| Mutation force | Never send or expose Fleet's `force` field | `force` bypasses hosted, managed, or deletion checks |
| Package version | Exact name and version in each integration artifact | Inputs and variables depend on package version |
| Missing package | Preview it; let Fleet's create path install the exact version | Fleet couples install and policy compilation |
| Different installed version | Refuse | Changing it can affect policies outside the command |
| Integration secrets | Refuse portable export and import in 0.6 | Fleet cannot return the original value; plaintext is not a safe fallback |
| Version floor | `Feature::FleetPolicies` shares the 9.5.1 fixture-evidence floor | `require_feature` has one floor for every feature. It says where fixtures exist, not where Fleet APIs begin |
| Conformance package | The contract installs the registry's latest `system` when absent and uninstalls it at cleanup only if it installed it | Neither cloud target has `system` installed, and no attachable installed package is shared by both (measured) |

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
local error. `--all-custom` excludes platform-owned policies. An agent policy
is platform-owned when any of `is_default`, `is_default_fleet_server`,
`has_fleet_server`, `is_managed`, `is_preconfigured`, `supports_agentless`, or
`is_verifier` is true, or when `agentless` is non-null. `agentless` is a
configuration object, not a boolean flag. `is_verifier` marks the short-lived
policy Fleet creates to verify OTel permissions. An integration is
platform-owned when it is `is_managed` or its parent is platform-owned.
`--all-custom` does not silently exclude an unsupported user-owned policy. An
environment reference, protected state, secret, cross-space share, or other
unsupported custom object fails the whole export rather than producing an
incomplete artifact. An explicit selector for a platform-owned object also
fails as `unsupported`.

Mutating commands reject an empty target before building a transport.

## 5. Agent-policy model

An agent policy is the Fleet configuration assigned to Elastic Agents. Its
integration policies supply inputs and streams. Fleet distributes saved
changes to enrolled agents on their next check-in.

A portable artifact is a JSON array, or the same array as a YAML sequence, of
`AgentPolicySpec` objects sorted by `id`:

```json
[
  {
    "id": "production-linux",
    "name": "Production Linux",
    "namespace": "production",
    "description": "Linux server agents",
    "inactivity_timeout": 1209600,
    "monitoring_enabled": ["logs", "metrics"],
    "agent_features": [],
    "global_data_tags": [
      {"name": "environment", "value": "production"}
    ]
  }
]
```

`id`, `name`, and `namespace` are required non-empty strings. The portable
configuration may also carry:

- `description`;
- `monitoring_enabled` (each entry one of `logs`, `metrics`, or `traces`);
- `unenroll_timeout` and `inactivity_timeout`;
- `agent_features` and `global_data_tags`;
- `advanced_settings` and `overrides`;
- `keep_monitoring_alive`; and
- `monitoring_pprof_enabled`, `monitoring_http`, and
  `monitoring_diagnostics`.

Unknown top-level fields are rejected locally. Open nested maps remain JSON
values because Fleet's advanced settings evolve independently. Validation
checks their documented outer shapes and preserves nested keys.
`agent_features` entries require a non-empty `name` and boolean `enabled`.
`global_data_tags` entries require a non-empty whitespace-free `name` and a
string or number `value`; tag names must be unique.

### 5.1 Server-applied defaults

Fleet fills defaults on create. The schema gives `inactivity_timeout` a
default of 1209600 seconds, so a created policy always carries it even when
the artifact omits it. Hosted 9.5.2's preconfigured policy carries 86400
instead, so the default is a create-time fill, not an invariant.

`-api` holds one fixed default table. Validation fills every absent entry from
it, export always writes those fields, and the post-write equality check in
section 10 compares the filled forms. The 0.6.0 table is:

| Field | Default |
|---|---|
| `inactivity_timeout` | `1209600` |
| `monitoring_enabled` | `[]` |
| `agent_features` | `[]` |
| `global_data_tags` | `[]` |

Recording extends the table only from measured create responses. A default the
table does not know surfaces as a post-write mismatch, which fails closed
rather than silently drifting. The 2026-09-04 recordings confirm this (section
15.1): create responses on Serverless 9.6.0, Hosted 9.5.2, and self-managed
9.5.1 filled nothing beyond this table.

Normalization treats a null and an absent optional value as the same state.
Hosted 9.5.2 returns null for `has_fleet_server`, `supports_agentless`,
`agentless`, and `is_verifier` on its preconfigured policy, so the two forms
must compare equal. A malformed non-null platform flag, `agentless`,
`required_versions`, or `space_ids` value is `http`; it is never treated as
absent or safe.

### 5.2 Normalization and unsupported states

Normalization removes server-owned or derived values:

- `status`, `revision`, `schema_version`, and saved-object `version`;
- `created_at`, `created_by`, `updated_at`, and `updated_by`;
- `agents`, `unprivileged_agents`, `fips_agents`, `agents_per_version`,
  `min_agent_version`, `package_agent_version_conditions`, and
  `has_agent_version_conditions`;
- populated `package_policies` and compiled policy output;
- every boolean platform flag from section 4 plus `is_protected` when it is
  false or null, and a null `agentless`; and
- the active space's `space_ids` entry.

A live top-level field outside this list and the portable set is
`unsupported` and names the field, so a new Fleet field is a loud refusal
rather than a silent loss from the artifact.

The following states make a live policy unsupported for portable export,
overwrite, or deletion:

- any boolean platform flag from section 4 true, non-null `agentless`, or
  `is_protected` true;
- a non-null `data_output_id`, `monitoring_output_id`, `download_source_id`,
  or `fleet_server_host_id`;
- a non-null `required_versions` automatic-upgrade configuration; or
- `space_ids` naming any space other than the active one.

Import never sends those fields.

### 5.3 Create and replace

Create uses `POST /api/fleet/agent_policies?sys_monitoring=false` with the
explicit artifact id, so Fleet does not silently attach a System integration.
The artifact's `monitoring_enabled` remains explicit. A create with non-empty
monitoring makes Fleet install its internal `elastic_agent` package when it is
absent; an install error there is not fatal to the create. A replace installs
it only when the stored policy has no `monitoring_enabled` value at all and
the desired value is non-empty. A stored empty array does not trigger it.
Normalization cannot tell a stored empty array from an absent value, so
planning treats every empty-to-non-empty replace as a possible install.
Planning reads `GET /api/fleet/epm/packages/elastic_agent` and previews that
server-selected installation as possible, never as certain. A replace whose
current monitoring is already non-empty does not plan an install. The
recorder and the conformance contract use empty monitoring so a recording or
matrix run never changes package inventory through this path.

Replace uses `PUT /api/fleet/agent_policies/{id}`. The service spreads the
supplied attributes into a saved-object update, and Kibana merges that update
into the stored attributes one top-level field at a time: an omitted top-level
field keeps its stored value. Two exceptions matter. `inactivity_timeout`
carries a request-schema default, so omitting it resets the stored value to
1209600 rather than keeping it. `advanced_settings`, `overrides`,
`monitoring_http`, and `monitoring_diagnostics` are mapped `flattened`, so a
supplied object replaces the stored object whole and a nested key is never
merged. Planning therefore compares the normalized current policy with the
filled desired spec and:

- sends the complete desired spec, never a delta;
- adds an explicit null for each nullable field the desired spec omits and the
  current policy has. The nullable fields are `overrides`,
  `keep_monitoring_alive`, `required_versions`, `supports_agentless`,
  `data_output_id`, `monitoring_output_id`, `download_source_id`, and
  `fleet_server_host_id`. Section 5.2 already refuses a true
  `supports_agentless`, any non-null `required_versions`, and a non-null value
  in the four ids, so in practice `overrides` and `keep_monitoring_alive` are
  clearable author fields; and
- fails `unsupported` before the guard when the desired spec removes any other
  optional top-level field the current policy has, such as `unenroll_timeout`
  or `description`. A nested object is always sent whole, so dropping a key
  inside one needs no rule.

The top-level merge is measured on Serverless 9.6.0, Hosted 9.5.2, and
self-managed 9.5.1 (2026-09-04, section 15.1): an update omitting a top-level
field keeps its stored value. The flattened-object replacement remains
source-derived from Kibana v9.5.1. The post-write equality check is the
measured backstop: a merge that leaves an unexpected value fails the row
rather than reporting success.

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
    "package": {"name": "system", "version": "2.23.4"},
    "inputs": {}
  }
]
```

`id`, `name`, `policy_ids`, `package.name`, `package.version`, and `inputs` are
required. `policy_ids` is a non-empty, deduplicated, sorted list. Fleet also
allows an empty list for an orphaned integration; 0.6 does not transfer those.
When an artifact omits `namespace`, planning reads every named parent, requires
one common parent namespace, and fills that value into the effective spec. An
explicit namespace remains exact; export always writes the stored namespace.

The portable configuration may also carry:

- `description` and `namespace`;
- package-level `vars` and `var_group_selections`;
- simplified input and stream enablement, variables, conditions, and streams;
- top-level `condition`; and
- `additional_datastreams_permissions`.

The artifact uses `format=simplified` with object-shaped `inputs`. The legacy
array, generated input ids, compiled inputs, and compiled streams are not
portable. Unknown top-level fields are rejected. Package-owned input, stream,
and variable maps remain open.

An empty `inputs` object remains structurally valid for offline `validate`,
which has no package metadata. Remote import planning reads the exact package
metadata before the guard. If that metadata declares one or more composite
input keys, an empty effective `inputs` object is `unsupported` before any
mutation. Fleet materializes registry defaults for every declared input and
stream when create receives an empty object, so accepting that shorthand would
make a successful write fail exact post-write equality and drift again on the
next import. A package whose exact metadata declares no inputs may keep an
empty object. Export writes the complete simplified input map returned by
Fleet; that map is stable when imported again.

Two response fields are deliberately not portable. `create_dataset_templates`
exists only in the create request schemas and never comes back from a read, so
carrying it would break round-trip equality. Top-level `enabled` comes back
from every read but the simplified create schema does not accept it; only
per-input and per-stream `enabled` are portable. Normalization requires the
top-level value to be true and drops it. A false value is `unsupported`.
Create and replace send no top-level `enabled`. Replace sends the complete
desired spec after removing its `id`; neither route sends `force` or
`create_dataset_templates`.

Normalization removes:

- `revision`, saved-object `version`, and the `created_at`, `created_by`,
  `updated_at`, and `updated_by` audit fields;
- the deprecated singular `policy_id`, which duplicates `policy_ids[0]`;
- `spaceIds`, the camelCase package-policy form of the agent policy's
  `space_ids`, after checking it names only the active space;
- generated input ids, compiled content, and the derived `elasticsearch`
  privileges block;
- the registry-derived `package.title`, `package.requires_root`,
  `package.fips_compatible`, and `package_agent_version_condition`;
- `agents`;
- `secret_references`; and
- `is_managed`, `supports_agentless`, `supports_cloud_connector`,
  `cloud_connector_id`, `cloud_connector_name`, and `output_id` when false,
  null, or absent.

Hosted 9.5.2 returns package policies without `is_managed`,
`secret_references`, or `vars` when they are unset, so absent means not
managed, no secrets, and no variables.

The following states make a live integration unsupported for portable export,
overwrite, or deletion:

- `is_managed` true (a managed integration), or a parent that is platform-owned
  or `is_protected` under section 4 and 5.2;
- a non-null `output_id` or `cloud_connector_id`, or `supports_agentless` or
  `supports_cloud_connector` true;
- `spaceIds` naming any space other than the active one; or
- a secret reference or a configured variable declared secret by the exact
  package version.

Replace uses `PUT /api/fleet/package_policies/{id}` with the complete desired
simplified spec. The service recompiles every input from the package and the
supplied values, so this route is a full replacement, unlike the agent-policy
route. Changing `package.name` or `package.version` on an existing id is
unsupported. Package upgrade and rollback use separate Fleet contracts and are
deferred.

## 7. Secrets and environment references

Fleet stores integration secret values separately. A later read exposes a
reference or hidden placeholder, not the original value. Export fails closed
if the policy has secret references. Its error names sorted policy and field
paths but never prints reference ids or values.

A deployment without secret storage keeps a secret variable in plaintext and
returns it on read, so references alone cannot prove absence. Export and
import planning both read `GET /api/fleet/epm/packages/{name}/{version}` for
the exact package version and reject every supplied package, input, or stream
variable the package declares secret. If that read fails, the classified
transport error stands. If the metadata cannot prove whether a configured
variable is secret, the operation fails `unsupported` before the guard.
Offline `validate` checks document structure only. Secret injection from an
environment, file, or secret store is a future capability.

The exact package response defines package variables in optional `item.vars`
and input variables in optional
`item.policy_templates[].inputs[].vars`. It defines stream variables in
`item.data_streams[].streams[].vars`, not only in an input's legacy nested
`streams`. Every variable definition has a non-empty unique `name`; absent
`secret` means false, while a present non-boolean value is malformed `http`.

Input schema keys are `<template-name>-<input-type>`. Template names and
composite input keys are unique. A template's absent `data_streams` selects all
top-level data streams, an empty list selects none, and each non-empty selector
must resolve exactly once as either an exact dataset or
`<package-name>.<selector>`. Each top-level data stream has one unique,
non-empty full dataset. Each of its stream entries has one non-empty `input`.
Joining a stream to template inputs with the same type and a matching dataset
must yield exactly one composite input key. Zero or multiple candidates,
duplicate selectors, datasets, stream inputs, or resulting stream keys are
malformed `http`.

For compatibility, legacy `policy_templates[].inputs[].streams` definitions
remain accepted. When modern and legacy metadata define the same composite
input and dataset, their normalized variable definitions must be identical;
otherwise metadata is malformed. A configured package variable, input key,
stream dataset, or variable without a matching definition remains
`unsupported` and error text never includes its value.

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
and re-reads package state. When the exact requested version became installed,
it advances the shared package snapshot, reports that observed install once,
and permits later rows using it. A different version or malformed read blocks
only rows using that package. It never uninstalls as rollback. Successful
policy deletion also leaves the package installed.

## 9. Selection and listing

Both list routes are paginated and reject `sortField=id` with 400 `Unknown
sort field id` (measured on Serverless 9.6.0 and Hosted 9.5.2). elasticctl
requests `sortField=created_at&sortOrder=asc` in pages of 1000, collects until
the reported `total`, then sorts by id locally. It fails `http` when page
metadata disagrees with the request, `total` changes between pages, an id
repeats, or a page is short before `total`. This mirrors the dashboard list.
Package-policy lists add `format=simplified`.

`--search` is a local case-insensitive substring match over id and name after
collection. KQL over `id` is not a usable server contract: the package-policy
route answers 400 because `id` is not a saved-object attribute, and the
agent-policy route silently ignores the clause and returns every policy. Name
KQL works but would give `--search` two different semantics, so neither is
used. `--limit` truncates after sorting and the list reports `truncated`.

Resolution tries the exact id with the single-object endpoint first. On
`not_found` it collects the list and keeps exact name matches. Zero matches is
`not_found`; more than one is `conflict`. A name never becomes stored identity.

Selectors are deduplicated by id. Every selector resolves before export or
delete. The single-object agent-policy read carries populated
`package_policies`, and carries `agents` only when the caller holds the Fleet
agents read privilege, because Kibana populates the count behind that check.
Mutation planning uses both for blast radius and attached integrations. A read
with no `agents` field is `permission` and names the missing privilege; a read
without `package_policies`, or with either field malformed, is `http`.
Ordinary list output does not request compiled full policies.

Integration parent snapshots keep only id, name, namespace, agents, sorted
attached integration ids, platform ownership, and protection. They ignore
agent-policy-only environment and portability fields, but require an existing
integration to appear in every parent named by its `policy_ids`; disagreement
is a malformed `http` response and the attachment list remains a race snapshot.

Agent-policy get returns a sanitized `AgentPolicyDetail`, never the raw Fleet
item. It contains `id`, `name`, `namespace`, `description`, `agents`, `status`,
sorted `attached_integrations` ids, and sorted `blocked_by` field names. The
last list explains why the live policy cannot be exported or mutated without
exposing environment ids, the `agentless` configuration, usernames, or
populated integration objects.

Integration-policy get returns a sanitized `IntegrationPolicyDetail`, never
the raw Fleet item. It contains `id`, `name`, `namespace`, `description`,
sorted `policy_ids`, the exact package coordinate, `affected_agents`, and
sorted `blocked_by`; it never exposes inputs, variable values, secret
references, audit identities, environment ids, or compiled content.

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

## 11. Safe deletion

Fleet can delete single-parent integration policies and detach reusable ones
as part of agent-policy deletion. elasticctl refuses that cascade.

Agent-policy delete requires zero assigned agents, zero attached integrations,
no unsupported state from section 5.2, and active-space-only visibility.
Preview names each target's id, name, agent count, and attached-integration
count, all read from the planning snapshot. A plan that reaches the guard
holds only targets with zero of both and no true platform flag, because
planning and normalization refuse everything else. Apply repeats the
snapshot, then sends
`POST /api/fleet/agent_policies/delete` with `{"agentPolicyId": id}` and no
`force`. Fleet's own checks refuse a policy with active or inactive agents, a
hosted policy, and a policy containing managed integrations; elasticctl refuses
earlier and with the same outcome. A 2xx response whose body echoes a
different id than the one deleted is reported failed with `applied: true`,
since the server acknowledged deleting something.

Integration-policy delete requires portable ownership from section 6. Preview
names every parent and the agent count that can receive the change. Apply
rechecks the policy, parents, counts, and package version before the single-id
`DELETE /api/fleet/package_policies/{id}` without `force`.

A target that disappears after planning is a failed `not_found`, not a no-op.
Delete never uninstalls a package. Multi-id deletion continues across
independent rows and does not use Fleet bulk or force routes.

## 12. Architecture

Dependency direction remains:

```text
elasticctl-cli  ->  elasticctl-api  ->  elasticctl-core
```

`elasticctl-api` owns the Fleet vertical under `src/fleet/`:

- `fleet/agent_policies.rs` owns route wrappers, strict response decoders, and
  the `AgentPolicySpec` model with its default table;
- `fleet/agent_policy_ops.rs` owns selection, normalization, portability,
  planning, apply, and deletion;
- `fleet/integration_policies.rs` owns package-policy route wrappers and
  simplified response models;
- `fleet/integration_policy_ops.rs` owns package validation, portability,
  planning, apply, and deletion; and
- existing `content_codec` owns portable JSON/YAML.

Modules may use package-policy names where they model Elastic's API. Public
types and output use integration-policy names unless a raw server field such as
`policy_ids` must remain compatible.

`elasticctl-cli::cmd::fleet` resolves context, invokes API plans, applies the
guard, serializes typed results, and hands values to `render`. It does not own
multi-request orchestration or parse response bodies.

`elasticctl-core` gains `Feature::FleetPolicies`, which `require_feature`
checks against the shared 9.5.1 floor. No Fleet model or orchestration enters
`-core`.

## 13. Errors and reports

- `not_found`: selector, target, parent, or exact package missing.
- `conflict`: ambiguous selector, existing import id, duplicate name, changed
  snapshot, different installed package version, or unsafe delete.
- `unsupported`: hosted agent policy or managed integration, platform flag,
  environment reference, cross-space policy, protected policy, secret, package
  change, or an overwrite that removes a field the update route cannot clear.
- `permission`: a single-object agent-policy read without `agents`, which
  Kibana populates only for a caller with Fleet agents read.
- `http`: malformed success response, paging contradiction, or failed
  post-write invariant.
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

Current design targets are Serverless 9.6.x, Hosted 9.5.x, and the self-managed
9.5.1 lab. Reports record actual versions under `docs/conformance/v0.6.2/`.

## 15. Research basis

### 15.1 Measured

These read-only probes ran on 2026-09-03 against Serverless 9.6.0 and Elastic
Cloud Hosted 9.5.2 with the project-scoped keys. They created nothing.

| Probe | Serverless 9.6.0 | Hosted 9.5.2 |
|---|---|---|
| `GET /api/fleet/agent_policies?sortField=id` | 400 `Unknown sort field id` | same |
| `GET /api/fleet/package_policies?sortField=id` | 400 `Unknown sort field id` | same |
| `sortField=created_at` and `sortField=name` | 200 | 200 |
| KQL `ingest-package-policies.id:"x"` | 400, key does not exist in the saved-object index pattern | same |
| KQL `ingest-agent-policies.id:"nonexistent"` | 200, total 0 (no policies exist) | 200, total 1: the clause is ignored |
| KQL `ingest-agent-policies.name:"nonexistent"` | 200, total 0 | 200, total 0 |
| `format=simplified` package-policy list | 200 | 200 |
| Agent policies in the space | 0 | 1, preconfigured and hosted |
| Package policies in the space | 0 | 2 (`apm`, `fleet_server`), each with `policy_id` beside `policy_ids` and `spaceIds` |
| Preconfigured policy fields | n/a | `is_managed: true`, `is_preconfigured: true`, non-null data and monitoring output ids, `inactivity_timeout: 86400`, null `has_fleet_server`, `supports_agentless`, `agentless`, and `is_verifier` |
| `system` and `elastic_agent` packages | `not_installed` | `not_installed` |
| Installed packages | endpoint, fleet_server, security_ai_prompts, security_detection_engine | those plus apm and synthetics |

On 2026-09-04, the exact installed-package inventory route with
`perPage=1000&sortOrder=asc` returned `items.len() == total` and a non-empty
one-string `searchAfter` on both cloud targets. The cursor is the last item's
sort value even when the response contains the full result set.

After `system` 2.23.4 was installed out of band, its exact package response on
both cloud targets omitted package `vars` and put stream definitions under 18
top-level data streams: 20 distinct input/dataset pairs and 101 variable
definitions. Its policy template carried four input types and empty legacy
stream lists. Variable definitions omitted `secret`, which therefore means
false. A read-only `azure` 1.40.0 probe confirmed the multi-template join: 10
templates reuse one input type, each template lists short data-stream
selectors, and each selector resolves to a unique `azure.<selector>` dataset.

On Serverless 9.6.0, creating a `system` 2.23.4 marker with `inputs: {}`
materialized all four simplified inputs and 20 streams. Supplying those four
inputs as disabled with empty stream maps still materialized registry vars and
streams. Supplying the first complete simplified response on a second create
was stable: the create response and following GET returned the same input map.
The simplified update route rejected that stable map when the otherwise exact
body also carried top-level `enabled: true`, and accepted the same body after
that response-only field was removed.
Each bounded probe deleted the integration before its parent and ended with
both exact marker ids absent.

The marker agent-policy lifecycle recorded again on 2026-09-04, against
Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and the self-managed 9.5.1 lab.
Every probe measured identically on all three flavors.

| Probe | Serverless 9.6.0 | Hosted 9.5.2 | Self-managed 9.5.1 |
|---|---|---|---|
| `POST /api/fleet/setup` with `{}` | 200 `{"isInitialized": true, "nonFatalErrors": []}` | same | same |
| `POST /api/fleet/agent_policies?sys_monitoring=false` with explicit `id`, `name`, `namespace`, `description`, `monitoring_enabled: []`, `inactivity_timeout: 1209600` | 200; `item` echoes the id and adds `is_managed: false`, `is_protected: false`, `status: "active"`, `revision: 1`, `schema_version: "1.1.1"`, `space_ids: ["default"]`, `created_at`, `updated_at`, `updated_by`; no `agent_features`, `global_data_tags`, `keep_monitoring_alive`, output ids, or `agentless` | same | same |
| Server-filled defaults beyond the 5.1 table | none | none | none |
| `GET /api/fleet/agent_policies/{id}` | adds `agents: 0`, `unprivileged_agents`, `fips_agents`, `agents_per_version`, `package_policies: []` | same | same |
| `GET /api/fleet/agent_policies?page=1&perPage=1000&sortField=created_at&sortOrder=asc` | 200 `{items, total, page, perPage}` and no other key | same | same |
| Create with a taken name and a new id | 409, classified `conflict`, message `Agent Policy '<existing id>' already exists with name '<name>'` | same | same |
| `PUT /api/fleet/agent_policies/{id}` adding `unenroll_timeout: 3600` | 200, `item.unenroll_timeout: 3600` | same | same |
| `PUT` again omitting `unenroll_timeout` (description changed), then `GET` | `unenroll_timeout` still `3600`: the update route merges top-level fields | same | same |
| `POST /api/fleet/agent_policies/delete` `{"agentPolicyId": id}` | 200 `{"id", "name"}`; `GET` after is 404 `not_found` | same | same |
| `GET /api/fleet/epm/packages/elastic_agent` | `status: "not_installed"`, `version: "2.9.6"`, `latestVersion: "2.9.6"` | same | same |
| Installed-package inventory after the lifecycle | unchanged from before | unchanged | unchanged |

Fixtures: `tests/fixtures/<flavor>-<version>/{fleet_setup,
agent_policy_not_found, package_elastic_agent, agent_policy_create,
agent_policy_get, agent_policies_list, agent_policy_name_conflict,
agent_policy_update, agent_policy_update_omitted, agent_policy_get_after_omit,
agent_policy_delete, agent_policy_delete_not_found}.json`.

### 15.2 Source-derived

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
| Delete cascade | Agent delete removes single-parent integrations and detaches reusable ones |
| Delete refusals | Assigned agents, a hosted policy, or managed integrations refuse without `force` |
| Agent count | The single read populates `agents` only for a caller with Fleet agents read |
| Flattened agent-policy fields | `advanced_settings`, `overrides`, `monitoring_http`, `monitoring_diagnostics`, `global_data_tags`, and `required_versions` are mapped `flattened` and replaced whole on update; the top-level merge itself is measured in 15.1 |
| Monitoring install | Create installs `elastic_agent` for non-empty monitoring and tolerates an install error; update installs only when the stored `monitoring_enabled` is absent or null |
| Agent-policy defaults | `inactivity_timeout` defaults to 1209600 in the shared create and update request schema; `unenroll_timeout` is optional and not nullable |
| Nullable agent-policy fields | `data_output_id`, `monitoring_output_id`, `download_source_id`, `fleet_server_host_id`, `overrides`, `keep_monitoring_alive`, `supports_agentless`, `required_versions` |
| `agentless` | A nullable configuration object, not a boolean platform flag |
| `sys_monitoring` | A create query parameter that adds the System integration |
| `is_verifier` | Marks a short-lived policy used for OTel permission verification |
| Package-policy update | Inputs are recompiled from the package; the write is a full replacement |
| Package dependency | Package-policy create ensures the exact package version |
| `create_dataset_templates` | Present only in the create request schemas |
| Simplified create schema | Has no top-level `enabled`; `enabled` is per input and stream |
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
- [Kibana agent-policy request schema](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/types/models/agent_policy.ts)
- [Kibana agent-policy routes](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/types/rest_spec/agent_policy.ts)
- [Kibana agent-policy service](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/services/agent_policy.ts)
- [Kibana agent-policy create helper](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/services/agent_policy_create.ts)
- [Kibana agent-policy route handlers](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/routes/agent_policy/handlers.ts)
- [Kibana Fleet saved-object mappings](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/server/saved_objects/index.ts)
- [Kibana saved-object update merge](https://github.com/elastic/kibana/blob/v9.5.1/src/core/packages/saved-objects/api-server-internal/src/lib/apis/utils/merge_for_update.ts)
- [Kibana package-policy model](https://github.com/elastic/kibana/blob/v9.5.1/x-pack/platform/plugins/shared/fleet/common/types/models/package_policy.ts)
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
5. Target-local infrastructure, cross-space sharing, hosted and managed state,
   and secrets fail closed.
6. Exact packages are dependencies; absent packages may be installed by
   guarded create, but 0.6 never upgrades, downgrades, or uninstalls them.
7. Agent-policy delete refuses attached integrations even though Fleet can
   cascade or detach them.
8. The cut line is 0.6.0 agent policies, 0.6.1 integrations, and 0.6.2 proof.
9. Lists page by `created_at` and sort by id locally; `--search` is local,
   because the routes reject or ignore `id` in sorts and KQL.
10. Agent-policy replace sends the full spec with explicit nulls and refuses
    top-level removals the merge route cannot express; nested objects are
    replaced whole. Validate fills a fixed default table so sparse artifacts
    round-trip.
11. `create_dataset_templates` and top-level `enabled` are not portable
    integration fields; `policy_id` and `spaceIds` are normalized away.
12. The conformance contract may install and later uninstall exactly one
    `system` package version on a target that lacks it, and never touches a
    package it did not install.
13. The `elastic_agent` install is observed and reported, never required, and
    a missing `agents` count is a privilege error rather than a malformed
    response.
