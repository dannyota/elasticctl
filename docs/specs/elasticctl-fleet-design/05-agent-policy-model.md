[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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

