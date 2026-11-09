[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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
empty object. The same check applies to an unchanged overwrite target; matching
an existing empty map does not exempt it from import validation.
Export writes the complete simplified input map returned by
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

