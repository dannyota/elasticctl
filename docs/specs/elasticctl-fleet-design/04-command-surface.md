[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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

An integration with a protected custom parent remains in the `--all-custom`
selection and fails the export as `unsupported`; protection alone does not
make its parent platform-owned.

Mutating commands reject an empty target before building a transport.

