[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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

