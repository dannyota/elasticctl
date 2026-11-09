[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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

