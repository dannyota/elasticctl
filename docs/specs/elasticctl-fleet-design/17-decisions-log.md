[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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
