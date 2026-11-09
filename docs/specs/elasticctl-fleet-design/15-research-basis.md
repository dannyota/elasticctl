[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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
Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and self-managed 9.5.1 omitted
package `vars` and put stream definitions under 18 top-level data streams: 20
distinct input/dataset pairs and 101 variable definitions. Its policy template
carried four input types and empty legacy stream lists. Variable definitions
omitted `secret`, which therefore means false. A read-only `azure` 1.40.0 probe
confirmed the multi-template join: 10 templates reuse one input type, each
template lists short data-stream selectors, and each selector resolves to a
unique `azure.<selector>` dataset.

On all three supported targets, creating a `system` 2.23.4 marker with
`inputs: {}` materialized all four simplified inputs and 20 streams. Reusing
the first complete simplified response on the recorded create was stable
through create, get, list, update, and export round trip. The update request
omitted top-level `enabled`; every response reported `enabled: true` and kept
the exact input map. A bounded Serverless probe also found that supplying the
four inputs as disabled with empty stream maps still materialized registry vars
and streams. Its simplified update rejected the otherwise exact body when it
carried top-level `enabled: true`, then accepted the same body after that
response-only field was removed. Every recorder leg and bounded probe deleted
the integration before its parent and ended with both exact marker ids absent.

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

