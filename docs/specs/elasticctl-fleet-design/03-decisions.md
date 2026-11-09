[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

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

