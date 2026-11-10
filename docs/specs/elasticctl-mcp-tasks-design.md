# elasticctl 0.8 MCP task tools, resources, and prompts

Status: 0.8.0 implements sections 4 to 7 and 10: the four task tools, the
`rules_list` threat filters, the verified corpus read, and the server
instructions. Sections 8 and 9, resources and prompts, are 0.8.1. Release and
publication each need separate approval. The
[0.7 MCP design](elasticctl-mcp-design.md) stays in force; this document only
adds to it. [Research](../plans/v0.8-research.md) records sources, measured
facts, and evidence gaps. Plans: [0.8.0](../plans/v0.8.0.md),
[0.8.1](../plans/v0.8.1.md), [0.8.2](../plans/v0.8.2.md).

0.8 adds four read-only tools that answer questions spanning several
capability areas, a small resource surface, and four prompts. It changes no
Elastic object and reads or writes no local file. Mutation is 0.9.

## Contents

| Section | Page |
|---|---|
| 1. Scope and release sequence | [Read](elasticctl-mcp-tasks-design/01-scope-and-release-sequence.md#1-scope-and-release-sequence) |
| 2. Decisions and alternatives | [Read](elasticctl-mcp-tasks-design/02-decisions-and-alternatives.md#2-decisions-and-alternatives) |
| 3. Protocol and capabilities | [Read](elasticctl-mcp-tasks-design/03-protocol-and-capabilities.md#3-protocol-and-capabilities) |
| 4. Composition contract | [Read](elasticctl-mcp-tasks-design/04-composition-contract.md#4-composition-contract) |
| 4.1 Parts and partial failure | [Read](elasticctl-mcp-tasks-design/04-composition-contract.md#41-parts-and-partial-failure) |
| 4.2 Shared building blocks | [Read](elasticctl-mcp-tasks-design/04-composition-contract.md#42-shared-building-blocks) |
| 4.3 Flavor behavior | [Read](elasticctl-mcp-tasks-design/04-composition-contract.md#43-flavor-behavior) |
| 5. `alert_context` and `rule_health` | [Read](elasticctl-mcp-tasks-design/05-alert-context-and-rule-health.md#5-alert_context-and-rule_health) |
| 6. `detection_coverage` and `rule_readiness` | [Read](elasticctl-mcp-tasks-design/06-detection-coverage-and-rule-readiness.md#6-detection_coverage-and-rule_readiness) |
| 7. Catalog and discovery | [Read](elasticctl-mcp-tasks-design/07-catalog-and-discovery.md#7-catalog-and-discovery) |
| 7.1 `rules_list` changes | [Read](elasticctl-mcp-tasks-design/07-catalog-and-discovery.md#71-rules_list-changes) |
| 7.2 Server instructions | [Read](elasticctl-mcp-tasks-design/07-catalog-and-discovery.md#72-server-instructions) |
| 8. Resources | [Read](elasticctl-mcp-tasks-design/08-resources.md#8-resources) |
| 9. Prompts | [Read](elasticctl-mcp-tasks-design/09-prompts.md#9-prompts) |
| 10. Bounds, errors, and safety | [Read](elasticctl-mcp-tasks-design/10-bounds-errors-and-safety.md#10-bounds-errors-and-safety) |
| 11. Measured behavior | [Read](elasticctl-mcp-tasks-design/11-measured-behavior.md#11-measured-behavior) |
| 11.1 Required measurements | [Read](elasticctl-mcp-tasks-design/11-measured-behavior.md#111-required-measurements) |
| 12. Evidence and release contract | [Read](elasticctl-mcp-tasks-design/12-evidence-and-release-contract.md#12-evidence-and-release-contract) |
| 13. Interface for 0.9 | [Read](elasticctl-mcp-tasks-design/13-interface-for-09.md#13-interface-for-09) |
