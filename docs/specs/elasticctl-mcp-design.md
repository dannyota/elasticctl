# elasticctl 0.7 MCP design

Status: 0.7.0 implementation, live proof, and final evidence review are
complete. The 0.7.1 implementation, live proof, and final evidence review
completed on 2026-09-06. The 0.7.2 implementation, live proof, gates, and
final evidence review completed on 2026-09-06. Release and publication need
separate approval. The
[shared design](elasticctl-design.md) defines existing behavior.
[Research](../plans/v0.7-research.md) records sources, the 0.6.2 baseline,
and unmeasured claims.

From 0.9, `mcp serve --allow-mutations` lets the server also apply opt-in
changes, each through a stored plan that a person confirms in the client. The
[MCP mutation design](elasticctl-mcp-mutation-design.md) defines that path.
Without the flag the server stays read-only.

## Contents

| Section | Page |
|---|---|
| 1. Scope and release sequence | [Read](elasticctl-mcp-design/01-scope-and-release-sequence.md#1-scope-and-release-sequence) |
| 2. Architecture and alternatives | [Read](elasticctl-mcp-design/02-architecture-and-alternatives.md#2-architecture-and-alternatives) |
| 3. Protocol and dependencies | [Read](elasticctl-mcp-design/03-protocol-and-dependencies.md#3-protocol-and-dependencies) |
| 4. Startup target and local access | [Read](elasticctl-mcp-design/04-startup-target-and-local-access.md#4-startup-target-and-local-access) |
| 5. Exact catalog and input contracts | [Read](elasticctl-mcp-design/05-exact-catalog-and-input-contracts.md#5-exact-catalog-and-input-contracts) |
| Result projections | [Read](elasticctl-mcp-design/05-exact-catalog-and-input-contracts.md#result-projections) |
| Query behavior | [Read](elasticctl-mcp-design/05-exact-catalog-and-input-contracts.md#query-behavior) |
| 6. Output, errors, and bounds | [Read](elasticctl-mcp-design/06-output-errors-and-bounds.md#6-output-errors-and-bounds) |
| 7. Safety and compatibility proofs | [Read](elasticctl-mcp-design/07-safety-and-compatibility-proofs.md#7-safety-and-compatibility-proofs) |
| 8. Evidence and release contract | [Read](elasticctl-mcp-design/08-evidence-and-release-contract.md#8-evidence-and-release-contract) |
| 9. Subagent execution contract | [Read](elasticctl-mcp-design/09-subagent-execution-contract.md#9-subagent-execution-contract) |
