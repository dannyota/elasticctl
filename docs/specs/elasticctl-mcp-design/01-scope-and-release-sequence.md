[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 1. Scope and release sequence

0.7 provides read-only MCP tools over existing Elastic capability areas.
The default server inspects an operator-selected deployment. Raw synchronous
queries require a separate startup flag because they can invoke downstream
inference services. No tool creates durable Elastic objects or reads or
writes arbitrary local files.

| Version | Deliverable | Required evidence before that version ships |
| --- | --- | --- |
| 0.7.0 | stdio server, seven stack/rule/exception tools, limits, error boundary, four-crate packaging | Current and legacy protocol tests; one real client; three-flavor reads for these tools; independent safety and release review |
| 0.7.1 | Thirteen more inspection tools; two opt-in synchronous query tools | All new schemas and route contracts; query admission and cancellation; three-flavor reads for new tools |
| 0.7.2 | Broader client matrix, integrated MCP conformance contract, confirmed review fixes | Two independent client implementations; all MCP tools exercised; eleven-contract release matrix |

These are proposed release scopes, not promised dates. A defect found before
0.7.0 ships belongs in 0.7.0. The later evidence release does not postpone
an earlier version's gates. Further 0.7 patches carry compatible fixes and
small additions within this read-only surface.

Resources, prompts, task-shaped cross-vertical tools, progressive discovery,
and durable protocol tasks remain outside 0.7. Mutation plans and confirmation
remain in 0.9. HTTP hosting and OAuth need a separate design. There is no
generic command runner, shell, HTTP proxy, file tool, export, state command,
rule preview, Fleet setup, or package installer.

