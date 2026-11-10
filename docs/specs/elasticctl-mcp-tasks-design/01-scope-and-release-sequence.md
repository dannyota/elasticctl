[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 1. Scope and release sequence

0.7 tools mirror commands: one tool, one object family. 0.8 tools mirror
questions. Each new tool reads several families in a fixed order and returns
one answer with an explicit status per part. The server stays read-only and
bound to the one deployment the operator selected at startup.

In scope:

- Four task tools: `alert_context`, `rule_health`, `detection_coverage`,
  `rule_readiness`.
- Two optional `rules_list` filters on the bounded page that 0.7.5 ships,
  and a verified corpus read for `detection_coverage`.
- Static server instructions.
- Resources: five listed resources and four resource templates.
- Prompts: four static prompts.
- A twelfth conformance contract and a two-client evidence matrix.

Out of scope: mutation and plans (0.9), durable protocol tasks, resource
subscriptions, list-changed notifications, argument completion, server-side
progressive discovery, HTTP hosting, OAuth, a client-config installer, new CLI
commands, and any tool that accepts a path, URL, target, or credential.

| Version | Deliverable | Required evidence before that version ships |
| --- | --- | --- |
| 0.8.0 | Four task tools, `rules_list` threat filters, server instructions, twelfth conformance contract | Recorded fixtures for every new request shape; unit, router, and SDK tests; exact 24 and 26 name catalogs through both binaries and both protocols; twelve-contract matrix on three flavors; latency gate in section 11.1; independent safety review |
| 0.8.1 | Resources and prompts | URI parser, registry, and prompt tests; both protocol paths; resource text equal to the matching tool text; extended twelfth contract rerun on three flavors |
| 0.8.2 | Real-client matrix, protocol gap tests, confirmed review fixes | Claude Code and Codex CLI runs on the local lab with captured frames; every 0.8 tool, resource, and prompt exercised; twelve-contract matrix on three flavors; final gates |

Every release in the band passes the three-flavor matrix. The gate is the
same for 0.8.0, 0.8.1, and 0.8.2 and is never weakened. The conformance
contract lands in 0.8.0, earlier than in 0.7, so that the decoder
measurements start while the current trial stacks exist. The plan is to run
the 0.8.1 and 0.8.2 live proofs inside the same trial window. If the window
closes first, the owner supplies replacement Serverless and Hosted stacks and
the version waits for them.

A defect found before a version ships belongs in that version. A missing
measurement stays open and blocks the version that needs it. It is never
inferred from another flavor or from CLI evidence.
