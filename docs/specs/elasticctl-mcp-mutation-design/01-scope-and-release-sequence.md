[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 1. Scope and release sequence

0.9 lets an MCP client change a bounded set of Elastic Security objects after
a person confirms each change. It extends the 0.7 stdio server. It keeps the
0.7 target, limit, error, and privacy rules unless a section here says
otherwise.

In scope: four mutation classes, seven planner tools, four plan tools, the
plan store, confirmation on both supported protocol revisions, and an audit
trail on stderr.

Out of scope:

- any apply without a person's confirmation, including unattended or
  scheduled use. Automation uses the CLI with `--yes`;
- deletes of any object, content changes to an existing rule, exception
  items, alert and case assignment, query-scoped alert transitions, case
  attach, data view and dashboard import, Fleet changes, prebuilt install,
  and `state push` ([section 4](04-mutation-set.md#4-mutation-set));
- local file input or output, an audit file, HTTP hosting, and OAuth;
- the MCP tasks extension and URL mode elicitation;
- new CLI commands. CLI output changes in one place: a case status conflict
  error gains `http_status`.

| Version | Deliverable | Required evidence before that version ships |
| --- | --- | --- |
| 0.9.0 | `--allow-mutations`, plan store, confirmation on both protocol paths, audit lines, class `rules-toggle`, and every `-api` addition 0.9 needs | SDK tests on both paths; route proofs; CLI snapshots unchanged; all live measurements M1 to M9 on three flavors; live MCP toggle on three flavors; one real client confirming on the lab; independent adversarial review |
| 0.9.1 | Classes `alerts-triage`, `cases`, `rules-create` | Schemas and route proofs for six planners; fixture-backed tests; live MCP pass for the six tools on three flavors; independent review |
| 0.9.2 | Thirteenth conformance contract, two-client consent matrix, confirmed review fixes | `mcp_mutations_plan_and_confirm` passing on three flavors; Claude Code and Codex CLI matrix on the lab; whole-range review |

These are release scopes, not dates. A defect found before a version ships
belongs in that version. A later evidence release does not postpone an earlier
version's gates.

Why this split:

- 0.9.0 carries the mechanism and `rules-toggle`, the class with the
  strongest re-check and the best measured route. The owner chose it as the
  first class on 2026-11-10.
- 0.9.0 also lands the whole `-api` delta and runs every live measurement.
  Live stacks are available briefly. After 0.9.0, the remaining live work is
  one MCP pass per later version, and the harness for it already exists.
- 0.9.1 adds adapters only. No new consent rule, store rule, or API function.
- 0.9.2 changes no runtime behavior unless evidence confirms a defect.

0.9 follows 0.8. The `-mcp` and CLI work branches from the released 0.8.2
tag, because both bands edit the same catalog, handler, and command files.
The `-api` files both bands edit belong to one serialized integration task
per version; the 0.9.0 one starts only after the 0.8.0 one is merged
([section 10](10-dependencies-on-0-8.md#shared-files-and-order-of-work)).
