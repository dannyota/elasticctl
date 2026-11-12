# elasticctl 0.9 MCP mutation design

Status: 0.9.0 implements the consent mechanism and the `rules-toggle` class,
and 0.9.1 the `alerts-triage`, `cases`, and `rules-create` classes. 0.9.2
registers the thirteenth conformance contract and records the two-client
consent matrix on Hosted; the 0.9 scope is complete. The live findings
([0.9.0](../conformance/v0.9.0-findings.md),
[0.9.1](../conformance/v0.9.1-findings.md),
[0.9.2](../conformance/v0.9.2/findings.md)) and the review records
([0.9.0](../reviews/v0.9.0.md), [0.9.1](../reviews/v0.9.1.md),
[0.9.2](../reviews/v0.9.2.md)) hold the evidence. Release and publication
each need separate approval.

The [shared design](elasticctl-design.md) defines existing behavior and the
[0.7 MCP design](elasticctl-mcp-design.md) defines the server this extends.
[Research](../plans/v0.9-research.md) records sources, probes, and unmeasured
claims. Plans: [0.9.0](../plans/v0.9.0.md), [0.9.1](../plans/v0.9.1.md),
[0.9.2](../plans/v0.9.2.md), and the [0.9.3](../plans/v0.9.3.md) cleanup.

0.9 answers one question: what consent means when the caller is a model. The
answer is that a model can ask for a change and a person at the client agrees
to it. The model never holds a switch that applies.

## Contents

| Section | Page |
|---|---|
| 1. Scope and release sequence | [Read](elasticctl-mcp-mutation-design/01-scope-and-release-sequence.md#1-scope-and-release-sequence) |
| 2. Consent model | [Read](elasticctl-mcp-mutation-design/02-consent-model.md#2-consent-model) |
| 2.1 What happens without elicitation | [Read](elasticctl-mcp-mutation-design/02-consent-model.md#21-what-happens-without-elicitation) |
| 2.2 Rejected alternatives | [Read](elasticctl-mcp-mutation-design/02-consent-model.md#22-rejected-alternatives) |
| 2.3 Limits of the model | [Read](elasticctl-mcp-mutation-design/02-consent-model.md#23-limits-of-the-model) |
| 3. Startup opt-in and catalog | [Read](elasticctl-mcp-mutation-design/03-startup-opt-in-and-catalog.md#3-startup-opt-in-and-catalog) |
| 4. Mutation set | [Read](elasticctl-mcp-mutation-design/04-mutation-set.md#4-mutation-set) |
| 4.1 Planner inputs | [Read](elasticctl-mcp-mutation-design/04-mutation-set.md#41-planner-inputs) |
| 5. Plans | [Read](elasticctl-mcp-mutation-design/05-plans.md#5-plans) |
| 5.1 Content and hash | [Read](elasticctl-mcp-mutation-design/05-plans.md#51-content-and-hash) |
| 5.2 Binding | [Read](elasticctl-mcp-mutation-design/05-plans.md#52-binding) |
| 5.3 Drift | [Read](elasticctl-mcp-mutation-design/05-plans.md#53-drift) |
| 5.4 States, expiry, and limits | [Read](elasticctl-mcp-mutation-design/05-plans.md#54-states-expiry-and-limits) |
| 5.5 Replay | [Read](elasticctl-mcp-mutation-design/05-plans.md#55-replay) |
| 6. Confirmation protocol | [Read](elasticctl-mcp-mutation-design/06-confirmation-protocol.md#6-confirmation-protocol) |
| 6.1 Consent text | [Read](elasticctl-mcp-mutation-design/06-confirmation-protocol.md#61-consent-text) |
| 6.2 Current protocol | [Read](elasticctl-mcp-mutation-design/06-confirmation-protocol.md#62-current-protocol) |
| 6.3 Legacy protocol | [Read](elasticctl-mcp-mutation-design/06-confirmation-protocol.md#63-legacy-protocol) |
| 7. API reuse | [Read](elasticctl-mcp-mutation-design/07-api-reuse.md#7-api-reuse) |
| 8. Apply, errors, limits, and cancellation | [Read](elasticctl-mcp-mutation-design/08-apply-errors-and-cancellation.md#8-apply-errors-limits-and-cancellation) |
| 8.4 Results and audit trail | [Read](elasticctl-mcp-mutation-design/08-apply-errors-and-cancellation.md#84-results-and-audit-trail) |
| 9. Testing and evidence | [Read](elasticctl-mcp-mutation-design/09-testing-and-evidence.md#9-testing-and-evidence) |
| 10. 0.8 dependencies | [Read](elasticctl-mcp-mutation-design/10-dependencies-on-0-8.md#10-08-dependencies) |
| 11. Decisions log | [Read](elasticctl-mcp-mutation-design/11-decisions-log.md#11-decisions-log) |

## The contract in ten lines

1. Without `--allow-mutations`, the server is the read-only server of 0.7 and
   0.8. Mutation tool names are unknown to the router.
2. The operator names mutation classes at startup. No tool call changes them.
3. A planner tool reads the stack, stores a plan in process memory, and
   returns a plan id. It sends no write.
4. `plan_apply` takes a plan id and no other input. No argument confirms.
5. `plan_apply` asks the client to show a server-written form. Only a form
   answer of `accept` with `apply: true` confirms.
6. A client that cannot show a form cannot apply through MCP. The person runs
   the CLI command the plan names.
7. A plan is bound to the target, the credential, the exact operation, and the
   state the planner saw. A changed target makes the plan stale.
8. A plan applies once, as one write request on its own connection. A repeat
   returns the first outcome.
9. A write that has been sent runs to its response. Its outcome is recorded
   even when the call was cancelled or timed out.
10. Every step writes one audit line to stderr with no secret and no free text
    from the stack.
