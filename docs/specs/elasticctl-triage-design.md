# elasticctl alerts and cases design

`alerts` and `cases` form the 0.4 capability area: the triage layer a
detection engineer works after a rule fires. `alerts` reads and transitions
detection alerts; `cases` tracks investigations and binds alerts to them. Both
verticals mutate remote state, so both carry the full dry-run guard, unlike
the read-only 0.3 `search` area.

This spec follows the shape of `elasticctl-search-design.md` and defers to
`elasticctl-design.md` for architecture, transport, and shared contracts.

## Contents

| Section | Page |
|---|---|
| 1. Scope | [Read](elasticctl-triage-design/01-scope.md#1-scope) |
| 2. Triage is operational, not as-code | [Read](elasticctl-triage-design/02-triage-is-operational-not-as-code.md#2-triage-is-operational-not-as-code) |
| 3. Decisions | [Read](elasticctl-triage-design/03-decisions.md#3-decisions) |
| 4. Command surface | [Read](elasticctl-triage-design/04-command-surface.md#4-command-surface) |
| 5. Mutation guard | [Read](elasticctl-triage-design/05-mutation-guard.md#5-mutation-guard) |
| 6. Query-scoped transitions | [Read](elasticctl-triage-design/06-query-scoped-transitions.md#6-query-scoped-transitions) |
| 7. Assignment and username resolution | [Read](elasticctl-triage-design/07-assignment-and-username-resolution.md#7-assignment-and-username-resolution) |
| 8. Architecture placement | [Read](elasticctl-triage-design/08-architecture-placement.md#8-architecture-placement) |
| 9. Fixtures and conformance | [Read](elasticctl-triage-design/09-fixtures-and-conformance.md#9-fixtures-and-conformance) |
| 10. Measured behavior | [Read](elasticctl-triage-design/10-measured-behavior.md#10-measured-behavior) |
| 11. Version placement | [Read](elasticctl-triage-design/11-version-placement.md#11-version-placement) |
| 12. Decisions log | [Read](elasticctl-triage-design/12-decisions-log.md#12-decisions-log) |
| 13. References | [Read](elasticctl-triage-design/13-references.md#13-references) |
