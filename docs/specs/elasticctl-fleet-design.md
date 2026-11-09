# elasticctl Fleet policy design

`fleet agent-policies` and `fleet integration-policies` form the 0.6
capability area: reviewable Fleet configuration that can be administered and
moved safely between spaces and deployments. An agent policy configures a set
of Elastic Agents. An integration policy is one configured integration inside
one or more agent policies; Elastic's API and source call it a package policy.

These are not detection rules. Detection rules remain under `rules` and search
indexed data to create security alerts. There is no single generic Elastic
"platform policy" resource.

This spec follows `elasticctl-content-design.md`. It defers to
`elasticctl-design.md` for architecture, transport, rendering, error, guard,
fixture, conformance, and release contracts.

## Contents

| Section | Page |
|---|---|
| 1. Scope | [Read](elasticctl-fleet-design/01-scope.md#1-scope) |
| 2. Transfer is not reconciliation | [Read](elasticctl-fleet-design/02-transfer-is-not-reconciliation.md#2-transfer-is-not-reconciliation) |
| 3. Decisions | [Read](elasticctl-fleet-design/03-decisions.md#3-decisions) |
| 4. Command surface | [Read](elasticctl-fleet-design/04-command-surface.md#4-command-surface) |
| 5. Agent-policy model | [Read](elasticctl-fleet-design/05-agent-policy-model.md#5-agent-policy-model) |
| 5.1 Server-applied defaults | [Read](elasticctl-fleet-design/05-agent-policy-model.md#51-server-applied-defaults) |
| 5.2 Normalization and unsupported states | [Read](elasticctl-fleet-design/05-agent-policy-model.md#52-normalization-and-unsupported-states) |
| 5.3 Create and replace | [Read](elasticctl-fleet-design/05-agent-policy-model.md#53-create-and-replace) |
| 6. Integration-policy model | [Read](elasticctl-fleet-design/06-integration-policy-model.md#6-integration-policy-model) |
| 7. Secrets and environment references | [Read](elasticctl-fleet-design/07-secrets-and-environment-references.md#7-secrets-and-environment-references) |
| 8. Package dependencies | [Read](elasticctl-fleet-design/08-package-dependencies.md#8-package-dependencies) |
| 9. Selection and listing | [Read](elasticctl-fleet-design/09-selection-and-listing.md#9-selection-and-listing) |
| 10. Import planning and races | [Read](elasticctl-fleet-design/10-import-planning-and-races.md#10-import-planning-and-races) |
| 11. Safe deletion | [Read](elasticctl-fleet-design/11-safe-deletion.md#11-safe-deletion) |
| 12. Architecture | [Read](elasticctl-fleet-design/12-architecture.md#12-architecture) |
| 13. Errors and reports | [Read](elasticctl-fleet-design/13-errors-and-reports.md#13-errors-and-reports) |
| 14. Fixtures and conformance | [Read](elasticctl-fleet-design/14-fixtures-and-conformance.md#14-fixtures-and-conformance) |
| 15. Research basis | [Read](elasticctl-fleet-design/15-research-basis.md#15-research-basis) |
| 15.1 Measured | [Read](elasticctl-fleet-design/15-research-basis.md#151-measured) |
| 15.2 Source-derived | [Read](elasticctl-fleet-design/15-research-basis.md#152-source-derived) |
| 16. Version placement | [Read](elasticctl-fleet-design/16-version-placement.md#16-version-placement) |
| 17. Decisions log | [Read](elasticctl-fleet-design/17-decisions-log.md#17-decisions-log) |
