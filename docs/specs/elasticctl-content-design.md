# elasticctl dashboards and data views design

`data-views` and `dashboards` form the 0.5 capability area: portable Kibana
content and the administration needed to move it safely between spaces and
deployments. `data-views` manages the stable objects dashboards query through.
`dashboards` manages the typed, reviewable dashboard definition and offers an
explicit opaque bundle path when related saved objects must travel with it.

This spec follows `elasticctl-search-design.md` and
`elasticctl-triage-design.md`. It defers to `elasticctl-design.md` for
architecture, transport, rendering, error, guard, fixture, and release
contracts.

## Contents

| Section | Page |
|---|---|
| 1. Scope | [Read](elasticctl-content-design/01-scope.md#1-scope) |
| 2. Transfer is not reconciliation | [Read](elasticctl-content-design/02-transfer-is-not-reconciliation.md#2-transfer-is-not-reconciliation) |
| 3. Decisions | [Read](elasticctl-content-design/03-decisions.md#3-decisions) |
| 4. Command surface | [Read](elasticctl-content-design/04-command-surface.md#4-command-surface) |
| 5. Data-view model and portable artifact | [Read](elasticctl-content-design/05-data-view-model-and-portable-artifact.md#5-data-view-model-and-portable-artifact) |
| 6. Dashboard model and portable artifact | [Read](elasticctl-content-design/06-dashboard-model-and-portable-artifact.md#6-dashboard-model-and-portable-artifact) |
| 7. Opaque dashboard bundles | [Read](elasticctl-content-design/07-opaque-dashboard-bundles.md#7-opaque-dashboard-bundles) |
| 8. Selection, listing, and resolution | [Read](elasticctl-content-design/08-selection-listing-and-resolution.md#8-selection-listing-and-resolution) |
| 9. Mutation guard, imports, and races | [Read](elasticctl-content-design/09-mutation-guard-imports-and-races.md#9-mutation-guard-imports-and-races) |
| 10. Reference-safe data-view deletion | [Read](elasticctl-content-design/10-reference-safe-data-view-deletion.md#10-reference-safe-data-view-deletion) |
| 11. Architecture | [Read](elasticctl-content-design/11-architecture.md#11-architecture) |
| 12. Errors and reports | [Read](elasticctl-content-design/12-errors-and-reports.md#12-errors-and-reports) |
| 13. Fixtures and conformance | [Read](elasticctl-content-design/13-fixtures-and-conformance.md#13-fixtures-and-conformance) |
| 14. Measured behavior | [Read](elasticctl-content-design/14-measured-behavior.md#14-measured-behavior) |
| 15. Version placement | [Read](elasticctl-content-design/15-version-placement.md#15-version-placement) |
| 16. Decisions log | [Read](elasticctl-content-design/16-decisions-log.md#16-decisions-log) |
| 17. References | [Read](elasticctl-content-design/17-references.md#17-references) |
