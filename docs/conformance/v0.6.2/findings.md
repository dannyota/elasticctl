# elasticctl 0.6.2 Conformance Findings

All ten contracts passed on all three targets. The new Fleet contract proves
agent-policy and integration-policy transfer, exact exports and reimports,
conflict and overwrite behavior, attached-parent refusal, and guarded cleanup.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 10 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 10 pass | [ech-9.5.2.json](ech-9.5.2.json) |
| Self-managed | 9.5.1 | 10 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

The matrix ran on 2026-09-05 from development commit `30e66f6`. No contract
failed or skipped. Every Fleet child ran its exact live test and passed.

Cleanup audits passed after every contract and at the end of each leg. All
Fleet marker agent and integration policies were absent, and each installed
package name/version inventory matched its captured baseline. Rule counts
(custom, prebuilt, and customized) and the exact default data view matched
their baselines. No marker rules, exception lists, indices, dashboards, data
views, cases, or open alerts remained. The self-managed lab was destroyed;
independent checks found zero remaining lab containers and volumes. Hosted
remained running.

## Residue and deviations

Fleet permits no marker residue or package inventory drift. No cross-flavor
deviation was found. The older triage contract still permits closed marker
alerts because the public API has no alert delete. Its baseline excludes
closed alerts and requires zero open marker alerts and zero marker cases.

## Bounded fixes

Integration-policy get and export now reject a mismatched exact id or a fresh
read inconsistent with the selected list summary. Offline regressions cover
those malformed responses. Review also tightened setup ordering, cleanup
ownership and mutation-attempt retention, package consumer checks, bootstrap
validation, and exact CLI assertions before this passing matrix.

The report schema and privacy checks passed. Public evidence contains only
versions, contract outcomes, and aggregate findings; raw output remains in
private ignored logs.
