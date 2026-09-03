# elasticctl 0.5.2 Conformance Findings

All nine contracts passed on all three targets. 0.5.2 adds the `content`
contract to the eight 0.4 contracts and proves portable data-view transfer,
typed and opaque dashboard transfer, reference replacement, exact default
restoration, and zero content residue across all supported deployment flavors.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 9 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 9 pass | [ech-9.5.2.json](ech-9.5.2.json) |
| Self-managed | 9.5.1 | 9 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

No contract failed or skipped. Cleanup audits passed after every contract. Each
leg ended with zero marker dashboards, data views, and indices. The exact
captured default data-view id was restored on both persistent cloud targets.
Prebuilt-rule counts matched each target's captured baseline. The self-managed
lab was destroyed with its containers and volumes.

## Residue and deviations

The content contract tolerates no residue, and none remained. The older triage
contract still permits only closed marker alerts because the public API has no
alert delete; its baseline excludes closed alerts and requires zero open marker
alerts. No new cross-flavor deviation was found by the content lifecycle.

## Fixes before the passing matrix

The bounded release review found that recorder cleanup could advance past a
failed dashboard or data-view dependency. Commit `c21418b` derives each cleanup
gate from retained ownership and adds regressions for both dependency edges.

The first Serverless content smoke found that the live probe sent a body to the
Elasticsearch refresh route. Commit `3f64fc8` changed the refresh to the
bodyless GET form already used by the fixture recorder and added an offline
request-shape regression. The Serverless smoke then passed, followed by the
complete matrix from candidate
`3f64fc8f86cff02616b02b586cbe7f308c60d60c`.
