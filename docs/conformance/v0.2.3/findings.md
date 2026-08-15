# elasticctl 0.2.3 Conformance Findings

All six contracts passed on all three targets. No release-worthy 0.2 defect
was found, so 0.2.4 is skipped and the next design is 0.3.0 search.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 6 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 6 pass | [ech-9.5.1.json](ech-9.5.1.json) |
| Self-managed | 9.5.1 | 6 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

No contract failed or skipped. Cleanup audits passed after every contract and
the final rule partitions matched each target's captured baseline.
