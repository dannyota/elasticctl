# elasticctl 0.2.5 Conformance Findings

All six contracts passed on all three targets. 0.2.5 hardens filesystem and
configuration boundaries and the report leak gate; it does not change the six
live contracts on valid input, so the matrix proves the patch left cross-flavor
behavior intact.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 6 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 6 pass | [ech-9.5.1.json](ech-9.5.1.json) |
| Self-managed | 9.5.1 | 6 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

No contract failed or skipped. Cleanup audits passed after every contract and
the final rule partitions matched each target's captured baseline. The
disposable self-managed lab and its volumes were removed after the traditional
run.
