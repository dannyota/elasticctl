# elasticctl 0.3.1 Conformance Findings

All seven contracts passed on all three targets. 0.3.1 adds the `search`
contract (ES|QL and Query DSL read the marked scratch documents) to the six
0.2 contracts, and the matrix proves the search vertical behaves identically
across Serverless, Hosted, and the self-managed 9.5.1 compatibility floor.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 7 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 7 pass | [ech-9.5.1.json](ech-9.5.1.json) |
| Self-managed | 9.5.1 | 7 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

No contract failed or skipped. Cleanup audits passed after every contract and
the final rule partitions matched each target's captured baseline. The
disposable self-managed lab installed its complete 2,066-rule prebuilt pack
before baseline capture and was destroyed with its volumes after the
traditional run.
