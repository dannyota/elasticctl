# elasticctl 0.10.0 conformance findings

All fourteen contracts passed on all three targets. The fourteenth,
`value_list_round_trip`, is new in 0.10.0: it bootstraps the list streams,
pulls and pushes value lists through `state`, checks the read-back as
multisets, previews which events alert under both operators before and after
the edit, confirms the three local refusals send no write, checks the 409 for
a referenced delete and that the list survives, and cleans up to the
recorded baseline.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 14 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 14 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 14 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `f2b91e81ad96624bfb960da07fc29767cb139d15`.
The two Cloud legs ran in one matrix process from `2026-11-13T21:54:52Z` to
`22:13:01Z`, which exited 0 with no re-run. The self-managed leg is Live lab
run 43514830120 on `dev-0.10` at the same commit; its matrix step ran from
`21:57:01Z` to `22:07:38Z`, about 637 seconds of the job's 22-minute budget,
and the teardown step succeeded. The published lab report is byte-identical
to the run's `live-lab-public` artifact. No separate read-only preflight ran;
each contract's initial and final baseline checks passed.

`mcp_answers_across_verticals` timings:

| Stack | alert_context | rule_health | rule_readiness | detection_coverage |
| --- | --- | --- | --- | --- |
| Hosted | 3 s | 2 s | 6 s | 6 s, 5 pages |
| Serverless | 2 s | 2 s | 6 s | 4 s, 5 pages |

`scripts/check-conformance-reports.sh` passes, and the reports hold no URL,
UUID, localhost address, or API key prefix.

## Offline evidence

The value-list fixtures were recorded on the same three stacks and frozen at
84 per flavor (#154). Every offline test of the value-lists design 9.2 loads
its bodies from them; faults are injected with recorded bodies only, and a
request that cannot be scoped to marker objects is recorded with a marker
filter while its test asserts the production request.
