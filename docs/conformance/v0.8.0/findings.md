# elasticctl 0.8.0 conformance findings

All twelve contracts passed on all three targets at the release commit,
including the new `mcp_answers_across_verticals`.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 12 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 12 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 12 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `b330988203b986c83c767778fcf3a4a696f71d13`,
the release head, with the client built at optimization level 3 on the
development host. Serverless ran from `2026-11-10T11:39:50Z` to `12:03:34Z`.
Hosted ran alone from `12:03:58Z` to `12:18:48Z`. The self-managed leg is the
Live lab run on the release branch from `11:37:07Z` to `11:51:51Z`, against a
disposable 9.5.1 lab.

## Earlier runs

The same contracts ran earlier the same day at `afe1479`, `5ae79e3`, and
`0881ee3`. Two runs failed one contract each, both `content`, with cleanup
and the baseline audit passing: at `afe1479` a Serverless dashboard delete
answered with a connection error, and at `b330988` a Hosted leg run alongside
Serverless could not start the `elasticctl` binary while the other leg's
build relinked it. Hosted then ran alone and passed all twelve. Later commits
added refusals for an invalid Kibana space and for response ids that would
leave their URL path segment, and a sentence in the `detection_coverage`
description, so all three legs ran again at the release head.

## Latency gate M9

The gate is 15 seconds for `alert_context`, `rule_health`, and
`rule_readiness`. `detection_coverage` is held to the 30-second default
deadline for one eight-page pass over 4,000 rules, the rule the owner set on
2026-11-10 (tasks design section 11.1).

Slowest maximum-work call of each tool at the release head, current
protocol:

| Tool | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 | Gate |
| --- | --- | --- | --- | --- |
| `alert_context` (19 requests) | 1.8 s | 2.4 s | 1 s | pass |
| `rule_health` (14 requests) | 1.5 s | 1.4 s | 1 s | pass |
| `rule_readiness` (29 requests) | 5.3 s | 4.8 s | 1 s | pass |

Self-managed values are the public whole-second lines; the Cloud values come
from the private timing log.

`detection_coverage` with default arguments, two calls in a row, at the
release head:

| Flavor | Rules | Pages | Call 1 | Call 2 | Worst per page |
| --- | --- | --- | --- | --- | --- |
| Serverless 9.7.0 | 2,263 | 5 | 3.9 s | 3.7 s | 0.78 s |
| Hosted 9.5.6 | 2,263 | 5 | 3.8 s | 3.7 s | 0.76 s |
| Self-managed 9.5.1 | 4,000 | 8 | 3 s | 2 s | 0.38 s |

At the release head the worst per-page time is 0.78 seconds: 6.2 seconds for
eight pages and 12.5 for sixteen, inside even the 15-second gate. Page time
on the Cloud stacks is network transfer of about 4.4 MB a page from the
development host and varied through the day. The slowest read, at
`0881ee3`, was a Hosted call of 14.9 seconds for five pages, 2.99 seconds a
page: 23.9 seconds for eight pages, still inside the 30-second deadline, and
47.8 seconds for sixteen. The second pass runs only when the rules change
during the first, and the tool description tells the caller that a call
near the limit can need a longer `--timeout`, up to 120 seconds.

## Frames

The `tools/list` frame is 86,255 bytes by default and 92,362 with query tools
on the current protocol path, under the 1,048,576-byte frame cap.

## Cleanup and evidence limits

Every contract and end-of-leg audit passed: rule counts, the default data
view, Fleet marker inventories, and installed package names and versions
matched their baselines, and no marker object remained. Hosted gained the
Fleet `system` 3.5.0 package before the matrix, for fixture recording; it
stays installed and is part of the baseline. The lab fill of 4,000 rules was
removed and the lab destroyed with its runner.

Real product clients are checked in 0.8.2. Raw results and timings stay in
private ignored logs; only whole-second timing lines reach public output.
