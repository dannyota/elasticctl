# elasticctl 0.8.0 conformance findings

All twelve contracts passed on all three targets at the release commit,
including the new `mcp_answers_across_verticals`.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 12 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 12 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 12 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `0881ee38a5e0dc9c7e5d422a4acc8f97001b9691`.
The Serverless and Hosted legs ran together from the development host from
`2026-11-10T09:30:40Z` to `09:58:15Z`, with the client built at optimization
level 3. The self-managed leg is the Live lab run on the release branch from
`2026-11-10T09:30:41Z` to `09:42:51Z`, against a disposable 9.5.1 lab.

## Earlier runs

The same contracts ran earlier the same day at `afe1479` and `5ae79e3`. In
the first of those, Serverless failed one contract, `content`: a dashboard
delete answered with a connection error before any response. Cleanup and the
baseline audit passed, an independent check found no marker object left, and
the rerun passed all twelve. The release commit adds refusals for an invalid
Kibana space and for response ids that would leave their URL path segment,
so all three legs ran again on it.

## Latency gate M9

The gate is 15 seconds for `alert_context`, `rule_health`, and
`rule_readiness`. `detection_coverage` is held to the 30-second default
deadline for one eight-page pass over 4,000 rules, the rule the owner set on
2026-11-10 (tasks design section 11.1).

Slowest maximum-work call of each tool, current protocol:

| Tool | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 | Gate |
| --- | --- | --- | --- | --- |
| `alert_context` (19 requests) | 2.9 s | 4.1 s | 1 s | pass |
| `rule_health` (14 requests) | 2.6 s | 2.0 s | 1 s | pass |
| `rule_readiness` (29 requests) | 8.6 s | 7.2 s | 2 s | pass |

Self-managed values are the public whole-second lines; the Cloud values come
from the private timing log.

`detection_coverage` with default arguments, two calls in a row:

| Flavor | Rules | Pages | Call 1 | Call 2 | Worst per page |
| --- | --- | --- | --- | --- | --- |
| Serverless 9.7.0 | 2,263 | 5 | 10.3 s | 11.0 s | 2.20 s |
| Hosted 9.5.6 | 2,263 | 5 | 14.9 s | 9.1 s | 2.99 s |
| Self-managed 9.5.1 | 4,000 | 8 | 2 s | 2 s | 0.25 s |

The worst per-page time is 2.99 seconds, from the first Hosted call. Eight
pages at that rate take 23.9 seconds, inside the 30-second deadline, so one
pass over 4,000 rules passes. Sixteen pages, two passes, take 47.8 seconds;
the second pass runs only when the rules change during the first, and the
tool description tells the caller that a call near the limit can need a
longer `--timeout`, up to 120 seconds.

Page time on the Cloud stacks is network transfer of about 4.4 MB a page
from the development host. It ranged from 1.2 to 3.0 seconds a page across
the day's runs and by-hand timings, with debug and optimized builds alike;
the lab on the CI runner read a page in 0.25 to 0.38 seconds.

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
