# elasticctl 0.8.0 conformance findings

All twelve contracts passed on all three targets, including the new
`mcp_answers_across_verticals`.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 12 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 12 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 12 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

The Serverless and Hosted legs ran from the main development machine at
source commit `afe14794778ed774300e67531f6afdb4ea5bb32f`: Hosted from
`2026-11-10T07:40:57Z` to `08:02:37Z`, Serverless again from
`2026-11-10T08:03:20Z` to `08:24:44Z`. The self-managed leg is the Live lab
run on the release branch at `5ae79e3d545bf50fdd26383a2c1acdab4085b575`, from
`2026-11-10T08:59:20Z` to `09:15:06Z`, against a disposable 9.5.1 lab.

## The first Serverless leg

The first Serverless leg failed one contract, `content`: a dashboard delete
answered with a connection error before any response. Cleanup and the
baseline audit passed, so the leg went on and the other eleven contracts
passed. An independent check afterwards found no marker dashboard, data
view, or rule on the project. The rerun above passed all twelve. No code
changed between the two runs.

## Latency gate M9

The gate is 15 seconds. `detection_coverage` is held to it for one
eight-page pass and to the 30-second default deadline for two passes, the
rule the owner set on 2026-11-10 (tasks design section 11.1).

Slowest maximum-work call of each tool, current protocol:

| Tool | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 | Gate |
| --- | --- | --- | --- | --- |
| `alert_context` (19 requests) | 2.5 s | 3.2 s | not recorded | pass |
| `rule_health` (14 requests) | 1.5 s | 1.8 s | 1 s | pass |
| `rule_readiness` (29 requests) | 6.1 s | 6.5 s | 2 s | pass |

The self-managed `alert_context` line was not printed: the harness wrote
the first timing line on the same line as the test name, and the runner
forwards only lines in the exact timing format. The harness starts a fresh
line in this release. The contract itself passed on that leg.

`detection_coverage` with default arguments, two calls in a row:

| Flavor | Rules | Pages | Call 1 | Call 2 | Worst per page |
| --- | --- | --- | --- | --- | --- |
| Serverless 9.7.0 | 2,263 | 5 | 9.9 s | 8.8 s | 1.98 s |
| Hosted 9.5.6 | 2,263 | 5 | 7.5 s | 6.8 s | 1.51 s |
| Self-managed 9.5.1 | 4,000 | 8 | 3 s | 3 s | 0.38 s |

The worst per-page time is 1.98 seconds, from the first Serverless call.
Eight pages at that rate take 15.8 seconds and sixteen take 31.7 seconds.
The Cloud harness runs a debug build; a release build of the same server,
timed by hand against both Cloud stacks, read the five pages in 6.2 to 8.2
seconds, at most 1.65 seconds a page: 13.2 seconds for eight pages and 26.3
for sixteen. A debug build timed the same way took 6.4 to 8.9 seconds, so
the time is spent on the network and the server more than in the client.
One pass over 4,000 rules fits the gate on the release build, and two
passes fit the 30-second default deadline. On the debug build the eight-page
estimate is 0.8 seconds over the gate; the measured eight-page pass on the
lab took 3 seconds.

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

The live contract runs the MCP server from a debug build. Real product
clients are checked in 0.8.2. Raw results and timings stay in private
ignored logs; only whole-second timing lines reach public output.
