# elasticctl 0.8.1 conformance findings

All twelve contracts passed on all three targets at the release head,
including `mcp_answers_across_verticals`, which now also covers resources and
prompts.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 12 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 12 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 12 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `5ecdea353d35d02b6f2c5a61c58472f4cb661a02`.
Serverless and Hosted ran at the same time from two work trees with separate
build directories, the client built at optimization level 3 on the
development host, from `2026-11-10T16:42:06Z` to `16:59:16Z`. The
self-managed leg is the Live lab run on the release pull request from
`16:47:56Z` to `16:57:35Z`, against a disposable 9.5.1 lab. The two later
commits, `9244203` and `704b582`, change only offline tests in the live test
harness.

## Resources and prompts, measurement M10

On every flavor the current-protocol child checked, against literals:

- `server/discover` capabilities: exactly `prompts`, `resources`, and `tools`;
- `resources/list`, `resources/templates/list`, and `prompts/list`;
- a read of each of the five listed resources, and of the four templates
  with the marker alert, the marker case, the marker exception list in the
  `single` namespace, and the marker rule by `rule_id`;
- for each of the nine reads, the matching tool call with the arguments of
  tasks design section 8.3, with equal text;
- `prompts/get` for each of the four prompts with marker ids, equal to the
  literal text of tasks design section 9.3.

An absent rule id and a URI with authority `plans` returned `-32602` on the
current protocol `2026-07-28` and `-32002` on the legacy protocol
`2025-11-25`, both with `Resource not found` and no `data`. M10 passed on all
three flavors. A text mismatch may be retried once as a pair; the run does
not record whether any pair used its retry.

## Latency, measurement M9

The 0.8.0 gates still hold. Slowest maximum-work call of each tool, from the
public whole-second lines:

| Tool | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 | Gate |
| --- | --- | --- | --- | --- |
| `alert_context` | 3 s | 3 s | 1 s | pass |
| `rule_health` | 2 s | 2 s | 1 s | pass |
| `rule_readiness` | 5 s | 7 s | 2 s | pass |
| `detection_coverage`, two calls | 5 s, 4 s, 5 pages | 5 s, 4 s, 5 pages | 2 s, 2 s, 8 pages | pass |

The worst Cloud page time is about one second, so one eight-page pass stays
well inside the 30-second default deadline.

## First run at the release branch

The first run, at `55584df`, failed `mcp_answers_across_verticals` on all
three flavors with `MCP resource result did not match.`, and cleanup and the
audits passed. The live check expected a current-protocol `resources/read`
result without the `ttlMs` and `cacheScope` fields the server sends. The fix
checks every frame kind the contract validates against a real server child
offline first. The run above is after that fix.

## Cleanup and evidence limits

Every contract and end-of-leg audit passed: rule counts, the default data
view, Fleet marker inventories, and installed package names and versions
matched their baselines, and no marker object remained. The lab fill of
4,000 rules was removed and the lab destroyed with its runner.

Resource reads and prompts are not timed. Real product clients, including
whether a client sends a template URI that is not listed, are checked in
0.8.2. Raw results stay in private ignored logs; only whole-second timing
lines reach public output.
