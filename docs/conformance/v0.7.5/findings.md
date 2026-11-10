# elasticctl 0.7.5 conformance findings

All eleven contracts passed on all three targets. No runtime change was
needed after the matrix.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 11 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 11 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 11 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

All three legs ran at source commit
`0bf48788c9f7b44c6724b2b0f6eaf95178832ae4`, with package versions at 0.7.4.
The Serverless and Hosted legs ran from `2026-11-10T02:43:56Z` to
`2026-11-10T03:00:31Z`. The self-managed leg is the Live lab workflow run for
the same commit on `master`, from `2026-11-10T02:38:39Z` to
`2026-11-10T02:57:35Z`, against a disposable 9.5.1 lab on the runner. Later
commits before the release change tests, fixtures, scripts, and documents
only.

## What this release changes

- MCP `rules_list` reads one page of `limit` rules ordered by name. Both Cloud
  targets held the full prebuilt pack, 2,263 rules. On that corpus the 0.7.4
  server answered a default `rules_list` with `elastic_unsupported`, because
  the 19.3 MB response exceeded the 16,777,216-byte body cap. The
  `mcp_reads_existing_verticals` contract passed on both targets with the
  bounded read.
- A rule selected by its `rule_id` is read once instead of twice.

## Serverless 9.7.0 tags a rule enabled with a project-scoped key

Within about ten seconds of a create with `enabled: true`, a `PATCH` enable,
or a `_bulk_action` enable sent with a project-scoped Elasticsearch API key,
Kibana appends the tag `Missing Elastic Cloud API Key` to the rule. The rule
still runs. A later `PUT` or `PATCH` that omits the tag removes it, and it
stays removed until the next enable. Hosted 9.5.6 added no tag in the same
probe.

elasticctl treats the tag as ordinary rule content: `state diff` reports it
once after an enable, and the next `state push` removes it. No contract
failed because of it. Shared spec section 7.2 records the measurement.

## Fixtures

The Serverless fixture set is re-recorded on 9.7.0 and replaces the 9.6.0
set. It adds the async columnar ES|QL exchange, which pins
`search esql --out`. The recorder redacts the rollover date in data stream
backing index names, and the fixture leak check rejects a dated name and
reports matches by file and line only.

## Cleanup and evidence limits

Every contract and end-of-leg audit passed. Custom, prebuilt, and customized
rule counts, the exact default data view, Fleet marker policy inventories,
and installed package names and versions matched their captured baselines.
No marker rules, exception lists, indices, dashboards, data views, cases,
Fleet policies, or open marker alerts remained. Closed marker alerts retain
the existing triage allowance because the public API has no alert delete.
Hosted remained running. The lab runner is destroyed with its job.

The Fleet `system` package that fixture recording installed on Serverless
stays installed, as the live-stack rules allow.

Claude Code and Codex CLI client checks were not rerun for this release; the
[0.7.2 findings](../v0.7.2/findings.md) remain the latest product-client
evidence. Raw results, identities, and failures stay in private ignored logs.
