# elasticctl 0.7.2 conformance findings

All eleven contracts passed on all three targets. Claude Code and Codex CLI
also passed the scoped client checks against the local lab. No runtime change
was needed.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 11 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 11 pass | [ech-9.5.2.json](ech-9.5.2.json) |
| Self-managed | 9.5.1 | 11 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

The final matrix ran from `2026-09-06T15:48:27Z` to `2026-09-06T15:58:01Z`
at source commit `d0c79b4cc99d0e8ae5ae15b476a7f5eb9e1eb4f2`. No contract
failed or skipped. Package and server versions remained 0.7.1, as the
implementation plan requires.

## MCP coverage

Each `mcp_reads_existing_verticals` run starts the actual `elasticctl` stdio
server. The default child exercises all twenty inspection tools across stack,
rules, exceptions, alerts, cases, data views, dashboards, and Fleet policies.
The second child enables and exercises both synchronous query tools.

| Check | Measured scope on each flavor |
| --- | --- |
| Catalog | Exactly twenty default tools; query opt-in adds only `search_dsl` and `search_esql` |
| Default protocol | `server/discover` and every later request carry `2026-07-28` metadata; discovery advertises exactly the current and legacy revisions |
| Query protocol | Legacy initialization negotiates `2025-11-25` |
| Inspection reads | Owned rule, exception, alert, case, content, and Fleet objects; six empty list families and six normalized missing gets |
| Query reads | Three marker documents, a two-row limit, and empty results for both query shapes |
| Results and lifecycle | Selected fields, owned values, page metadata, text/structured-content agreement, and child shutdown |

The offline rmcp client checks compare current and legacy catalog and stack
results, prove both default query rejections and the exact opt-in catalog,
and exercise busy, deadline, cancellation, and oversized input behavior.
A JSON Schema validator checks one actual routed success and one error for
each of the twenty-two tools against its advertised output schema.

## Product clients

The client runs took place from `2026-09-06T16:02:16Z` to
`2026-09-06T16:04:17Z` on Fedora Linux 44, x86_64, against self-managed
Elastic 9.5.1. Both used the same source commit and server version 0.7.1.
Configuration and a transparent stdio tee lived outside the repository.
The server processes used only the local lab profile and environment.

| Client | Requested protocol | Negotiated protocol | Result |
| --- | --- | --- | --- |
| Claude Code 2.1.263 | `2025-11-25` | `2025-11-25` | Pass |
| Codex CLI 0.153.4 | `2025-06-18` | `2025-11-25` | Pass |

Codex accepted the server's supported fallback and completed the calls.
This does not claim support for `2025-06-18`.

Both captured sessions discovered twenty tools, read `stack_info`, and read
an owned sample rule with an exception reference. A missing `rules_get`
returned kind `not_found` and code `elastic_not_found`. Both clients sent
`rules_list` with `limit: 0` and received `invalid_argument` from the server.
All eight tool results passed their captured output schemas and matched
their JSON text copies.

Neither client sent `search_esql`: the captured default catalogs omit it,
and both client transcripts explicitly refused the unavailable tool. That
check proves client catalog refusal, not a server unknown-tool response.
No synthetic request was inserted into either client session.
Both clients exited with code zero; their server children and tee processes
were gone, and both server stderr logs were empty.

## Initial failure and correction

The first matrix, at commit `46a201a`, passed ten contracts on every flavor
and failed only MCP. The live validator rejected the current protocol's
`resultType: "complete"` before any tool reads. All three cleanup audits
passed. Those initial reports provide no MCP projection evidence.

The corrected harness validates the discriminator at its shared receive
boundary and removes it before the existing strict payload checks. Legacy
results must omit it. A local process regression reaches both protocol paths
and both local argument errors with zero HTTP requests. The primary also
captured the expected regression failure with the new receive hook removed,
restored the approved file, and reran the passing offline harness. The final
matrix above reran all eleven contracts on every flavor.

## Cleanup and evidence limits

Every final contract and end-of-leg audit passed. Custom, prebuilt, and
customized rule counts, the exact default data view, Fleet marker policy inventories,
and installed package names and versions matched their captured baselines.
No marker rules, exception lists, indices, dashboards, data views, cases,
Fleet policies, or open marker alerts remained. Closed marker alerts retain
the existing triage allowance because the public API has no alert delete.
Hosted remained running.

Both disposable lab runs ended with successful teardown. Independent Podman
checks by both Compose labels and name found zero lab containers and volumes.
The task-owned Podman service also exited.

MCP debug logging stays disabled, so the matrix has no live HTTP request
capture. Its read-only proof combines the existing offline recording-mock
route assertions, the child command and configuration, and baseline equality.
The product-client tee records stdio, not HTTP. Current protocol live evidence
comes from the project harness; both product clients negotiated the legacy
revision. Raw results, identities, and failures remain in private ignored
logs. No fixture was edited or re-recorded.
