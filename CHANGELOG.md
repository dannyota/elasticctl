# Changelog

## 0.8.0 — 2026-11-10

### Added

- MCP task tools `alert_context`, `rule_health`, `detection_coverage`, and
  `rule_readiness`, bringing the default catalog to twenty-four tools and to
  twenty-six with `--allow-query-tools`. Each sends a capped number of
  requests in a fixed order. `alert_context`, `rule_health`, and
  `rule_readiness` report a status per part and static finding codes;
  `detection_coverage` groups at most 4,000 matching rules.
- MCP `rules_list` takes optional MITRE ATT&CK filters: `technique`, a
  technique id such as `T1059` or a subtechnique id such as `T1059.001`, and
  `tactic`, a tactic id such as `TA0002`.
- The MCP server returns static instructions that point a model to the task
  tools first and mark result text as data.
- `elasticctl_core::Transport::put_absolute_es_once`,
  `post_absolute_es_once`, and `delete_absolute_es_once` send an
  Elasticsearch write exactly once, with no retry on any status.

### Changed

- Rule normalization drops the tag `Missing Elastic Cloud API Key`, which
  Serverless appends to a rule a project-scoped key enables. `state pull` never
  writes it, `state diff` does not report it as drift, and `state push` never
  sends it or plans an update only because the server holds it. `rules get`,
  MCP `rules_get`, and `rules export` omit it too.

### Fixed

- Reject invalid space ids before profile resolution or transport construction.

- `elasticctl_core::Transport` refuses a request path that does not start with
  `/` before sending anything, so a path such as `@other.example/x` cannot
  carry the credential to another host.
- An id read from a Kibana or Elasticsearch response, or from an import file,
  is refused with kind `http` before it becomes a URL path segment when it is
  empty, `.`, or `..`. URL parsing turns those into a request to the parent
  route. This covers data views, dashboards, agent and integration policies,
  parent policy ids, package names and versions, and ES|QL async query ids,
  which are also percent-encoded so a returned `/` cannot add a segment.
- MCP `cases_get`, `data_views_get`, `dashboards_get`,
  `fleet_agent_policies_get`, and `fleet_integration_policies_get` refuse an
  id or selector of `.` or `..` with `invalid_argument` and send no request.

### Verified

- All twelve conformance contracts pass on Serverless 9.7.0, Hosted 9.5.6,
  and self-managed 9.5.1, including `mcp_answers_across_verticals`, which
  calls the four task tools on both protocol paths. The self-managed run read
  a 4,000-rule corpus in eight pages per call.

## 0.7.5 — 2026-11-10

### Fixed

- `rules get`, `enable`, `disable`, `delete`, `preview`, and MCP `rules_get`
  read a rule once when selected by its `rule_id`, instead of twice.
- MCP `rules_list` reads one page of `limit` rules, ordered by name, instead of
  the whole corpus. With default arguments it failed with `unsupported` on
  stacks with the prebuilt rules installed, because the 19.3 MB response for
  2,263 rules exceeded the 16 MiB body cap. `rules list` is unchanged.

### Verified

- All eleven conformance contracts pass on Serverless 9.7.0, Hosted 9.5.6,
  and self-managed 9.5.1. Both Cloud targets held 2,263 prebuilt rules.
- The Serverless fixture set is re-recorded on 9.7.0 and pins
  `search esql --out` through the async query API.

## 0.7.4 — 2026-11-10

### Security

- Upgrade rmcp to 3.9.0 for RUSTSEC-2026-0457, 0461, and 0462.

### Changed

- Always-written nullable fields are now required in tool output schemas.
  Payloads are unchanged; clients that generate types from `outputSchema` may
  see optional fields become required-nullable.
- Current `tools/list` results carry `ttlMs: 0` and `cacheScope: "private"`;
  legacy results omit both fields.
- CI tests on macOS and runs the self-managed conformance matrix against a
  throwaway 9.5.1 lab on every pull request.

### Fixed

- `state push --report` accepts a path whose parent is a symlink, such as
  `/tmp` on macOS. It resolves the existing parent once, as `state pull`
  does, and still refuses final symlinks, symlinked locks, and missing
  parents.

## 0.7.3 — 2026-11-09

### Security

- Update rustls to 0.23.46, rustls-webpki to 0.103.16, and webpki-root-certs
  to 1.0.11 for RUSTSEC-2026-0285, 0346, 0348, 0349, 0382, and 0383, and tokio
  to 1.54.1 for RUSTSEC-2026-0386. Every TLS connection to Kibana and
  Elasticsearch goes through rustls.
- RUSTSEC-2026-0457, 0461, and 0462 affect rmcp's OAuth client and Streamable
  HTTP transports. elasticctl serves MCP over stdio only and enables neither,
  so rmcp stays at 3.2.0 until its upgrade ships with an MCP contract update.

### Changed

- CI pins every third-party GitHub Action to a commit SHA.
- Release builds for Apple Silicon run on `macos-15`; GitHub retired the
  `macos-14` runner.
- Routine dependency updates, including reqwest 0.13.5, clap 4.6.7, and
  serde_json 1.0.154.

## 0.7.2 — 2026-09-07

### Verified

- All eleven conformance contracts pass on Serverless 9.6.0, Hosted 9.5.2,
  and self-managed 9.5.1, including all twenty-two MCP tools.
- Claude Code 2.1.263 and Codex CLI 0.153.4 pass scoped MCP client checks
  against the local lab, with captured protocol negotiation and results.
- SDK tests cover current and legacy catalogs, query admission, busy calls,
  deadlines, cancellation, the input-line cap, and every output schema.

### Fixed

- Live conformance validates current protocol result discriminators before
  checking the shared catalog and tool payloads.

## 0.7.1 — 2026-09-06

### Added

- Thirteen MCP inspection tools for alerts, cases, data views, dashboards,
  and Fleet policies, bringing the default catalog to twenty tools.
- Startup opt-in through `mcp serve --allow-query-tools` for synchronous
  ES|QL and Query DSL tools. Each query uses one HTTP attempt and returns
  bounded results under the selected credential's index privileges.

## 0.7.0 — 2026-09-06

### Added

- `mcp serve` in both binaries, with seven read tools for stack diagnostics,
  rules, and exception lists under one operator-selected target.
- Typed tool schemas, selected result fields, static error messages, input
  and output byte limits, four-call admission, deadlines, and cancellation.
- The `elasticctl-mcp` library, all-four-crate package checks, and a crates.io
  ownership guard for the normal publishing workflow.

### Verified

- All seven MCP tools passed on Serverless 9.6.0, Hosted 9.5.2 and
  self-managed 9.5.1. MCP Inspector 2.5.0 passed all seven calls on the lab;
  exact cleanup and lab teardown passed.

## Older releases

- [0.6.x](docs/changelog/0.6.md)
- [0.5.x](docs/changelog/0.5.md)
- [0.4.x](docs/changelog/0.4.md)
- [0.3.x](docs/changelog/0.3.md)
- [0.2.x](docs/changelog/0.2.md)
- [0.1.x](docs/changelog/0.1.md)
