# Changelog

## Unreleased

### Fixed

- `rules get`, `enable`, `disable`, `delete`, `preview`, and MCP `rules_get`
  read a rule once when selected by its `rule_id`, instead of twice.

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
