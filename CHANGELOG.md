# Changelog

## 0.9.1 — Unreleased

### Added

- MCP mutation classes `alerts-triage`, `cases`, and `rules-create` for
  `mcp serve --allow-mutations`, beside `rules-toggle`. There is still no
  `all` value. With all four classes the catalog has 35 tools, or 37 with
  `--allow-query-tools`. With no class, or with `rules-toggle` alone, the
  catalog and schemas are unchanged.
- MCP planner tools, each listed only when its class is enabled:
  `alerts_set_status_plan` and `alerts_set_tags_plan` (`alerts-triage`) set
  the workflow status, or add and remove tags, of 1 to 20 alerts named by
  `_id`; `cases_create_plan`, `cases_comment_plan`, and
  `cases_set_status_plan` (`cases`) create one case, add one comment, or
  close or reopen 1 to 20 cases; `rules_create_plan` (`rules-create`) creates
  one rule, always disabled. Each apply is one write request. No tool selects
  alerts by query, sets assignees, or creates an enabled rule. A second call
  does not restore an alert's workflow user and time or its earlier tags, and
  no tool removes a posted comment.
- The tool error `case_sync_alerts`, kind `unsupported`. A case status plan
  is refused, at planning and at both checks, unless every case has
  `settings.syncAlerts` set to a JSON `false`, because Kibana would also
  change the attached alerts. A new case is created with `syncAlerts: false`.
- A rule create plan shows every field of the rule in full and carries its
  own consent note: Kibana creates the rule disabled and without an API key,
  and the credential that first enables it gives it a key. Its
  `cli_equivalent` is `null`. A 409 answer to a case status or rule create
  write makes the plan `stale`.
- Rust source changes, outside the CLI and MCP compatibility promise:
  `elasticctl_mcp::MutationClass` gains `AlertsTriage`, `Cases`, and
  `RulesCreate`, and `catalog::ToolId` gains six variants, so `ToolId::ALL`
  holds 37.

### Changed

- MCP planning refuses an organization-level Elastic Cloud API key
  (`_cloud_api_key`) with `credential_unsuitable` for every mutation kind,
  before any other read.
- The `doctor` `key_scope` warning for an organization-level key says the key
  is not supported, that MCP planning refuses it, and that rule changes may
  fail on some deployments, and asks for a project- or deployment-scoped
  Elasticsearch API key.
- The consent text's action line holds one line: a line feed from the stack
  shows there as U+FFFD, and a new case title with a line feed is
  `invalid_argument`. A rule create plan shows its `rule_id` line first.

### Fixed

- Alert status, tag, and assignee reports (`alerts ack`, `open`, `close`,
  `tag`, and `assign`, and MCP alert plans) add their failure counters with
  checked arithmetic. An overflowing sum is an `http` error that says the
  counters are unreadable.
- MCP maps every apply report with checked arithmetic, including a rule
  toggle's. A report whose counters overflow or pass the planned count
  records the plan as `unknown` with no outcome.

## 0.9.0 — 2026-11-11

### Added

- `mcp serve --allow-mutations <CLASSES>` enables MCP mutation classes for the
  life of the process. `rules-toggle` is the one class. The value is a
  comma-separated list and the flag may repeat; there is no `all` value or
  wildcard, and an empty value, an unknown name, or whitespace is a usage
  error. A class set needs the profile's Elasticsearch URL and a profile
  name, host, and space without line breaks or control characters, writes a
  `mutations_enabled` warning line to stderr at startup, and replaces one
  sentence of the server instructions. Without the flag the catalog, schemas,
  results, and instructions are unchanged.
- MCP tools `rules_set_enabled_plan`, `plan_apply`, `plan_get`, `plan_list`,
  and `plan_discard`, listed only when a class is enabled: 29 tools, or 31
  with `--allow-query-tools`. The planner reads the stack and stores a plan in
  server memory for 15 minutes without writing. `plan_apply` takes only a
  plan id.
- `plan_apply` applies a plan only after a form elicitation answered `accept`
  with `apply: true`; no tool argument confirms. On protocol `2026-07-28` it
  returns an input request and reads the answer from the next call; on
  `2025-11-25` it asks the client while the call waits, up to 240 seconds. A
  client without form elicitation gets `confirmation_unavailable`, and the
  plan names the CLI command in `cli_equivalent`. A plan is checked for drift
  in target, credential, and rule state before the question and again before
  the write, applies at most once as one write request on its own
  connection, and returns its first outcome when applied again. At most 8
  plans are open, 32 final records are kept, and a plan holds at most 20
  rules and prompts at most 3 times.
- An audit trail on stderr: one JSON line per plan event (`plan_created`,
  `confirmation_requested`, `confirmation_answered`, `apply_started`,
  `apply_finished`, `apply_interrupted`, `plan_closed`), with ids, counts,
  and classifications only.
- Rust source changes, outside the CLI and MCP compatibility promise:
  `elasticctl_mcp::ServerOptions::allow_mutations` with `MutationClasses` and
  `MutationClass`; in `elasticctl-mcp` also `validate_startup`,
  `ServerState::mutation_transport`, `tools::CallContext` and `CallProtocol`,
  `ToolAdapter::call_with_context`, the `AdapterError::Tool` variant, and five
  `catalog::ToolId` variants;
  `elasticctl_core::TransportOptions::disable_connection_pool`,
  which keeps no idle connection so each request opens its own socket; and in
  `elasticctl-api` the `observe` module (`Observed`, `Preconditions`,
  `require_rule_identity`), `rules_ops::plan_set_enabled_observed`,
  `rules_ops::observe_rules`, `rules_ops::plan_create` and
  `rules_ops::apply_create` with `RuleCreatePlan` and `RuleCreateOutcome`,
  `alerts_ops::plan_status_by_ids_observed`,
  `alerts_ops::plan_tags_observed`, `alerts_ops::observe_alerts` with
  `AlertFacet`, `cases_ops::plan_status_observed`,
  `cases_ops::plan_comment_observed`, `cases_ops::observe_cases`, and
  `health::credential_identity` with `CredentialIdentity`.

### Changed

- A conflicting `cases close` or `cases open` error carries
  `"http_status": 409`.
- The `mcp` command description drops "read-only" and reads
  `Serve Elastic tools over MCP stdio`.

## 0.8.2 — 2026-11-11

### Added

- `scripts/mcp-stdio-shim.sh` runs an MCP server and records both stdio
  directions to private files, for checking what a client sends.

### Changed

- The MCP server is checked with two product clients, Claude Code 2.1.322 and
  Codex CLI 0.167.0, on a local lab; the MCP wiki page lists what each one
  supports. Protocol tests now cover the whole 0.8 surface at once: every tool
  against its output schema, exact request maxima, mixed tool and resource
  admission, and credential sentinels. The server is unchanged.

## 0.8.1 — 2026-11-11

### Added

- MCP resources. `resources/list` returns five fixed URIs under
  `elasticctl://stack/`: coverage by ATT&CK tactic and by technique, stack
  diagnostics, stack info, and prebuilt rule status. `resources/templates/list`
  returns four templates: an alert, a case, an exception list, and a rule by
  `rule_id`. A read is one call of the matching read-only tool with fixed
  arguments: its text equals that tool's text, it takes one of the four call
  slots, and it obeys `--timeout`. Listing sends no Elastic request and needs
  no credential.
- MCP prompts `check_rule_readiness`, `review_detection_coverage`,
  `review_rule_health`, and `triage_alert`. Each validates its arguments and
  returns fixed text that asks the model to call one task tool. A prompt reads
  nothing from Elastic.
- The server advertises exactly the `prompts`, `resources`, and `tools`
  capabilities. The tool catalogs are unchanged: twenty-four tools by default
  and twenty-six with `--allow-query-tools`.

### Changed

- MCP `completion/complete` fails with `-32601` instead of returning an empty
  result, because the server advertises no completions.

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

- A Kibana space id other than empty or `[a-z0-9_-]+` is refused before any
  request, so a space such as `..` cannot reach the default space's routes.
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
