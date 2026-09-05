# Changelog

## 0.6.2 — Unreleased

### Added

- Fleet policy transfer live contract with guarded cleanup, exact package
  inventory audits, and setup shared with the conformance controller.
- Ten-contract conformance evidence for Serverless 9.6.0, Hosted 9.5.2,
  and self-managed 9.5.1; all 30 checks pass.

### Fixed

- Integration-policy get and export reject mismatched ids and inconsistent
  list-selected responses before returning mixed policy data.

## 0.6.1 — 2026-09-05

### Added

- Fleet integration-policy administration: list, get, validate, portable
  JSON/YAML export and import, and guarded delete by stable policy id.
- Exact package-version checks and fail-closed handling for managed,
  environment-bound, cross-space, and secret-backed integration policies.

### Verified

- Offline tests cover integration-policy normalization, parent and package
  dependency preflight, import conflict handling, overwrite and skip behavior,
  and delete guards.
- Scrubbed 16-exchange integration-policy fixtures pass through the production
  decoders on Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and self-managed
  9.5.1. Each run preserved the materialized System input map, updated without
  sending the response-only `enabled` field, and finished with no marker-policy
  residue.

## 0.6.0 — 2026-09-04

### Added

- Fleet agent-policy administration: list, get, validate, portable JSON/YAML
  export and import, and guarded delete over stable policy ids.
- A fixed server-default table so sparse agent-policy artifacts round-trip
  exactly, and fail-closed refusal of platform-owned, environment-bound,
  cross-space, and unclearable state.

### Verified

- Marker-scoped agent-policy fixtures record create, read, paged list, name
  conflict, update, delete, and the update route's merge behavior on
  Serverless, Elastic Cloud Hosted, and self-managed deployments.

## 0.5.2 — 2026-09-03

### Fixed

- Content cleanup now retains data views and their backing index when an
  earlier dashboard or data-view cleanup step fails, preserving dependencies
  for the retry.
- Live content checks refresh their marker index through the bodyless route
  accepted by every supported deployment flavor.

### Verified

- The nine-contract conformance matrix passes on Serverless 9.6.0, Elastic
  Cloud Hosted 9.5.2, and self-managed 9.5.1. Each target finished with no
  marker content residue, its original default data view restored, and its
  prebuilt-rule baseline unchanged.

## 0.5.1 — 2026-09-02

### Added

- Dashboard administration: list, get, validate, typed JSON/YAML export and
  import, and guarded delete using stable dashboard ids.
- Opaque Saved Objects dashboard bundle export/import with deep dependencies.

### Fixed

- Dashboard search now decodes the measured nested row shape and derives the
  flat rendering summary without accepting the prior unmeasured flat row.
- Traditional fixture recording activates and verifies the headless lab
  profile before its marker-scoped alert assignment probe.
- Dashboard fixture scrubbing now deterministically normalizes generated panel
  tokens in direct responses and opaque Saved Objects bundles while preserving
  caller-selected dashboard and data-view ids.

### Verified

- Scrubbed dashboard fixtures cover create, get, scoped search, replacement,
  delete, final not-found, deep export, import success/conflict, and the
  accepted loss of `$.time_range.mode` on Serverless 9.6.0, Elastic Cloud
  Hosted 9.5.2, and self-managed 9.5.1. Every recorder leg completed its
  marker cleanup audit.

## 0.5.0 — 2026-09-02

### Added

- Data-view administration: list, get, validate, export, import, guarded
  delete with reference replacement, and guarded default get/set/unset.
- Portable JSON and YAML data-view transfer with stable ids and strict route
  response decoding.

### Fixed

- Data-view delete and default changes now refuse unsafe referenced/default
  states and restore a pending original default before marker cleanup.
- Portable legacy scripted fields are globally rejected before I/O.
- Fixture recording removes deployment identity from status responses and
  keeps retry diagnostics free of server-provided object ids.

### Verified

- Scrubbed 21-exchange data-view fixtures now verify strict live response
  contracts and cleanup on Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and
  self-managed 9.5.1.

## 0.4.2 — 2026-09-01

### Added

- An eighth live conformance contract covers alert transitions, tags,
  assignment, and the full case lifecycle. The same contract now passes on
  Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and self-managed 9.5.1.

### Fixed

- Alert and case mutations now reject empty or inconsistent public plans
  before a request. Case status changes also require an exact one-to-one
  response for every requested id and target status.
- Alert list search escapes wildcard syntax, profile lookup recognizes the
  internal route's unavailable response, and `alerts get` and `cases get` no
  longer derive their exit status from fields inside the returned document.
- Case attachment preserves earlier group outcomes after a later failure.
  Live cleanup refuses dirty triage targets and can delete a created case by
  its exact title and marker tag when its response has no usable id.

### Verified

- All 24 rows in the three-flavor 0.4.2 matrix passed. The scrubbed
  [findings](docs/conformance/v0.4.2/findings.md) record the targets and
  cleanup result.

## 0.4.1 — 2026-09-01

The 0.4.0 alerts vertical below was developed back-to-back with this release
and ships with it; v0.4.1 is the first tag carrying both.

### Added

- `cases list`, `cases get`, `cases create`, `cases close`, `cases open`,
  `cases delete`, `cases attach`, and `cases comment` track investigations as
  cases. Every mutation previews on stderr and applies only with `--yes`;
  `cases delete` is the area's only destructive verb, and its preview names
  each case title. Case identity is the case id plus a version fetched just
  before the mutation, so a change since the preview is reported as a
  conflict rather than silently overwritten.
- `elkctl`, a shorter alias binary for `elasticctl`. Both compile from the
  same entrypoint, so the command surface is identical; help text and shell
  completions follow whichever name invoked the process.

## 0.4.0 — 2026-09-01 (released as part of v0.4.1)

### Added

- `alerts list`, `alerts get`, `alerts ack`, `alerts open`, `alerts close`,
  `alerts tag`, and `alerts assign` triage detection alerts by id or by query
  DSL. Every mutation previews on stderr and applies only with `--yes`;
  `close` also accepts `--reason` and `--conflicts abort|proceed` for
  query-scoped transitions.

## 0.3.2 — 2026-09-01

### Fixed

- Flavor detection mis-parsed a doubled-scheme URL as its scheme name and a
  query-only URL as `host?query`; the host is now cut at `/`, `?`, `#`, or `:`
  after the real scheme boundary.
- `Profile`'s derived `Debug` printed the raw API key, password, and URL
  userinfo. A manual implementation now marks secrets present-but-redacted and
  strips userinfo, so `Config` and `Resolved` debug output stays safe by
  delegation.

### Security

- Updated `h2` to 0.4.19 for RUSTSEC-2026-0258 (unbounded queuing of empty
  DATA frames; low severity).

## 0.3.1 — 2026-08-16

### Added

- `--search` narrows `rules list` and `exceptions list` by name substring and
  tag, and `state pull`, `state diff`, and `state push` to the matching rules.
  It is mutually exclusive with `--filter` on `rules list`.
- `search dsl --with-meta` surfaces each hit's `_id`, `_index`, and `_score`
  alongside the source document; without the flag output is unchanged.
- ES|QL bulk export requests columnar results and renders CSV client-side,
  lowering memory for large exports.
- The `search` conformance contract is published for all three deployment
  flavors.

### Fixed

- A URL with a doubled scheme or an empty-port host could leave credential
  userinfo embedded in output. Userinfo is now stripped from those URLs too.
- An empty `--search` value selected every rule instead of narrowing; it is now
  rejected.
- `search esql` without `--out` again reports `capped at N rows` when it
  truncates a peek.

## 0.3.0 — 2026-08-16

### Added

- `search esql` and `search dsl` run ES|QL and Query DSL against Elasticsearch
  data and render or export the results. `--index` and `--data-view` select the
  target, `--limit` caps rows (default 100 for a peek), and `--out` writes
  NDJSON — DSL streams pages through a point-in-time, ES|QL through the async
  API.
- The Elasticsearch error envelope (`{"error": {"reason": ...}, "status": ...}`)
  is now classified alongside the Kibana and Cloud edge shapes.

## 0.2.5 — 2026-08-15

### Fixed

- `config init` no longer reports failure on macOS: the post-rename directory
  sync now runs only on Linux, where directory `fsync` is supported.
- A doubled-scheme URL whose authority carries userinfo is now scrubbed
  consistently with `host()`, so a credential never reaches a banner.
- `config list` scrubs URL userinfo from `kibana_url` instead of echoing a
  credential embedded in a hand-edited or pre-0.2.4 config file.
- `doctor` fails a malformed identity whose `username` or
  `authentication_realm.type` is an empty string, not just a missing field.
- A `--timeout` (or `--space`) flag now supersedes an invalid
  `ELASTICCTL_TIMEOUT` / `ELASTICCTL_SPACE`, matching flag-over-env precedence
  instead of failing before the flag applies.
- Mirror file reads now open with `O_NOFOLLOW`, so a file swapped for a symlink
  between enumeration and read is refused atomically rather than followed.
- The conformance-report leak scan now uses `grep -P` instead of `rg`, so it
  actually runs on a release box that lacks ripgrep instead of silently passing.

## 0.2.4 — 2026-08-15

### Fixed

- Config saves now replace the file atomically through a same-directory
  temporary file, so a save never truncates an existing file in place or
  writes through a symlink, and always lands with `0600` permissions.
- The CLI rejects invalid `ELASTICCTL_*` input — non-UTF-8 values and a
  non-integer timeout — instead of silently dropping it, and URL userinfo is
  scrubbed at every public sink (`redacted`, `host`, `save`, and `--debug`).
- Malformed mutation responses (`_bulk_action` summaries and import reports)
  now fail as `http` errors rather than reading as zero success.
- Malformed export trailers, preview-hits bodies, and identity responses now
  fail closed instead of being discarded or read as zero or "unknown".
- Mirror reads refuse symlinked `rules`/`exceptions` roots and symlinked rule
  or list files, and a lost directory entry fails instead of being skipped.
- Pull-journal recovery validates phase transitions and refuses a record that
  jumps ahead without touching the target or discarding the journal.

### Verified

- Package-content checks now inspect every publishable crate —
  `elasticctl-core`, `elasticctl-api`, and `elasticctl` — so none packages its
  integration tests or the private test-support crate.

## 0.2.3 — 2026-08-15

### Added

- A target-neutral conformance runner now executes the same six live contracts
  serially and publishes a report only after cleanup and baseline audits pass.

### Verified

- All six contracts passed on Serverless 9.6.0, Elastic Cloud Hosted 9.5.1,
  and self-managed 9.5.1. The scrubbed
  [findings](docs/conformance/v0.2.3/findings.md) contain the measured matrix
  and cleanup result.
- The run found no release-worthy 0.2 defect, so 0.2.4 is skipped and 0.3.0
  search design is next.

## 0.2.2 — 2026-08-15

### Added

- A manual release preflight now packages and verifies all three publishable
  crates without credentials or uploads before a version tag.

### Changed

- CI now resolves the committed dependency graph, proves every workspace
  target with Rust 1.97.1, and retains the stable-toolchain checks.
- Windows now runs the full CLI package test suite, including raw export and
  report-file paths, in addition to the API transaction regressions.

### Fixed

- POSIX permission-mode tests now run only on Unix, so the full CLI suite also
  compiles on Windows.

## 0.2.1 — 2026-08-15

### Fixed

- Transaction durability now opens staged files and pull journals with write
  access before syncing them. Windows rejected the previous read-only handle
  with `Access is denied`, which failed the transaction test job.
- Exception-list, prebuilt-rule, and source-filtered rule routes now probe and
  cache stack capabilities before their first request. Versions older than the
  verified 9.5.1 floor return a typed `unsupported` error instead of a generic
  route failure.
- Elastic Cloud Hosted hostname fallback matching is now case-insensitive and
  accepts a final DNS dot without matching lookalike domains.

### Documented

- Public state-diff and CLI tests now cover exception container and item drift,
  list filters, offline validation, partial imports, skip-existing uploads, and
  qualified delete failures.
- All three deployment flavors now have 29 scrubbed fixtures. Their recorded
  custom and prebuilt source filters prove the source partition at the 9.5.1
  compatibility floor.

## 0.2.0 — 2026-08-14

### Breaking

- `state pull`, `state diff`, and `state push` now default to `--source custom`
  and mirror only the rules you authored. A 0.1 mirror of Elastic's prebuilt
  rules is reported as `out_of_scope` rather than as pending changes. Pass
  `--source all` for the previous behavior.
- `state diff` output gains an `exceptions` block, and `clean` is now true only
  when the rules *and* the exception lists match.

### Added

- `exceptions list|get|validate|export|import|delete`.
- `rules prebuilt status|install`.
- `--source custom|customized|prebuilt|all` on `rules list`, `rules export`,
  and the state commands.
- `state pull` mirrors the exception lists your rules reference; `state push`
  creates them before the rules that point at them.
- `doctor` reports whether the value-list data streams exist.

### Fixed

- `rules export` failed with `line 2: a rule must have a rule_id` for every
  rule carrying an exception list. Export bundles are now decoded in full.
- A rule's `exceptions_list[].id` is a per-stack pointer and was written to
  disk verbatim, so promoting a rule between stacks carried a pointer to an
  object that did not exist there. It is now stripped on pull, re-resolved on
  push, and a mismatch is reported by `state diff`.

## 0.1.3 — 2026-08-13

Closes the remaining v0.1.x gaps. No breaking changes: every real corpus today
has fewer than 10,000 rules and is read exactly as in 0.1.2, including output.

### Fixed

- `state pull` and `state diff` no longer stop at 10,000 rules. Above the
  result window, the corpus is read as one query per rule type. An oversized
  type is further split by enabled state, raising the ceiling to about 140,000.
  Every rule has one type, so the slices are disjoint and exhaustive. Their
  counts must sum to the corpus total or the read is refused. Otherwise, a rule
  type added by a future stack version could silently vanish from every pull.
- The refusal above the window no longer points at `rules export` as a way
  around it. Export has its own 10,000 cap and answers `Can't export more than
  10000 rules`, so the advice sent operators to a second limit. Saved-object
  export is not an alternative: detection rules register as not exportable
  through that interface at any size.

### Documented

- All three deployment flavors now hold 14 recorded fixtures. The self-managed
  set gained the four it lacked, so no flavor is the least-tested one.
- `rules preview` is confirmed against a self-managed stack. It had only ever
  been exercised on Serverless.
- A self-managed stack is now *measured* not to emit
  `x-found-handling-cluster`; this was previously inferred from the absence of
  a Cloud proxy. Every fixture set records response headers, and the
  classification test requires them. An unrecorded set can no longer read as a
  measured absence.

## 0.1.2 — 2026-08-13

Finishes the detection-rules vertical. No breaking changes: every command
without selectors behaves exactly as in 0.1.1, including output fields.

### Added

- `state pull`, `diff`, and `push` take the positional selectors and `--tag`
  that `rules export` already took. A selection narrows both the local and the
  remote side before drift is computed, so the remote read becomes one
  `rule_id`-filtered `_find` rather than a corpus read. Measured against 2,066
  rules, a scoped `diff` costs 0.50 s where an unscoped one costs 3.65 s.
  `diff` and `push` report `selected` and `local_total`; `pull` reports
  `selected`. The `push` guard banner names the selection, so a scoped apply
  cannot read as a full one.
- Selectors on `diff` and `push` resolve against the local directory first, so
  a rule that exists only on disk can be selected by name before it exists on
  the stack. An ambiguous local name is refused naming both `rule_id`s.

### Changed

- The rule corpus is read in one request instead of paged. `_find` is a search
  underneath, so `from + size` is bounded by Elasticsearch's 10,000 result
  window; reading at the window is both the fastest way to read a corpus and
  the only page size that reads as much of one as exists. A pull of 2,066 rules
  is now 1 request where it was 21.
- Elastic Cloud Hosted is detected from the `x-found-handling-cluster` header
  the Cloud edge proxy injects, rather than by matching the hostname against
  known Cloud suffixes. Hosted reports `build_flavor: "traditional"`, identical
  to a self-managed stack, so the status body could never separate them.
  Hostname matching remains as a fallback for a deployment behind a proxy that
  strips the header.

### Fixed

- `ELASTICCTL_ES_URL` is read from the environment. It was documented and read
  by the fixture recorder but ignored by the CLI, so overriding the Kibana host
  left the Elasticsearch host pointing at the saved profile's — addressing two
  deployments at once and sending the overridden credential to the host the
  operator had not named. Overriding `kibana_url` alone now clears `es_url`
  rather than inheriting it.
- A corpus larger than the result window is refused naming the limit, and a
  server that returns fewer rules than it counted is refused as a short read.
  Both previously produced a partial corpus indistinguishable from rules having
  been deleted, which would make `state diff` report every unread rule as
  locally added.

### Documented

- Elastic Cloud Hosted has a recorded fixture set (`ech-9.5.1`), making all
  three deployment flavors tested rather than two.
- Every API key type carries the `essu_` prefix. The claim that provisioning
  keys carry `essa_` was wrong; only the authenticate realm distinguishes them.

## 0.1.1 — 2026-08-13

Improvements and fixes inside the existing command surface. No breaking
changes: every new flag has a default that preserves the previous behavior.

### Added

- `rules preview` reports how many events matched. The API returns a preview id
  and no count, so the alerts the preview wrote are read back and counted;
  `--sample N` returns the matched documents themselves. When the count cannot
  be read the preview still reports its id, errors, and warnings, with
  `hits: null` and `hits_error` saying why.
- `rules export` takes rule ids or names as positional selectors and a `--tag`
  filter, and exports only those. A selection that matches nothing is refused
  rather than widened to the whole space.
- `rules import --skip-existing` leaves rules that already exist alone instead
  of failing on each of them. The dry run names what would be created and what
  would be skipped. Mutually exclusive with `--overwrite`.
- `info` reports the space list and a real license tier, both probed, instead
  of no spaces and a hardcoded null.
- `--debug` logs a line before each request is sent and on the timeout and
  connection-error branches.
- A `samples/` harness that fetches a Sigma rule slice and three MIT event
  datasets on demand, with the ECS remap and timestamp rewrite `preview` needs.

### Changed

- Resolving a rule by name filters server-side instead of reading every page of
  the corpus: a lookup that took 8.8 seconds against 2,066 rules is now one
  request. A selector matching neither an id nor a name reports "No rule with
  rule_id or name".
- `state pull` reports every filename collision in one error and writes nothing
  when any collide, instead of failing on the first pair after writing the
  files before it.
- `doctor` truncates the credential id in its auth check. It is not the secret
  half, but it identifies the key.

### Fixed

- A `rule_id` that is present but not a string is rejected when the rule is
  constructed, and an NDJSON decode error names the line.
- Userinfo in a profile's `kibana_url` or `es_url` is stripped at resolution
  and never written to the config file, so a hand-written URL that embeds
  credentials in its authority cannot reach the guard banner or a `--debug`
  line.

### Documented

- `rules export` without `--out` writes the exported file to stdout verbatim
  under every report format. `--json` does not wrap it.

## 0.1.0 — 2026-08-13

First release. Manages Elastic Security detection rules as code.

### Added

- Profiles with `config init`, `list`, `show`, `test`. Secrets stored at mode
  `0600` and redacted in all output.
- `doctor` checks connectivity, authentication, API key scope, deployment
  flavor, and rule access. It reports every failure in one pass.
- `info` shows the CLI version, profile name, Kibana URL, the configured space,
  stack version, flavor, and license tier.
- `rules list`, `get`, `validate`, `enable`, `disable`, `delete`, `export`,
  `import`, `preview`.
- `state pull`, `diff`, `push` with a change-evidence report.
- Output as table, JSON, YAML, CSV, or JSONL, with `--fields` and `--out`.
- Shell completion for Bash, Elvish, Fish, PowerShell, and Zsh, and a
  machine-readable command tree.

### Contracts

- Every mutation previews by default and applies only with `--yes`.
- `state push` never deletes a remote rule.
- Rules are matched by `rule_id`, never by name or by the server-side `id`.

### Known limitations

- An organization-level Elastic Cloud API key cannot enable rules. Use a
  project-scoped Elasticsearch API key created in Kibana. `doctor` reports
  which one is configured.
- Elastic Cloud Hosted is detected by hostname rather than by a stack-reported
  signal.
