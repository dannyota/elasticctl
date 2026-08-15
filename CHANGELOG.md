# Changelog

## 0.2.2 — 2026-08-15

### Added

- A manual release preflight now packages and verifies all three publishable
  crates without credentials or uploads before a version tag.

### Changed

- CI now resolves the committed dependency graph, proves every workspace
  target with Rust 1.97.1, and retains the stable-toolchain checks.
- Windows now runs the full CLI package test suite, including raw export and
  report-file paths, in addition to the API transaction regressions.

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
