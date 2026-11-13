# Testing, fixtures, and sample data

## Gates

CI runs all but the last on every pull request; the publish dry run is the manual
`release-preflight.yml` workflow. Run them before opening a pull request.

```bash
cargo test --locked --workspace                   # unit + fixture, offline, no stack needed
bash scripts/test/check-lengths-test.sh && bash scripts/check-lengths.sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny check advisories bans licenses sources
bash scripts/test/check-fixtures-test.sh && ./scripts/check-fixtures.sh
./scripts/check-packages.sh && ./scripts/check-conformance-reports.sh
cargo publish --workspace --dry-run --locked      # release preflight, no upload
```

CI uses pinned cargo-nextest for the full workspace on Linux and macOS, then
runs `cargo test --locked --workspace --doc` separately. Windows uses one
nextest filter covering API state integration, transaction tests, and every
`elasticctl` package test. `cargo test` remains a valid local command.
CI also runs full-history gitleaks, actionlint, and Rust/Actions CodeQL.

Live and recording commands need `.env`; see [live stacks](live-stacks.md) first.

```bash
ELASTICCTL_LIVE=1 cargo test --locked --test live -- --ignored --test-threads=1
cargo xtask record                                # re-record fixtures from a live stack
cargo xtask conformance-matrix --report-dir <path> # all three live conformance legs, concurrently
```

On the development laptop, append the limits from `CONTRIBUTING.md` to these commands: `--jobs 2`
for builds, `--test-threads=4` for tests, and one build-heavy command at a time. Pass them per command. Do
not commit `RUST_TEST_THREADS` or job limits to `.cargo/config.toml`; CI uses runner defaults.

## Fixtures

Before re-recording, read this section, "Sample data", and `xtask/src/main.rs`.

Fixtures are recorded from real traffic, never hand-written. They are tagged with flavor and
stack version, and live in `tests/fixtures/<flavor>-<version>/`. Do not hand-edit a fixture to
make a test pass; re-record it.

The same holds for MCP frames. A live check that compares a frame with an exact shape needs an
offline test that runs the real server and passes its frame through that check, on each protocol
path the check runs on. A hand-written frame repeats the author's guess, so it cannot catch a
wrong expectation.

The directory is named for the *deployment* flavor, not the reported flavor. Hosted and
self-managed Kibana both report `build_flavor: "traditional"`. Recording a Hosted stack without
`ELASTICCTL_FIXTURE_FLAVOR=ech` overwrites `traditional-9.5.1`.

Fixtures are public, so scope every recording request to the probe rule. An unscoped `_find` or
`_export` writes real rule content into the repo. Scrub identity (`username`, `full_name`,
`email`, `created_by`, `updated_by`) and credentials. The export fixture holds NDJSON as an opaque
string, so it needs its own scrub pass.

`scripts/check-fixtures.sh` backs up the recorder's scrub. It exists beside gitleaks because a generic secret scanner misses identity held in a value, such as a project hostname in `kibana.alert.url`, which was the original leak. Its patterns match the shapes this project produces: an API key or authorization header, a Cloud deployment hostname (the recorder rewrites the recording host to `REDACTED.example.invalid`), URL userinfo, an email address outside `example.com` and `.invalid`, and a dated backing index name.

The fixture-scanner regression tests build credential-shaped values at run time, so secret scanners never read one from their source. `MockStack` logs requests from the `wiremock` server's `received_requests`, not from a wrapper around `Transport`: a wrapper would sit where `--debug` must never log.

The recorder relies on these external behaviors:

- `POST /<index>/_refresh` rejects a request body, so the recorder sends the GET form.
- The marker rule runs every minute. The alerts probe disables it before `record_cases` runs, so new alerts do not pile up under the case exchanges, push the final close-by-query `total` past its 15-second retry budget, or race that close with a version conflict.
- An index named `logs-*-*` matches Elastic's built-in template and refuses a plain document write, so scratch indices avoid the `logs-` prefix.
- The recorder never deletes preview alerts, so each preview probe name carries a per-run suffix that a leftover alert cannot match.
- `record-compose` binds the marker index to its UUID. Serverless returns no `index.uuid` from the index settings or get-index APIs; `_cat/indices` reports it on every flavor. An index create on a taken name answers 400 `resource_already_exists_exception`, `index [<name>/<uuid>] already exists`. A document write to a missing index creates it, so a lost marker document write can re-create the index after cleanup.
- Serverless can answer an alert close with 409 while the rule's last execution or a case attachment still updates that alert; cleanup searches again and retries.

Live tests rely on these:

- `GET /api/status` carries no Elasticsearch cluster UUID. The lab identity check compares `cluster_uuid` from `GET /api/stats?extended=true` with Elasticsearch `GET /`. The Console proxy is an internal route on 9.5 and refuses a body on `GET /`, so it is not used.
- Kibana's case search tokenizes the text and matches any token (`simple_query_string`, OR), so a search meant to miss avoids the shared hyphenated fixture terms.
- A case read does not carry its comments on every stack, so the live mutation contract reads a comment through the comment search.

## Sample data

Fetch, never vendor: third-party rule and event content stays out of this public repo; scripts
download it on demand. Verified licenses (2026-08-13):

- SigmaHQ/sigma is DRL 1.1: attribution and license notice required.
- OTRF/Security-Datasets is MIT (its README's GPL-3.0 line is stale).
- elastic/detection-rules is Elastic License v2: never commit its content.
- sbousseaden/EVTX-ATTACK-SAMPLES has no license: do not use it at all.

`sigma-cli` with `-t lucene -p ecs_windows -f siem_rule_ndjson` converts Sigma rules to importable
NDJSON. Mordor events use pre-ECS Winlogbeat field names (`EventID`, `CommandLine`, `Image`).
Remap them to ECS and rewrite `@timestamp` to now before ingest, or no rule can match.

## MCP stdio shim

`scripts/mcp-stdio-shim.sh <log-dir> -- <command> [args...]` sits between a real MCP client and the server during client runs and appends the stdin and stdout bytes to `in.jsonl` and `out.jsonl`, mode 0600. It needs Bash 4.4 or newer.

- Bytes reach `in.jsonl` before the command can read them. After the command exits, the shim waits for the output relay, then stops the input relay, so client bytes written after the exit may be missing from `in.jsonl`.
- TERM, INT, and HUP reach the command once it can receive them; before that, they stop the relays and the shim. After any of them, the shim stops both relays without waiting, so output still in the pipe may be missing from stdout and `out.jsonl`.
- The shim exits with the command's status, or with 128 plus the signal number when a signal arrives as the command exits. Bash cannot clean up after SIGKILL: the command and relays then outlive the shim.

The script works around these Bash and tool behaviors; `scripts/test/mcp-stdio-shim-test.sh` exercises the paths. Keep the workarounds when editing it.

- An asynchronous subshell ignores SIGINT and SIGQUIT and can lose a signal that arrives before `exec`, so a fresh Bash starts the command behind a gate.
- Bash 5.2 can run a pending trap inside a process or command substitution and then fail to parse it, so nothing is substituted after the traps are set.
- Bash 5.2 can lose a child that exits while a signal interrupts `wait`, and a later `wait` for it never returns, so the shim waits for a process only while it exists.
- Bash ignores an untrapped SIGINT while it waits for a foreground command that exits normally.
- Bash reports a job killed by an untrapped signal on its own stderr when it reaps it, so the shim's stderr is `/dev/null` and the command gets the original fd 2.
- Bash closes a coprocess's pipes once it exits, so the input relay waits for EOF on its own stdin until the shim holds its output.
- GNU `tee` writes standard output first and BSD `tee` last; each branch writes `in.jsonl` before the command's pipe.
- BSD `chmod` rejects `--`, so the log path is made absolute first.
