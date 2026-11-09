# Testing, fixtures, and sample data

## Gates

CI runs all but the last on every pull request; the publish dry run is the manual
`release-preflight.yml` workflow. Run them before opening a pull request.

```bash
cargo test --locked --workspace                   # unit + fixture, offline, no stack needed
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny check advisories bans licenses sources
./scripts/check-packages.sh && ./scripts/check-fixtures.sh && ./scripts/check-conformance-reports.sh
cargo publish --workspace --dry-run --locked      # release preflight, no upload
```

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

The directory is named for the *deployment* flavor, not the reported flavor. Hosted and
self-managed Kibana both report `build_flavor: "traditional"`. Recording a Hosted stack without
`ELASTICCTL_FIXTURE_FLAVOR=ech` overwrites `traditional-9.5.1`.

Fixtures are public, so scope every recording request to the probe rule. An unscoped `_find` or
`_export` writes real rule content into the repo. Scrub identity (`username`, `full_name`,
`email`, `created_by`, `updated_by`) and credentials. The export fixture holds NDJSON as an opaque
string, so it needs its own scrub pass.

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
