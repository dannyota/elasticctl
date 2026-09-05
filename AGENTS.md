<!--
Maintainer notes: keep under 200 lines because this file loads every session. Include only rules
that are easy to violate, not rules derivable from code or the spec. Sync changes with their owner.
-->

# elasticctl

Rust CLI for operating Elastic Security detection rules as code across self-managed, Elastic
Cloud Hosted, and Serverless deployments. Its sibling,
[splunkctl](https://github.com/dannyota/splunkctl), is the reference for operating contracts.

**Read `docs/specs/elasticctl-design.md` before changing anything.** It is the source of truth
for scope, architecture, and verified API behavior. When code and spec disagree, the spec wins.
Update the spec first; never silently improve. Documentation is the contract. A behavioral change
updates the spec in the same commit. Remove a closed backlog item from the current backlog.
Guidance precedence is: the user's current instruction, the spec, then this file.

| Task | Read first |
| --- | --- |
| Any behavior change | `docs/specs/elasticctl-design.md` |
| Releasing | `docs/releasing.md` |
| Re-recording fixtures | "Testing" and "Sample data" below, `xtask/src/main.rs` |

## Development workflow

Design first: the brief is its product. Prefer `gpt-5.6-sol` for design, reviews, and
complex implementation or debugging. Use `gpt-5.6-terra` for routine implementation and
`gpt-5.6-luna` for exploration, tests, and small mechanical edits. Set the model explicitly
on every dispatch.

Use Sol for every code, defect, plan, and phase review. Mutation paths, credential handling,
and release workflows need adversarial review. Sol may implement complex work; a separate
Sol reviewer checks it. The coordinator owns planning, verification, Git operations, and the
final answer. Inspect worker edits and rerun relevant checks before accepting them.

Use parallel agents for independent tasks once the plan pins files and interfaces. Each runs
in its own git worktree. Agents own named files, never directories, and no two workers edit
the same file. Give each worker a self-contained brief with its objective, authorities,
constraints, owned files, forbidden actions, checks, and report contract. Review each task
before dependent work uses it. Run only one build-heavy command at a time, with two Cargo
jobs and four test threads.

## Architecture rules

Dependency direction is strictly one way and must not be broken:

```
elasticctl-cli  →  elasticctl-api  →  elasticctl-core
```
`-core` owns config, transport, auth, and errors; `-api` owns the model and the
rules/exceptions/state orchestration; `-cli` owns `clap` parsing, `render`, and the dry-run guard.
- **API orchestration returns typed values.** CLI adapters handle command context and mutation
  guards, then serialize values for `elasticctl-cli::render`. This keeps a future MCP server
  additive: it calls the same API functions and serializes the same structs. A command that prints
  gives MCP only a string to re-parse.
- **Orchestration belongs in `-api`.** `cli/cmd/` adapters must not own stack orchestration; MCP
  cannot depend on `-cli`. Moving orchestration must preserve byte-identical output, proven by
  snapshots.
- **`clap` types never appear in `-api` or `-core`.** Pass a value, not a parsed arg struct.
- Flavor differences use the runtime capability probe, not compile-time traits or per-flavor
  modules.
- `xtask` may depend on `-api` and `-core`, never on the CLI crate, and ships nothing — it is the
  dev-tool crate (`publish = false`).

## Safety contracts

- Every remote mutation is a dry run by default. `--yes` applies. Both preview and apply print
  profile, host, and space.
- **`state push` never deletes remote rules or exception list containers.** A missing local rule
  is not a delete instruction. Delete them only through `rules delete` or `exceptions delete`.
  From 0.2, exception *items* inside a mirrored container reconcile exactly, including deletes,
  because a container's item set is always written in full. Spec 5.4 gives the reasoning.
- State rule identity is **always `rule_id`** — never display name or volatile saved-object `id`.
  Exception list identity is **always `list_id` plus `namespace_type`**. Pull strips a rule's
  `exceptions_list[].id`; push re-resolves it. Spec 4.5.
- Never put credentials in URLs. Debug logs complete URLs, but exclude authorization headers and
  bodies.

## Credentials

`.env` holds live credentials for the development stack. It is gitignored and mode `0600`;
`.env.example` is the placeholder-only template.

- Never commit it, copy its contents into tracked files, or echo a key into output or commits.
- Live systems are trial-only Serverless and Hosted test deployments. Never expose their URLs, IDs, credentials, or
  identifying data. The trial was extended; it ends 2026-09-08 at 08:56 UTC.
- The Hosted deployment stays running for the whole trial. Do not stop, suspend, or tear it
  down; a stopped deployment changes its endpoints on restart and invalidates `.env`.
- `.env.example` is the committed template and must contain placeholders only.
- An **organization-level** Cloud API key is not enough. Every key type carries the `essu_`
  prefix, so it does not indicate scope. Only `GET /_security/_authenticate` reports the realm.
  An organization key can read and create *disabled* rules, but **cannot enable a rule**. The
  alerting framework refuses to mint a rule API key on its behalf. Enable, disable-apply, and
  `state push` need a **project-scoped Elasticsearch API key** created inside Kibana.
- Recording reads the generic `ELASTICCTL_*` target and `ELASTICCTL_FIXTURE_FLAVOR`. Map a second
  `ELASTICCTL_ECH_*` target to those generic names for the recorder command. A worktree has no
  `.env`; source the main checkout instead of copying it.

## Elastic API gotchas

- `kbn-xsrf: true` is required on every non-GET Kibana request or it is rejected.
- `elastic-api-version: 2023-10-31` is required on versioned public APIs.
- **Two error envelope shapes exist.** The Cloud edge proxy returns
  `{"ok":false,"message":"Unknown resource."}`; Kibana returns
  `{"statusCode":...,"error":...,"message":...}`. The classifier must handle both. The edge
  shape also appears for a hostname that no longer resolves after a project rename.
- `rules/_export` ends with a `{"exported_count":N,...}` summary object. It is a trailer, not a
  rule. With zero rules it is the entire body.
- `_bulk_action` targets rules by stable `rule_id` through
  `alert.attributes.params.ruleId: "<rule_id>"`, so no server-id lookup is needed. It also accepts
  `?dry_run=true` for a server-computed preview. Enable/disable/delete are idempotent — acting on a
  rule already in the target state reports `succeeded`, and a missing rule is just absent from
  `total` — so `skipped` stays `0` for every action elasticctl sends. The
  `total == succeeded + failed + skipped` invariant's `skipped > 0` branch is defensive-only.
- Rule export includes volatile `id`, `created_at`, `created_by`, `updated_at`, `updated_by`,
  `version`, `revision`, and `execution_summary`. Normalize them away on `pull` or every diff is
  false drift.
- A real self-managed stack reports `version.build_flavor: "traditional"`, not `"default"`. Only
  `"serverless"` is matched exactly; everything else falls through to hostname detection.
- `rules/preview` returns `{preview_id, invocations, errors, warnings}` and **no hit count**.
  Four hits and zero hits are byte-identical responses. Query the preview alerts index separately
  with `preview_id`. The only in-band hit signal is the `max_signals` warning at 100+.
- Re-importing existing rules without overwrite is a per-rule 409 storm, not a skip: N "already
  exists" errors and exit 1.
- ES|QL `POST /_query/async` rejects `format`: a `format: csv` body is a 400 "unknown field".
  `columnar: true` is accepted, so CSV export transposes the columnar response client-side.

## Testing

```bash
cargo test                                    # unit + fixture, offline, no stack needed
ELASTICCTL_LIVE=1 cargo test -- --ignored     # live suite against a real stack
cargo xtask record                            # re-record fixtures from a live stack
cargo xtask conformance-matrix --report-dir <path>  # all three live conformance legs, concurrently
cargo fmt --all --check                       # the CI gate, alongside:
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories bans licenses sources
./scripts/check-packages.sh && ./scripts/check-fixtures.sh && ./scripts/check-conformance-reports.sh
cargo publish --workspace --dry-run --locked  # release preflight, no upload
```

The test harness runs one thread per logical core. Cap it per run with
`cargo test -- --test-threads=6` (the dev machine has 8 cores) so a full offline suite does not
oversubscribe the CPU. Do not commit `RUST_TEST_THREADS` to `.cargo/config.toml`; CI runners have
fewer cores than the dev machine.

Fixtures are recorded from real traffic, never hand-written. They are tagged with flavor and
stack version, and live in `tests/fixtures/<flavor>-<version>/`. Do not hand-edit a fixture to
make a test pass; re-record it.

The directory is named for the *deployment* flavor, not the reported flavor. Hosted and
self-managed both report `build_flavor: "traditional"`. Recording a Hosted stack without
`ELASTICCTL_FIXTURE_FLAVOR=ech` overwrites `traditional-9.5.1`.

Fixtures are public, so scope every recording request to the probe rule. An unscoped `_find` or
`_export` writes real rule content into the repo. Scrub identity (`username`, `full_name`,
`email`, `created_by`, `updated_by`) and credentials. The export fixture holds NDJSON as an opaque
string, so it needs its own scrub pass.

## Development target and live testing

Serverless is the primary target; nothing needs to run locally day to day. The `lab/` podman
stack is an on-demand session (~3 GB, ~20 minutes) used only to record self-managed fixtures. Do
not assume it is running. `podman compose` delegates to `docker-compose`; `podman-compose` is not
installed. Kibana's entrypoint maps only `UPPER_SNAKE` environment variable names. The dotted
`xpack.encryptedSavedObjects.encryptionKey` form is silently ignored, so every rule creation
fails.

Live testing against the trial Serverless and Hosted stacks is always permitted: probe them
read-only or run a marker-scoped mutation without asking first. The marker and baseline rules
below still apply.

The Serverless dev project holds ~2,066 Elastic prebuilt rules for scale testing. They are
read-only ground truth: never mutate an untagged rule. Every object a live test creates carries
the `elasticctl-sample` marker: a `rule_id` prefix and tag for rules, and
`*elasticctl-sample*` in index names. Every remote mutation targets explicit ids. A run ends by
verifying the project is back to baseline: unchanged prebuilt-rule count, no sample rules, and
no sample indices. Fleet packages are the exception: the trial stacks are development
environments, so a package a test installs (for example `system` or `elastic_agent`) may stay
installed and needs no cleanup. Marker objects are still removed.

## Sample data

Fetch, never vendor: third-party rule and event content stays out of this public repo; scripts
download it on demand. Verified licenses (2026-08-13): SigmaHQ/sigma is DRL 1.1 — attribution
and license notice required; OTRF/Security-Datasets is MIT (its README's GPL-3.0 line is stale);
elastic/detection-rules is Elastic License v2 — never commit its content;
sbousseaden/EVTX-ATTACK-SAMPLES has no license — do not use it at all.

`sigma-cli` with `-t lucene -p ecs_windows -f siem_rule_ndjson` converts Sigma rules to importable
NDJSON. Mordor events use pre-ECS Winlogbeat field names (`EventID`, `CommandLine`, `Image`).
Remap them to ECS and rewrite `@timestamp` to now before ingest, or no rule can match.

## Release

The binary crate package is `elasticctl` (directory `crates/elasticctl-cli`), so
`--package elasticctl-cli` does not resolve. Publish by dispatching
`.github/workflows/publish-crates.yml` with the released tag; the owner approves the
`crates-io` environment and the job runs `cargo publish --workspace` with a Trusted Publishing
token after checking the Release assets. That command from the tagged commit is the manual
fallback. Either way `cargo publish --workspace` verifies all three crates against a temporary
registry before uploading any. Never publish crate-by-crate. A partial failure strands crates on
crates.io, where versions can be
yanked but not deleted. cargo-dist installs as `dist`; `cargo dist` does not resolve.
`dist build --artifacts=host` builds only the host target.

**A release does not publish to crates.io.** The default release is the tag and GitHub Release
binaries, and stops there. Publishing needs the owner's explicit approval for that release. A
standing "we publish now" from 0.1.3 or approval for a previous version is not enough. Never run
`cargo publish` or dispatch the publish workflow as a step in a release you were asked to cut.
Ask, and release the rest meanwhile; a version can follow onto crates.io later, but it cannot be
taken back.

When approval is given, tag first and publish last. The tag and GitHub Release are deletable; a
crates.io version is not, so publish only after the matrix produces a complete asset list.

Cut an `-rc.N` tag only when the build matrix is unproven: it has never run, or its target list
changed. Check the last release's assets first. A complete list means a candidate proves nothing.
Since 0.1.3 a candidate can also be *published* — pre-release versions are ignored by `^0.1` and
by `cargo install` — which is worth doing when a release changes packaging rather than targets.
`docs/releasing.md` explains why.

## Git

`AGENTS.md` holds the agent rules and `CLAUDE.md` is its one-line import; both are tracked in the
repository (re-included via `.gitignore` negations). Durable rules still belong in
`CONTRIBUTING.md` or the design spec.
