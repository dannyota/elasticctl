# Contributing to elasticctl

## Setup

Requires a stable Rust toolchain.

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cp .env.example .env    # fill in your Elastic endpoints and API key
cargo test --jobs 2 -- --test-threads=4
```

`cargo test` needs no stack and no credentials. `.env` only matters for the
live suite and for recording fixtures.

## Read the spec before changing behavior

`docs/specs/elasticctl-design.md` is the source of truth for scope,
architecture, and verified API behavior. When code and spec disagree, the spec
wins and the fix lands in the spec first. A change that alters behavior
updates the spec in the same commit — docs here are the contract, not a
description written afterwards.

## Tests and gates

CI runs workspace nextest tests and separate doctests on Linux/macOS, Windows
regressions, and the extra gates in `instructions/testing.md`. Run them before
opening a pull request.

```bash
cargo test --jobs 2 -- --test-threads=4
cargo fmt --all --check
cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
```

On the development laptop, use two build jobs and four test threads, and run
one build-heavy command at a time. Keep these limits per command so CI can use
its runner defaults. Prefer GitHub Actions for release builds and preflight;
crates.io publishing runs only through GitHub Actions.

Tests come in three tiers. Unit and fixture tests run offline against recorded
traffic and need no stack. The live tier runs against a real deployment and is
opt-in:

```bash
ELASTICCTL_LIVE=1 cargo test --locked --test live -- --ignored --test-threads=1
cargo xtask conformance --flavor serverless \
  --report-dir docs/conformance/v0.2.5
cargo xtask conformance-matrix --report-dir docs/conformance/v0.2.5
```

A live run creates only objects marked `elasticctl-sample` and verifies the
stack is back to baseline when it finishes. Never point it at production.
The conformance runner reads the same generic `ELASTICCTL_*` variables as the
fixture recorder. Map `ELASTICCTL_ECH_*` into those names for Hosted. Raw test
output stays under the ignored `target/conformance-private/` directory; only
the scrubbed report is tracked. Supply the disposable lab key only to the
runner process and never persist it. `conformance-matrix` runs all three
flavors above as concurrent child processes instead of one at a time; see
design spec 8.3.

## Fixtures are recorded, never written

`tests/fixtures/` holds real exchanges captured by `cargo xtask record`, tagged
with deployment flavor and stack version. **Do not hand-edit a fixture to make
a test pass — re-record it.** A hand-edited fixture asserts what we assumed
Elastic sends rather than what it sent, which is the failure the whole tier
exists to prevent.

Fixtures are public. Scope every recording request to the probe rule: an
unscoped `_find` or `_export` writes real rule content into a public
repository. Scrub identity (`username`, `full_name`, `email`, `created_by`,
`updated_by`) and every credential.

After sourcing `.env`, `cargo xtask record` reads the generic
`ELASTICCTL_*` target. A second Hosted target may use `ELASTICCTL_ECH_*`
names in `.env`, but the recorder does not read those names directly. Map its
Kibana URL, Elasticsearch URL, and API key to the generic names and set
`ELASTICCTL_FIXTURE_FLAVOR=ech` for that command. The exact example is in
`.env.example`.

## CI workflows

- `ci.yml`, `codeql.yml`, and `wiki.yml` group runs by workflow and by the
  pull request ref, or by the commit for any other event. A new push to a pull
  request cancels its older run; a newer `master` push never cancels a pending
  `master` run.
- The wiki `publish` job runs one at a time in the `wiki-publish` group
  without cancelling, and checks out the `master` tip. A run that starts late
  cannot put older pages back.
- `test-macos`, `transaction-windows`, and `declared-rust` wait for the Linux
  `test` job, so a failing change does not hold the scarcer runners.
- `taiki-e/install-action` supports neither gitleaks nor actionlint
  ([tool list](https://github.com/taiki-e/install-action/blob/main/TOOLS.md)).
  Those jobs download the pinned release and check its SHA-256 against the
  value in the release's checksums file.
- `gitleaks` scans with `--diff-merges=separate`. By default `git log -p`
  shows no diff for a merge commit, so it would miss a secret added while
  resolving a merge ([git log](https://git-scm.com/docs/git-log)).
  `.gitleaks.toml` extends the default rules, and each allowlist entry names
  one known non-secret value and why it is safe.
- macOS ships Bash 3.2. Sample scripts and every script the macOS jobs run
  avoid Bash 4 features such as associative arrays. `mcp-stdio-shim.sh` needs
  Bash 4.4, so CI runs its test on Linux only.

## Dependency policy

`deny.toml` sets what `cargo deny check advisories bans licenses sources`
enforces. CI runs it on every push and weekly, because a new advisory can
affect an unchanged tree.

- **Advisories.** Every RustSec vulnerability fails; cargo-deny has no
  setting that downgrades one
  ([advisories config](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html)).
  A yanked version fails. An unmaintained advisory fails only for a direct
  dependency: on a transitive crate it is a signal, not a release blocker.
- **Licences.** The crates are Apache-2.0, and the allow list holds the
  permissive licences the tree uses. Any other licence needs an explicit
  decision. `MPL-2.0` covers `option-ext`, reached through `directories` and
  `dirs-sys`, with no alternative licence. MPL-2.0 is file-level copyleft:
  linking it is allowed, and only changes to its files would have to be
  published. We vendor and change none. `Zlib` covers `foldhash`, reached
  through `hashbrown` and `indexmap`.
- **Bans.** Duplicate versions warn, because they usually mean transitive
  lag. A wildcard version requirement fails, except on a path dependency
  (`allow-wildcard-paths`), so the unpublished `elasticctl-api-test-support`
  dev-dependency stays versionless and Cargo omits it from published
  manifests. Keep direct dependencies current. Each `skip` names one exact
  older version and the upstream that still needs it, so an upstream change
  shows up instead of widening the exception.
- **Sources.** Only crates.io. A git or other registry dependency needs an
  explicit decision.

## What review will hold you to

The reasoning is in the spec, sections 3 and 6. The rules themselves:

- Dependency direction is one way: `cli` → `api` → `core`.
- API command orchestration returns typed values and never prints. CLI adapters
  resolve context, apply mutation guards, and serialize values for rendering.
- `clap` types never appear in `-api` or `-core`.
- Every remote mutation is a dry run until `--yes`, and both preview and apply
  name the profile, host, and space.
- `state push` never deletes a remote rule or exception-list container. It
  deletes an exception item only when that item is absent from a complete local
  mirror of a container present on both sides.
- Rule identity is always `rule_id` — never the display name, never the
  saved-object `id`.
- Exception-list identity is `list_id` + `namespace_type`.
- Never put credentials in URLs. Debug logs complete URLs, but exclude
  authorization headers and bodies.

## Credentials

`.env` is gitignored and mode `0600`. Never commit it or copy its contents into
a tracked file. Keep real test-system URLs, deployment IDs, account data, and
credentials out of terminal output and commit messages. `.env.example` is the
committed template and holds placeholders only.

## Releasing

Maintainers only: [`docs/releasing.md`](docs/releasing.md).

## Agents

Agent instructions live in the tracked `AGENTS.md`, which maps topic rules in
`instructions/`; `CLAUDE.md` imports it. Repository-local ignore exceptions
keep both files tracked despite global ignore defaults. Durable project rules
belong in this file or the design spec.

## Commits

Use Conventional Commits (`fix(deps): ...`, `docs(spec): ...`, `ci: ...`,
`chore: release X.Y.Z`) and sign them. Messages describe the change only.
