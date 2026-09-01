# Contributing to elasticctl

## Setup

Requires a stable Rust toolchain.

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cp .env.example .env    # fill in your Elastic endpoints and API key
cargo test
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

CI runs all three. Run them before opening a pull request.

```bash
cargo test
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

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

Maintainer-local agent instructions live in globally ignored `AGENTS.md`.
Durable project rules belong in this file or the design spec, where every
contributor can read them.
