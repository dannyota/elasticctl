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

## Read the spec before changing behaviour

`docs/specs/elasticctl-design.md` is the source of truth for scope,
architecture, and verified API behaviour. When code and spec disagree, the spec
wins and the fix lands in the spec first. A change that alters behaviour
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
ELASTICCTL_LIVE=1 cargo test -- --ignored
```

A live run creates only objects marked `elasticctl-sample` and verifies the
stack is back to baseline when it finishes. Never point it at production.

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

## What review will hold you to

The reasoning is in the spec, sections 3 and 6. The rules themselves:

- Dependency direction is one way: `cli` → `api` → `core`.
- Command functions return typed values and never print. Rendering belongs to
  `elasticctl-cli::render`.
- Orchestration belongs in `-api`; `cli/cmd/` parses arguments and renders.
- `clap` types never appear in `-api` or `-core`.
- Every mutation is a dry run until `--yes`, and both preview and apply name
  the profile, host, and space.
- `state push` never deletes a remote rule. Deletion is only `rules delete`.
- Rule identity is always `rule_id` — never the display name, never the
  saved-object `id`.
- Secrets are redacted everywhere, including `--debug` HTTP logs.

## Credentials

`.env` is gitignored and mode `0600`. Never commit it, never copy its contents
into a tracked file, and never echo a key into terminal output or a commit
message. `.env.example` is the committed template and holds placeholders only.

## Releasing

Maintainers only: [`docs/releasing.md`](docs/releasing.md).

## Agents

`CLAUDE.md` carries these same rules in the form Claude Code reads. If you
change a rule here, change it there too.
