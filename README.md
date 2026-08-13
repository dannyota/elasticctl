# elasticctl

**Operate Elastic Security as code with a safety-first CLI for security engineers.**

`elasticctl` is a Rust CLI for managing Elastic Security detection rules as
code, across self-managed stacks, Elastic Cloud Hosted deployments, and Elastic
Cloud Serverless projects. It is a sibling to
[splunkctl](https://github.com/dannyota/splunkctl) and shares its operating
contracts:

- **Every mutation is a dry run by default.** Nothing changes until you pass
  `--yes`, and every preview names the profile, host, and space it would touch.
- **Configuration as code.** Pull live rules, review structured drift, push
  approved changes with a change-evidence report. Push never deletes remote
  rules.
- **Stable machine output.** Table by default, `--json` on request, typed error
  envelopes on stderr.
- **Named profiles** for separate development, UAT, and production instances.

An MCP server is planned once the CLI surface is stable.

## Install

Two options: build from crates.io, or download a prebuilt binary.

### From crates.io

Requires a Rust toolchain (stable).

```bash
cargo install elasticctl
```

### From GitHub Releases

Each release ships prebuilt binaries for Linux (glibc and musl), macOS
(Intel and Apple Silicon), and Windows. Download the archive for your platform
from the [latest release](https://github.com/dannyota/elasticctl/releases/latest)
and put the `elasticctl` binary on your `PATH`, or use an installer script:

```bash
# macOS and Linux
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/dannyota/elasticctl/releases/latest/download/elasticctl-installer.sh \
  | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/dannyota/elasticctl/releases/latest/download/elasticctl-installer.ps1 | iex"
```

## Quickstart

Point `elasticctl` at your stack and write a profile. Credentials come from
`ELASTICCTL_*` environment variables; `.env.example` documents them. The key
must be a project-scoped Elasticsearch API key created inside Kibana — an
organization-level Cloud key can read and create disabled rules but cannot
enable one.

```bash
export ELASTICCTL_KIBANA_URL=https://YOUR-PROJECT.kb.YOUR-REGION.aws.elastic.cloud
export ELASTICCTL_API_KEY=...
elasticctl config init --from-env
```

Confirm the stack is reachable, the key scope is right, and rules are readable:

```bash
elasticctl doctor
```

The rules-as-code loop:

```bash
elasticctl state pull --dir state   # writes state/rules/*.ndjson
# edit rules, or add new ones
elasticctl state diff --dir state   # field-level drift, no changes made
elasticctl state push --dir state   # preview; add --yes to apply
```

`push` and every other mutation preview by default and apply only with `--yes`.

Inspect and manage individual rules:

```bash
elasticctl rules list
elasticctl rules get <rule_id-or-name>
elasticctl rules validate --path rule.yaml
elasticctl rules enable <rule_id> --yes
elasticctl rules export --format-file ndjson --out rules.ndjson
```

## Command surface

```
elasticctl config init | list | show | test
elasticctl doctor
elasticctl info

elasticctl rules list | get | validate | enable | disable | delete
elasticctl rules export | import | preview

elasticctl state pull | diff | push

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands
```

Global flags: `--profile`, `--config`, `--space`, `--json` / `--format`,
`--fields`, `--out`, `--yes`, `--timeout`, `--debug`. Run `elasticctl help` for
details.

## Releasing

Releases go out two ways: the three crates on crates.io, and cross-platform
binaries on GitHub Releases. `cargo publish --workspace` packages and verifies
all three crates before uploading any of them, so a verification failure cannot
strand a published crate with an unpublished dependency. (`elasticctl-api`
depends on `elasticctl-core`, and `elasticctl` depends on both; `xtask` is not
published.)

1. Bump the version in `Cargo.toml` in two places: `[workspace.package] version`
   and the `version` fields of `elasticctl-core` and `elasticctl-api` in
   `[workspace.dependencies]`. Bumping only `[workspace.package] version` leaves
   stale `0.1.0` requirements in the dependency metadata.
2. Add a dated entry to `CHANGELOG.md`.
3. `cargo publish --workspace --dry-run` — confirm all three package and
   verify-compile.
4. `cargo publish --workspace`.
5. `git tag vX.Y.Z && git push --tags`. The tag triggers
   `.github/workflows/release.yml`, which builds the binary matrix and publishes
   the GitHub Release.

Cross-platform artifacts are built by
[`cargo-dist`](https://opensource.axo.dev/cargo-dist/); the matrix runs in CI.
To build only the host target locally: `dist build --artifacts=host`.

## Development

Requires a stable Rust toolchain.

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cp .env.example .env    # fill in your Elastic endpoints and API key
cargo test
```

`.env` is gitignored. Never commit credentials.

## License

Apache-2.0
