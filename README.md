# elasticctl

**A safety-first CLI to operate Elastic Security as code.**

`elasticctl` is a Rust CLI for managing Elastic Security detection rules as
code across self-managed stacks, Elastic Cloud Hosted deployments, and Elastic
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

Install from crates.io or download a prebuilt binary.

### From crates.io

Requires the stable Rust toolchain.

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

Create a profile from `ELASTICCTL_*` environment variables; `.env.example`
documents them. The key must be a project-scoped Elasticsearch API key created
inside Kibana. An organization-level Cloud key can read and create disabled
rules but cannot enable one.

```bash
export ELASTICCTL_KIBANA_URL=https://YOUR-PROJECT.kb.YOUR-REGION.aws.elastic.cloud
export ELASTICCTL_API_KEY=...
elasticctl config init --from-env
```

Confirm the stack is reachable, the key scope is right, and rules are readable:

```bash
elasticctl doctor
```

Manage rules as code:

```bash
elasticctl state pull --dir state   # writes state/rules/*.ndjson
# edit rules, or add new ones
elasticctl state diff --dir state   # field-level drift, no changes made
elasticctl state push --dir state   # preview; add --yes to apply
```

`push` and every other mutation preview by default and apply only with `--yes`.

All three take the same positional selectors and `--tag` as `rules export`.
A selection narrows both sides before drift is computed. A scoped run reads one
filtered query instead of the whole corpus:

```bash
elasticctl state diff --dir state my-rule-id      # one rule
elasticctl state push --dir state --tag prod      # one tag
```

`diff` and `push` resolve a selector against the directory first, so a rule you
have only written locally is selectable by name before it exists on the stack.

Inspect and manage individual rules:

```bash
elasticctl rules list
elasticctl rules get <rule_id-or-name>
elasticctl rules validate --path rule.yaml
elasticctl rules enable <rule_id> --yes
elasticctl rules export --tag my-corpus --out rules.ndjson
elasticctl rules preview my-rule-id --sample 3
```

## Command surface

```
elasticctl config init | list | show | test
elasticctl doctor
elasticctl info

elasticctl rules list | get | validate | enable | disable | delete
elasticctl rules export [<selector>...] [--tag TAG] | import [--skip-existing] | preview [--sample N]

elasticctl state pull | diff | push  [<selector>...] [--tag TAG] --dir DIR

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands
```

Global flags: `--profile`, `--config`, `--space`, `--json` / `--format`,
`--fields`, `--out`, `--yes`, `--timeout`, `--debug`. Run `elasticctl help` for
details.

## Releasing

Releases publish the three crates to crates.io and cross-platform binaries to
GitHub Releases. `cargo publish --workspace` packages and verifies all three
crates before uploading any. A verification failure therefore cannot strand a
published crate with an unpublished dependency. (`elasticctl-api` depends on
`elasticctl-core`, and `elasticctl` depends on both; `xtask` is not published.)

Releases through 0.1.2 were tagged without publishing. From 0.1.3, the tag
builds GitHub Release binaries and the workspace publishes to crates.io.
Publish all three crates together or none. The binary depends on both libraries
by version, so publishing it alone leaves `cargo install elasticctl` unable to
resolve.

1. Bump the version in `Cargo.toml` in two places: `[workspace.package] version`
   and the `version` fields of `elasticctl-core` and `elasticctl-api` in
   `[workspace.dependencies]`. Bumping only `[workspace.package] version` leaves
   stale `0.1.0` requirements in the dependency metadata.
2. Add a dated entry to `CHANGELOG.md`.
3. `cargo publish --workspace --dry-run` — confirm all three package and
   verify-compile.
4. `git tag vX.Y.Z && git push --tags`. The tag triggers
   `.github/workflows/release.yml`, which builds the binary matrix and publishes
   the GitHub Release.
5. Confirm the release carries a complete asset list.
6. `cargo publish --workspace`, from the tagged commit.

Publish last, because it is the only step that cannot be undone. A tag and a
GitHub Release can be deleted; a crates.io version can only be yanked. Running
the matrix first means a broken build costs a deleted tag rather than a
permanent version, and it makes every release prove itself the way a release
candidate would.

Cross-platform artifacts are built by
[`cargo-dist`](https://opensource.axo.dev/cargo-dist/); the matrix runs in CI.
To build only the host target locally: `dist build --artifacts=host`.

### Do not write a credential-shaped URL in the changelog

cargo-dist embeds the changelog entry in the plan manifest. The workflow passes
that manifest between jobs as a job output. The GitHub runner masks anything
resembling a URL credential — the literal `user:password@host` form. If an
output contains masked text, the runner **drops the whole output** with `Skip
output 'val' since it may contain secret`. The build matrix comes from that
output, so every build job silently skips. The release then publishes only a
manifest while reporting success.

Describe such a URL in prose instead. If a release ever produces only
`dist-manifest.json`, look for that warning in the `plan` job first.

### When a release candidate is worth it

Tag an `-rc.N` only when the build matrix is unproven: it has never run, or
`dist-workspace.toml` changed its target list. Check the last release's assets
first:

```bash
gh release view vX.Y.Z --json assets --jq '.assets[].name'
```

A complete asset list means the matrix works, so tag the real version.
Otherwise, tag `-rc.1`, confirm its assets, install from it, then delete the
release and tag before tagging for real.

A release candidate costs a second full matrix build and four cleanup commands.
Once a release has proved an unchanged matrix, repeating that test adds little
protection. Test it again only after the target list changes.

What a candidate no longer has to insure against is the matrix itself, because
step 4 now runs before step 6: the real tag proves the build while both the tag
and the Release are still deletable. What it *can* insure, since 0.1.3, is the
publish. A crates.io version is permanent — yanking hides it from resolution
but never removes it — and `cargo install elasticctl` now has users to break.
When a release changes packaging rather than the target list, `cargo publish`
a `-rc.N` first: pre-release versions are ignored by a `^0.1` requirement and
by `cargo install` unless asked for by name, so it is a real rehearsal rather
than a permanent mistake.

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
