# Releasing elasticctl

Maintainer procedure. Users do not need this; see the README to install.

A release builds cross-platform binaries and publishes a GitHub Release. It
does **not** publish to crates.io. Publishing is a separate workflow that runs
only when the owner dispatches it for that version, and most releases never
reach it. Publish to crates.io only through GitHub Actions; never publish
locally.

Publishing to crates.io is a separate, opt-in step that needs the owner's
explicit approval for that specific version. Approval does not carry forward:
0.1.3 being on crates.io is not permission to put 0.1.4 there. The asymmetry is
the reason — a tag and a GitHub Release can be deleted, while a crates.io
version can only be yanked, which hides it from resolution without removing it.
A version withheld today can be published tomorrow; one published today cannot
be withdrawn.

When approval is given, submit all four crates through one workspace command.
Cargo packages and verifies all four before uploading dependency-ready crates.
Uploads are not atomic: a registry rejection or connection failure can leave a
partial version set. The binary depends on all three libraries by version, so
publishing it alone can leave `cargo install elasticctl` unable to resolve.
`elasticctl-mcp` depends on API and core; API depends on core. `xtask` and test
support are not published. See the
[Cargo upload sequence](https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/cargo/ops/registry/publish.rs#L150-L251).

1. Bump the version in `Cargo.toml`: `[workspace.package] version` and the
   `version` fields for `elasticctl-core`, `elasticctl-api`, and `elasticctl-mcp` in
   `[workspace.dependencies]`. Bumping only `[workspace.package] version`
   leaves stale `0.1.0` requirements in the dependency metadata.
2. Add a dated entry to `CHANGELOG.md`.
3. Run `cargo fmt --all --check`. Prefer GitHub Actions for the build and test
   gates below to limit memory use on the development laptop.
4. Push `master` and require CI success for that exact commit.
5. Dispatch `.github/workflows/release-preflight.yml` on `master` and require
   success for that same commit.
6. `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag triggers
   `.github/workflows/release.yml`, which builds the binary matrix and publishes
   the GitHub Release.
7. Confirm the release carries a complete asset list. **The release ends here.**
8. Only with the owner's explicit approval for this version: dispatch
   `.github/workflows/publish-crates.yml` with the tag and approve the
   `crates-io` environment when the run pauses for review. A `verify` job
   checks out `refs/tags/<tag>`, refuses unless every workspace version field
   equals the tag and the GitHub Release for it carries every expected asset,
   checks that all four crate names exist with the expected owner, and repeats
   the dry run. Only then does the `publish` job wait for environment approval.
   It repeats the crate ownership check before obtaining a short-lived
   crates.io Trusted Publishing token and submitting the workspace.

CI in step 4 runs formatting, locked Clippy, locked workspace tests,
package-content and fixture-leak checks. Preflight in step 5 verifies the
workspace packages without uploading them. Both must pass for the exact
release commit before tagging.

For local checks when needed, cap builds at two jobs and tests at four threads.
The package check requires Python 3.11 or later for TOML parsing.
Run one build-heavy command at a time:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --jobs 2 -- -D warnings
cargo test --locked --workspace --jobs 2 -- --test-threads=4
./scripts/check-packages.sh
./scripts/check-fixtures.sh
```

After step 4 passes CI, dispatch and identify the preflight run:

```bash
release_sha="$(git rev-parse HEAD)"
gh workflow run release-preflight.yml --ref master
gh run list --workflow release-preflight.yml --branch master \
  --event workflow_dispatch --limit 5
```

The listed run's head SHA must equal `release_sha`. Once it appears, capture
that row's numeric database ID in `preflight_run_id`, require the variable to
be nonempty, and run
`gh run watch "$preflight_run_id" --exit-status`. If the run has not appeared
yet, repeat the list command before selecting it.

Step 5 stays in the default path even though step 8 usually does not run. Its
dry run on GitHub Actions catches packaging errors — a missing `include`, a
path dependency without a version — while they are still free to fix. Finding
them later, on the day publishing is approved, means fixing them against a
version already tagged and released.

Publish last, because it is the only step that cannot be undone. A tag and a
GitHub Release can be deleted; a crates.io version can only be yanked. Running
the matrix first means a broken build costs a deleted tag rather than a
permanent version, and it makes every release prove itself the way a release
candidate would. The publish workflow enforces that order by refusing a tag
whose Release is missing any asset.

To dispatch and follow the publish run:

```bash
gh workflow run publish-crates.yml --ref master -f tag=vX.Y.Z
gh run list --workflow publish-crates.yml --limit 3
```

Capture the listed run's numeric database ID in `publish_run_id`, require it
to be nonempty, then `gh run watch "$publish_run_id" --exit-status`.

The `publish` job waits in the `crates-io` environment until the owner
approves it in the Actions UI. That gate is repository configuration, not
workflow text: the environment must exist under Settings, Environments, with
the owner as a required reviewer. GitHub creates a missing environment on
first use with no protection rules, which would let a dispatch publish
without approval, so confirm the reviewer rule before the first dispatch:

```bash
gh api repos/dannyota/elasticctl/environments/crates-io \
  --jq '.protection_rules[] | select(.type == "required_reviewers")'
```

Before every dispatch, verify each crate's Trusted Publishing entry on
crates.io: repository owner `dannyota`, repository `elasticctl`, workflow
`publish-crates.yml`, environment `crates-io`. Check all four entries and the
environment's required-reviewer rule. A successful token exchange does not
prove the token authorizes all four crates.

The normal workflow runs `scripts/check-crates-io-publish-ready.sh` in both
jobs before token exchange or upload. The guard requires all four names to
exist on crates.io with `dannyota` as an owner. A failed registry read also
stops the workflow. The guard does not inspect Trusted Publisher settings and
cannot replace the owner's settings check. Both workspace commands use
`--registry crates-io`. `cargo publish --workspace --dry-run --locked
--registry crates-io` packages, checks, and builds all selected crates without
uploading. It does not prove per-crate registry authorization or Trusted
Publisher configuration.

[Trusted Publishing requires an existing crate](https://crates.io/docs/trusted-publishing).
Version 0.7.0 of all four crates was published under an explicit, one-time
owner exception for local publication. That exception is closed.
Future publication uses the workflow above and requires separate approval
for each version. Verify every crate's ownership and Trusted Publishing
entry before dispatch; the first publication does not prove those settings.

Cross-platform artifacts are built by
[`cargo-dist`](https://opensource.axo.dev/cargo-dist/); the matrix runs in CI.
Prefer the release workflow for builds. If a local host build is needed, use
`CARGO_BUILD_JOBS=2 dist build --artifacts=host`.

## Do not write a credential-shaped URL in the changelog

cargo-dist embeds the changelog entry in the plan manifest. The workflow passes
that manifest between jobs as a job output. The GitHub runner masks anything
resembling a URL credential — the literal `user:password@host` form. If an
output contains masked text, the runner **drops the whole output** with `Skip
output 'val' since it may contain secret`. The build matrix comes from that
output, so every build job silently skips. The release then publishes only a
manifest while reporting success.

Describe such a URL in prose instead. If a release ever produces only
`dist-manifest.json`, look for that warning in the `plan` job first.

## When a release candidate is worth it

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
step 6 now runs before step 8: the real tag proves the build while both the tag
and the Release are still deletable. What it *can* insure, since 0.1.3, is the
publish. A crates.io version is permanent — yanking hides it from resolution
but never removes it — and `cargo install elasticctl` now has users to break.
When a release changes packaging rather than the target list, publish a
`-rc.N` first through `publish-crates.yml`, with the owner's approval for that
candidate and a complete GitHub Release. Pre-release versions are ignored by
a `^0.1` requirement and by `cargo install` unless asked for by name, so this
tests packaging before the final version is permanent.
