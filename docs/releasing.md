# Releasing elasticctl

Maintainer procedure. Users do not need this; see the README to install.

A release builds cross-platform binaries and publishes a GitHub Release. It
does **not** publish to crates.io. Publishing is a separate workflow that runs
only when the owner dispatches it for that version, and most releases never
reach it.

Publishing to crates.io is a separate, opt-in step that needs the owner's
explicit approval for that specific version. Approval does not carry forward:
0.1.3 being on crates.io is not permission to put 0.1.4 there. The asymmetry is
the reason — a tag and a GitHub Release can be deleted, while a crates.io
version can only be yanked, which hides it from resolution without removing it.
A version withheld today can be published tomorrow; one published today cannot
be withdrawn.

When approval is given, publish all three crates together or none.
`cargo publish --workspace` packages and verifies all three before uploading
any, so a verification failure cannot strand a published crate with an
unpublished dependency. The binary depends on both libraries by version, so
publishing it alone leaves `cargo install elasticctl` unable to resolve.
(`elasticctl-api` depends on `elasticctl-core`, and `elasticctl` on both;
`xtask` is not published.)

1. Bump the version in `Cargo.toml`: `[workspace.package] version` and the
   `version` fields for `elasticctl-core` and `elasticctl-api` in
   `[workspace.dependencies]`. Bumping only `[workspace.package] version`
   leaves stale `0.1.0` requirements in the dependency metadata.
2. Add a dated entry to `CHANGELOG.md`.
3. Run formatting, locked Clippy, locked workspace tests, package-content and
   fixture-leak checks, then `cargo publish --workspace --dry-run --locked`.
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
   and repeats the dry run. Only then does the `publish` job wait for the
   environment approval and publish all three crates with a short-lived
   crates.io Trusted Publishing token. `cargo publish --workspace` from the
   tagged commit is the manual fallback.

The complete local gate for step 3 is:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
./scripts/check-packages.sh
./scripts/check-fixtures.sh
cargo publish --workspace --dry-run --locked
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

Step 3 stays in the default path even though step 8 usually does not run. The
dry run costs one build and catches packaging errors — a missing `include`, a
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

Trusted Publishing is the second first-dispatch prerequisite. Configure it
once per crate on crates.io (crate settings, Trusted Publishing): repository
owner `dannyota`, repository name `elasticctl`, workflow filename
`publish-crates.yml`, environment `crates-io`. All three crates need the same
entry; a dispatch made before that fails at the token exchange, after the
`verify` job, and publishes nothing. A crate that has never been published
must go through the manual fallback once before Trusted Publishing can be
configured for it.

Cross-platform artifacts are built by
[`cargo-dist`](https://opensource.axo.dev/cargo-dist/); the matrix runs in CI.
To build only the host target locally: `dist build --artifacts=host`.

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
When a release changes packaging rather than the target list, `cargo publish`
a `-rc.N` first: pre-release versions are ignored by a `^0.1` requirement and
by `cargo install` unless asked for by name, so it is a real rehearsal rather
than a permanent mistake.
