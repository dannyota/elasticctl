# Releasing elasticctl

Maintainer procedure. Users do not need this; see the README to install.

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
step 4 now runs before step 6: the real tag proves the build while both the tag
and the Release are still deletable. What it *can* insure, since 0.1.3, is the
publish. A crates.io version is permanent — yanking hides it from resolution
but never removes it — and `cargo install elasticctl` now has users to break.
When a release changes packaging rather than the target list, `cargo publish`
a `-rc.N` first: pre-release versions are ignored by a `^0.1` requirement and
by `cargo install` unless asked for by name, so it is a real rehearsal rather
than a permanent mistake.

