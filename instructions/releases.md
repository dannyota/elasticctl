# Releases

Read `docs/releasing.md` before any release step; this file holds the rules that are easy to
break.

- The binary crate package is `elasticctl`, not `elasticctl-cli`.
- **A release ends at the tag and GitHub Release binaries.** Publishing to crates.io needs the
  owner's explicit approval for that version; approval never carries forward. Ask separately and
  complete the release meanwhile.
- Publish last, after the matrix produces a complete asset list, only through
  `.github/workflows/publish-crates.yml` with the released tag and `crates-io` environment
  approval. Never publish locally or crate by crate. The workflow verifies all four crates before
  upload; registry uploads are not atomic. Crate ownership and Trusted Publishing must be ready
  first. Versions can be yanked, never deleted.
- Cut an `-rc.N` only for an unproven or changed build matrix; check the last release's assets.
  For packaging changes, `docs/releasing.md` covers the published-candidate exception and
  approvals.
- cargo-dist installs as `dist`, not `cargo dist`; `dist build --artifacts=host` builds the host
  only. `release.yml` is hand-edited generator output; `dist-workspace.toml` explains how to
  regenerate it without losing the edits.
- A security advisory against a shipped dependency is fixed on `master` and shipped as a patch
  release, not held for the next feature release.
