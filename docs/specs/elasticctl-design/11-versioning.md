[Back to elasticctl-design](../elasticctl-design.md)

## 11. Versioning

The project follows Cargo SemVer and stays in `0.x` until the command surface
settles. Under the `0.x` rule, the minor position is the breaking position.
Cargo implements this directly: `^0.1.2` resolves to `>=0.1.2, <0.2.0`, so
every `0.1.x` is compatible and `0.2.0` is a break.

Development is iterative — ship small, ship often.

- **Patch** (`0.1.1`, `0.1.2`, …) carries fixes and small additive changes
  *inside* the capability areas that already exist: a new flag on
  `rules list`, a new output field, a bug fix.
- **Minor** (`0.2.0`, `0.3.0`, …) marks a **new capability area** — `search`,
  `dashboards`, `cases`, `fleet` — or an actual break.

A minor bump is *required* when something breaks. It is not *restricted* to
breaks. Marking each new capability area with a minor bump tells users what the
tool can do.

The dividing line is scale, not novelty. A new flag on an existing command is
a patch. A whole new command group is a minor.

Manifests always carry three components: `version = "0.1.0"`, never `"0.1"`.

Planned shape. 0.2 is fixed; the order after it is not:

| Version | Capability area |
|---|---|
| `0.1` | Detection rules as code |
| `0.2` | Exceptions, prebuilt rules, and the `-api` retrofit |
| `0.3` | Search — ES\|QL and DSL |
| `0.4` | Alert triage and cases |
| `0.5` | Dashboards and data views |
| `0.6` | Fleet and agent policies |
| `0.7` | MCP server — read-only tools over the existing verticals |
| `0.8` | Task-shaped and cross-vertical tools; resources and prompts |
| `0.9` | Mutation through plan-and-confirm |
| `1.0` | Everything stable |

The 0.3 search capability area is specified in
[`elasticctl-search-design.md`](../elasticctl-search-design.md). The 0.4 alert
triage and cases capability area is specified in
[`elasticctl-triage-design.md`](../elasticctl-triage-design.md). The 0.5 dashboard
and data-view capability area is specified in
[`elasticctl-content-design.md`](../elasticctl-content-design.md).

The 0.6 Fleet agent- and integration-policy capability area is specified in
[`elasticctl-fleet-design.md`](../elasticctl-fleet-design.md).

The 0.7 read-only MCP capability area is described in
[`elasticctl-mcp-design.md`](../elasticctl-mcp-design.md), with
[research](../../plans/v0.7-research.md) and separate plans for
[0.7.0](../../plans/v0.7.0.md), [0.7.1](../../plans/v0.7.1.md), and
[0.7.2](../../plans/v0.7.2.md). The 0.7.0 implementation, live proof, and evidence
review are complete. The 0.7.1 implementation, live proof, and final evidence
review completed on 2026-09-06. The 0.7.2 implementation, live proof, gates,
and final evidence review completed on 2026-09-06.
None grants release or publication approval.

The 0.8 task-tool, resource, and prompt capability area is described in
[`elasticctl-mcp-tasks-design.md`](../elasticctl-mcp-tasks-design.md), with
[research](../../plans/v0.8-research.md) and plans for
[0.8.0](../../plans/v0.8.0.md), [0.8.1](../../plans/v0.8.1.md), and
[0.8.2](../../plans/v0.8.2.md).

The 0.9 MCP mutation capability area is described in
[`elasticctl-mcp-mutation-design.md`](../elasticctl-mcp-mutation-design.md), with
[research](../../plans/v0.9-research.md) and plans for
[0.9.0](../../plans/v0.9.0.md), [0.9.1](../../plans/v0.9.1.md), and
[0.9.2](../../plans/v0.9.2.md).

Neither grants release or publication approval. Every 0.8 and 0.9 release
passes the three-flavor conformance matrix; when a trial deployment ends first,
the release waits for replacement deployments.

Trial deployments are temporary. Their lifetime changes execution order, not
capability boundaries. The evidence ladder is:

1. 0.2.2 hardens locked CI, declared-toolchain proof, Windows smoke coverage,
   and non-publishing package preflight.
2. 0.2.3 runs the guarded 0.2 live contracts across Serverless, Hosted, and the
   self-managed 9.5.1 compatibility floor.
3. 0.2.4 ships the bounded post-release review patch: the boundary defects found
   by a static review of the post-0.2.3 codebase, each with a regression.
4. 0.3.0 delivers the complete ES|QL and Query DSL search vertical.
5. 0.3.1 publishes the search conformance matrix and completes the deferred
   search items: ES|QL export payload, DSL hit metadata, and object search
   (`--search` and substring name matching) over rules, exceptions, and state.
6. 0.4.0 and 0.4.1 deliver alert triage and cases; 0.4.2 publishes their
   cross-flavor proof and bounded review patch.
7. 0.5.0 delivers complete data-view administration and transfer; 0.5.1 adds
   typed dashboard administration plus opaque dependency bundles; 0.5.2
   publishes the content matrix and bounded review patch.
8. 0.6.0 delivers complete Fleet agent-policy administration and transfer;
   0.6.1 adds integration-policy administration and exact package dependency
   checks; 0.6.2 publishes the Fleet matrix and bounded review patch.
9. 0.7.0 and 0.7.1 deliver the read-only MCP server; 0.7.2 publishes its
   cross-flavor proof. A later 0.7 patch re-proves it when new trial stacks
   report newer Elastic versions.

Later minor capability areas begin only after the current area is complete.
While trial stacks exist, live measurements for the current area run first.
Trial end dates stay with the owner, not in this repository. A short trial
never weakens a release gate.

The privacy, cleanup, evidence, and release gates for this sequence are defined
in §8.3, §11.2, and §12.

MCP holds its own band rather than landing at 1.0, because a 1.0 that
introduces the MCP server would declare the surface stable in the same release
that adds the least-proven code in the project. Three minors rather than one
because they are three capability areas, not one iterated three times: 0.7
proves the transport and the layering, 0.8 is where tools stop mirroring
commands and start mirroring questions, and 0.9 answers what consent means when
the caller is a model. That last one stands alone deliberately —
`--yes` has no honest MCP analogue, and a model choosing to pass it is the
failure the guard exists to prevent. Room past 0.9 is expected; if 0.8 shows the
tools want reshaping, that is a fourth area, not a reason to compress.

### 11.1 What counts as breaking

SemVer is written for library consumers, but users depend on elasticctl's CLI
and MCP surfaces, not its Rust types. Those two surfaces are the public API
that the version number describes. The library crates are published so
`cargo install` resolves; in `0.x` their Rust items are not a compatibility
promise, and a patch release may change them.

Breaking, requiring a minor bump:

- Renaming or removing a command, subcommand, or flag
- Renaming or removing a field in `--json` output
- Changing or removing an error `kind` value
- Changing an exit code's meaning
- Changing the on-disk rule format in a way older files cannot round-trip
- Renaming or removing an MCP tool, resource URI or template, or prompt
- Renaming or removing an MCP input or output field, or rejecting input that
  was accepted
- Changing or removing an MCP error `kind` or `code`
- Removing a tool from the default catalog or from a startup opt-in

Additive, allowed in a patch release: new commands, new flags with defaults,
new fields in JSON output, new error kinds for previously unclassified
failures, and new MCP tools, resources, prompts, optional inputs, and output
fields. Ordering results the contract left unordered, or bounding a read that
failed a documented cap, is a fix, not a break.

0.2 breaks two things under this list. The state commands default to
`--source custom` instead of the whole space, and the `diff` report gains an
`exceptions` block whose presence narrows what `clean` asserts. Both are named
in the changelog beside the flag that restores the previous behavior. The
mirror layout also grows a directory, but an 0.1 mirror still round-trips: a
tree with no `exceptions/` describes a corpus with no exception lists, which is
what it was.

### 11.2 Publishing

One shared workspace version, so all four published crates move together.

Publish to crates.io only through `.github/workflows/publish-crates.yml` on
GitHub Actions. Local publishing is not a fallback. Dispatch the workflow with
the released tag after the owner approves publishing that version; its
`crates-io` environment approval remains required.

An approved publication submits all four crates (`elasticctl-core`,
`elasticctl-api`, `elasticctl-mcp`, and `elasticctl`) through one
`cargo publish --workspace --locked --registry crates-io` command. Cargo
packages and verifies every selected crate against a temporary registry before
uploading dependency-ready crates. Uploads are not atomic: registry rejection
or a connection failure can leave a partial version set. A version can be
yanked, never deleted. `xtask` stays `publish = false` and ships nothing.
The [Cargo implementation](https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/cargo/ops/registry/publish.rs#L150-L251)
separates verification from the per-crate upload loop.

The normal workflow runs `scripts/check-crates-io-publish-ready.sh` in both
jobs before token exchange or upload. It requires all four names to exist on
crates.io with `dannyota` as an owner. Missing names, wrong ownership, and
failed public registry reads stop the workflow. This does not verify Trusted
Publisher settings. Before each dispatch, the owner checks every crate's
publisher entry and the `crates-io` environment's required-reviewer rule.

[Trusted Publishing](https://crates.io/docs/trusted-publishing) requires an
existing crate. The first `elasticctl-mcp` publication therefore needs a
separate owner decision that resolves the current Actions-only,
workspace-only, Trusted-Publishing-only policy. No bootstrap or token fallback
is authorized here. This publication block does not block implementation,
nonpublishing preflight, or the tag and GitHub Release. A dry run verifies
packages; it does not prove registry authorization for a later upload.

`elasticctl-api-test-support` remains private and unpublished. The published
`elasticctl-core`, `elasticctl-api`, `elasticctl-mcp`, and `elasticctl`
manifests exclude `tests/**`, because Cargo
cannot resolve those integration tests after it omits their path-only private
dev-dependency from the package. Inline unit tests under `src/` remain in the
archives. `scripts/check-packages.sh` runs the locked, allow-dirty
`cargo package --package <name> --list` check separately for all four crates.
It rejects every `tests/` entry and every `elasticctl-api-test-support` path,
and requires `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, plus `src/lib.rs`
for each library or `src/main.rs` for the CLI crate. It also checks that all
four package versions and all three library dependency versions match the
workspace version. Cargo's package list is
the archive-content authority for this release gate.

Publishing was deferred through 0.1.2 because a crates.io version is forever
while a tag costs nothing. Publishing `elasticctl-core` and `elasticctl-api`
would also make their Rust APIs a contract while those boundaries still moved.
0.1.3 claimed the three names and proved the path.

**Publishing is not part of a release.** A release ends at the tag and the
GitHub Release binaries. Putting a version on crates.io is a separate step
needing the owner's explicit approval for that version, and approval never
carries forward from a previous one. The reason is the asymmetry rather than
any doubt about the crates: a withheld version can still be published
tomorrow, while a published one can only be yanked — hidden from resolution,
never removed. Where one direction is recoverable and the other is not, the
default belongs on the recoverable side and the irreversible step is taken
deliberately, per version.

The original deferral is nonetheless dropped, because its central cost is
already accounted for.
Under Cargo's `0.x` rules, the minor position is the breaking position, so
`0.1.x` → `0.2.0` is a break a consumer must opt into. Section 11 already
bumps the minor for every new capability area. The crate boundaries can move as
much after publishing as before.

Name ownership does not reverse. All three names were unclaimed, and anyone can
claim a name until it is taken. That cost cannot be recovered, unlike a bad
version, which can still be yanked.

Publishing runs *after* the tag, because it is the only irreversible step in a
release. A tag and a GitHub Release can be deleted; a crates.io version can
only be yanked, and yanking hides a version from resolution rather than
removing it. Tagging first has the binary matrix prove the build while both the
tag and the Release are still disposable, which is the check a release
candidate used to buy separately.

Normal publication always selects the whole workspace. The binary crate
depends on all three libraries by version; publishing it alone can leave
`cargo install elasticctl` unable to resolve them.

