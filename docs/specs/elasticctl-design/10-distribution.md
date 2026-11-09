[Back to elasticctl-design](../elasticctl-design.md)

## 10. Distribution

`cargo-dist` produces GitHub Releases for Linux gnu and musl (x86_64,
aarch64), macOS (x86_64, aarch64), and Windows x86_64, plus
`cargo install elasticctl`. Static musl supports locked-down Linux laptops.
macOS aarch64 is likely the common case. Add a Homebrew tap when there is demand.

The package builds two binaries from the same `src/main.rs` entrypoint:
`elasticctl`, the canonical name, and `elkctl`, a shorter alias. Both ship in
every archive and both install from `cargo install elasticctl`. Because they
compile from one entrypoint, the two surfaces cannot drift; the `commands`
JSON output is byte-identical between them. Help text and shell completions
follow whichever name invoked the process — `elkctl --help` and
`elkctl completion zsh` both name `elkctl`, never `elasticctl` — derived from
`argv[0]` at runtime, not from a compiled-in literal. `elasticctl` remains the
canonical name for the package, the crates, artifact names, error text, and
the `commands` JSON's own `name` field, which stays `"elasticctl"` regardless
of invocation so that field stays part of the byte-identical surface.
User-facing documentation and its command examples lead with `elkctl`.
`--version` follows the same
rule as that `name` field, not the help/completions rule: both binaries print
`elasticctl <version>`, the canonical name, regardless of which one was
invoked — only help usage text and completions follow `argv[0]`. Sharing one
entrypoint across two `[[bin]]` targets has a known, harmless build-time cost:
`cargo build`/`cargo install` print a "file present in multiple build
targets" notice for `src/main.rs`. It is a manifest-level Cargo notice, not a
lint — `cargo clippy -D warnings` does not see it and there is no way to
suppress it short of duplicating the entrypoint file.

