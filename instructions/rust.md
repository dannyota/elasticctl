# File size and splits

`scripts/check-lengths.sh` caps Rust at 700 non-test lines and Markdown at 400
lines. Rust files under any `tests/` directory and files named `tests.rs` are
exempt. A Rust file counts only lines before the first `#[cfg(test)]` whose
next line opens an inline module. Markdown under `docs/plans/`,
`docs/conformance/`, and `docs/reviews/` is historical evidence and is never
edited. Generated files are exempt only when one of their first five lines
contains `@generated`, or both `Code generated` and `DO NOT EDIT`.

`scripts/lengths-baseline.txt` caps existing oversized files at their measured
counts. Do not add entries or raise caps. Lower a cap when its file shrinks;
remove the entry when the file reaches the limit. Missing or untracked paths
must be removed.

These limits are final; do not ratchet them lower. Clear the baseline instead:
split one listed file below its limit per PR, by concern, and remove its entry
in the same PR.

## Rust splits

Split by concern, not by line count. Move code unchanged into sibling modules
named after the concern. Change no public API, error text, ordering, locks, or
timeouts. Reviewers check that every item appears exactly once with identical
tokens.

## Markdown splits

Keep the parent as a short index. Move whole sections verbatim to linked
sibling pages. Keep every cited anchor resolvable, including links into the
parent page.

## Comments

Use plain words. Do not use em dashes, plan or task IDs, or history wording
such as "now" or "no longer".
