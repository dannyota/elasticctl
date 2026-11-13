# File size and splits

`scripts/check-lengths.sh` caps Rust at 700 non-test lines and Markdown at 400
lines. Rust files under any `tests/` directory are exempt. Exclude a top-level
`#[cfg(test)]` directly followed by `mod <name> {` (including public modules),
through the next closing line starting with `}` at column 0. Count code before
and after each module; empty `{}` modules end on their opening line. Markdown under `docs/plans/`, `docs/conformance/`, and
`docs/reviews/` is historical evidence and is never edited.

`scripts/lengths-baseline.txt` caps existing oversized files at their measured
counts exactly. Do not add entries or raise caps. Lower a cap when its file shrinks;
remove the entry when the file reaches the limit. Missing or untracked paths
must be removed. `--base-ref <ref>` rejects entries absent from that ref and caps
above that ref's caps. A ref without a baseline (the change that introduces
the gate) skips the comparison.

The gate is a lexical check, not a parser: text that only looks like a test
module, such as one inside a raw string, can hide code from it. Review rejects
any change that games the count.

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

Design docs, not comments, hold decisions and explanations. Comments drift from
the code and mislead readers.

- Write no comments in code, scripts, or workflows, except tool directives
  (`# shellcheck`, the `# vX.Y.Z` pin after an action SHA, generated-code
  markers) and one line on why for a Kibana, Elasticsearch, or other external
  behaviour that no design doc owns. That line names its source: an Elastic
  docs page or a recorded fixture.
- No doc comments that only repeat a name, and no comments that restate the
  code or a design doc. Delete such comments in code you touch.
- Use plain words. Do not use em dashes, plan or task IDs, or history wording
  such as "now" or "no longer".
