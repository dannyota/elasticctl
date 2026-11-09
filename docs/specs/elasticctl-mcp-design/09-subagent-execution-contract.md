[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 9. Subagent execution contract

Use the three plans: [0.7.0](../../plans/v0.7.0.md),
[0.7.1](../../plans/v0.7.1.md), and [0.7.2](../../plans/v0.7.2.md).
The primary agent owns coordination, spec changes, reviewed integration,
verification, Git, and release operations.

Set the model explicitly on each dispatch: `gpt-5.6-sol` for design and every
independent review, `gpt-5.6-terra` for implementation, and `gpt-5.6-luna` for
searches or mechanical edits. A designer or reviewer must not
implement the same slice. Each editing worker gets a separate worktree,
fixed paths, one directive, exact interfaces, forbidden actions, and checks.
Read-only research and reviews can run in parallel. Implementation uses a
fresh worker per task with review before dependent work; do not overlap
shared catalog, manifest, lockfile, or test-support ownership.

The execution ledger records task commits, tests, review verdicts, and design
rulings. Each task needs both spec-compliance and quality approval. A separate
whole-branch review covers the integrated credential, routing, and packaging
boundaries. The primary inspects worker diffs and runs required checks before
accepting them. Local builds use two jobs, tests use four threads, and only
one build-heavy process runs at a time.
