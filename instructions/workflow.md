# Workflow

## Roles and review

Design first: the brief is its product. The primary session, the one the owner talks to, designs:
it writes the architecture notes, specs, plans, and documentation, reviews them itself, and makes
the decisions. It also writes briefs, reruns every check itself, commits (signed), pushes, opens
the pull request, and merges only after CI is green and the reviewer's verdict is MERGE or its
findings are fixed. No Codex designer runs by default.

|Role|Who|Duty|
|-|-|-|
|Primary|The session the owner talks to|Designs, writes documentation, decides, verifies, owns Git and releases|
|Astra|Codex `--model gpt-6-astra --effort high`, no `--write` (read-only)|Independently reviews every architecture design and every code diff|
|Implementer|Codex Sol (`--model gpt-6.1-sol --effort high --write`) or a Claude subagent|Implements and writes the tests, troubleshoots, and runs QA; never commits|

Documentation and prose the primary wrote need no independent review. An architecture or
contract design and all code get an independent Astra review before merge. Without Codex, keep
the same separation with available models: an agent assigned review must not implement the same
slice, each brief says so, and no model reviews its own work. Mutation paths, credential
handling, and release workflows always get an independent adversarial review.

Plans live in tracked `docs/plans/vX.Y.Z.md` files that the spec links. Mark a step done only
with its evidence.

## Codex jobs

`C=~/.claude/plugins/cache/openai-codex/codex/<version>/scripts/codex-companion.mjs`

- Start: `node $C task --background [--write] --model <m> --effort high -C <worktree> --prompt-file <file>`.
- Run `status <id>`, `result <id>`, and `cancel <id>` from the directory passed to `-C`;
  elsewhere they print "No job found".
- To wait, poll only the job line `- <id> | <state> | ...` with `awk -F' [|] ' '{print $2}'`.
  Stop on any state other than running or queued, and on empty output. Never grep the whole
  output for "completed": progress lines contain "Command completed".
- The Codex sandbox cannot write outside its worktree and may have no network. Rerun anything
  that needs the network, a live stack, or another toolchain yourself.

## Flow

1. One worktree per task under `.worktrees/` (git-ignored). The implementer runs there.
2. Design: the primary writes the goal, the constraints (contracts and what must not change),
   and file:line for every hook. An architecture or contract design goes to Astra for review
   before implementation; small changes skip the design review.
3. Implementer brief: the design plus numbered decisions where it was open ("decision wins over
   design"), test requirements, "run the full gate set", "report files changed, results, and
   deviations", and "Do NOT commit".
4. Verify yourself: run the full gates, read the risky parts of the diff, then commit.
5. Astra review brief: the commit SHA, the design and its decisions, bugs already known, and a
   checklist that includes regressions in existing behavior. Ask for file:line, severity, a
   failure scenario, a fix, and a MERGE, MERGE-WITH-FIXES, or BLOCK verdict. A change that is
   only documentation or prose skips this step.
6. Paste the findings verbatim into a new implementer brief and repeat from step 4 until MERGE.
7. If new facts arrive while an implementer runs, cancel it and start a new job with the full
   brief, telling it to review its own uncommitted partial changes.

Tests drive the real library code paths with only the network faked, and every mock copies a
real recorded response ([testing](testing.md)). Mocks pass reviews that a live server fails, so
verify against a live stack before a release.

## Parallel work

Parallel tasks need fixed interfaces, named files with no overlapping ownership, and a separate
git worktree for each worker that edits files. A slice needing a test alongside another's creates
a new file instead of editing a shared one. Assign one directive per agent; do not add work to a
running agent because it owns the files. Review each task before dependent work starts.

## Pull requests and CI

- Every change lands through a pull request with green CI. A pull request that is red only
  because `master` is red waits for the `master` fix, then rebases.
- A red scheduled run on `master` is fixed forward at once. The weekly `audit` job catches new
  RustSec advisories against an unchanged tree, which means the shipped release carries them.
  Check `gh run list --branch master --limit 3` when a session starts work.
- Dependabot runs alerts only: no version or security-update pull requests, so it never uses
  Actions runners. Check `gh api repos/dannyota/elasticctl/dependabot/alerts?state=open` and
  the weekly `audit` job, then update dependencies in our own pull request.
- Pin every action by full commit SHA with a `# vX.Y.Z` comment; the repository requires it.
  Bump pins by hand in our own pull request.
