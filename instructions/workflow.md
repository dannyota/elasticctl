# Workflow

## Roles and review

Design first: the brief is its product. Follow any user-wide model assignments for the current
provider; otherwise choose available models by the roles below. Set each dispatch's model
explicitly.

- Assign design and complex analysis to the planning role, routine implementation to the
  implementation role, and transcription or single-file mechanical fixes to the support role.
- Mutation paths, credential handling, and release workflows need independent adversarial
  review. Ordinary code needs its tests, the gates, and independent code review.
- Agents assigned design or review must not implement the same slice; state that restriction in
  each brief.

Plans live in tracked `docs/plans/vX.Y.Z.md` files that the spec links. Mark a step done only
with its evidence.

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
- Dependabot opens one grouped pull request per ecosystem each week. Merge it when green; when a
  dependency change breaks the build, fix it on that branch.
- Pin every third-party action by full commit SHA with a `# vX.Y.Z` comment. Dependabot keeps
  the pins current.
