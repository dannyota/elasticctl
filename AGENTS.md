<!-- Keep under 120 lines. Hold only rules every task needs; topic rules live in instructions/. Include only rules easy to violate, not facts derivable from code or the spec. -->

# elasticctl

Rust CLI and MCP server for operating Elastic Security detection rules as code across
self-managed, Elastic Cloud Hosted, and Serverless deployments. Its sibling,
[splunkctl](https://github.com/dannyota/splunkctl), is the reference for operating contracts.
**The repository, fixtures, conformance reports, and CI logs are public.**

## Scope and authority

Guidance precedence is: the user's current instruction, the spec, then this file and
`instructions/`. `CLAUDE.md` only imports this file. Durable contributor rules belong in
`CONTRIBUTING.md` or the spec.

**Read `docs/specs/elasticctl-design.md` before changing anything.** It defines scope,
architecture, and verified API behavior. When code and spec disagree, the spec wins. Update the
spec first and in the same commit as any behavior change.

## Map

|Question|Entry point|
|-|-|
|What is in scope, and how does the API behave?|`docs/specs/elasticctl-design.md`|
|What does a capability area add?|`docs/specs/elasticctl-*-design.md`|
|What was planned and proven per release?|`docs/plans/`, `docs/conformance/`, `docs/reviews/`|
|What changed?|`CHANGELOG.md`|
|How do I set up, test, and contribute?|`CONTRIBUTING.md`|
|Which environment variables exist?|`.env.example`|

|Doing|Read first|
|-|-|
|Planning, briefing, implementing, or reviewing|[`instructions/workflow.md`](instructions/workflow.md)|
|Writing or splitting Rust and Markdown|[`instructions/rust.md`](instructions/rust.md)|
|Running tests, recording fixtures, or using sample data|[`instructions/testing.md`](instructions/testing.md)|
|Touching live stacks, `.env`, credentials, or the lab|[`instructions/live-stacks.md`](instructions/live-stacks.md)|
|Changing transport, an API call, or the response model|[`instructions/elastic-api.md`](instructions/elastic-api.md)|
|Cutting or publishing a release|[`instructions/releases.md`](instructions/releases.md), then `docs/releasing.md`|

## Architecture rules

Dependency direction is one way; API/core never depend on a frontend:
```
elasticctl-cli  →  elasticctl-mcp  →  elasticctl-api  →  elasticctl-core
```
CLI also calls API directly; both frontends may use core.
`-mcp` owns stdio, schemas, projections, and call limits; it never uses CLI rendering.
`-core` owns config, transport, auth, and errors; `-api` owns the model and the
rules/exceptions/state orchestration; `-cli` owns `clap` parsing, `render`, and the dry-run guard.
- **API orchestration returns typed values.** CLI adapters handle command context and mutation
  guards, then serialize values for `elasticctl-cli::render`. MCP calls the same API functions
  and projects their typed data. A command that prints gives MCP only a string to re-parse.
- **Orchestration belongs in `-api`.** `cli/cmd/` adapters must not own stack orchestration; MCP
  cannot depend on `-cli`. Moving orchestration must preserve byte-identical output, proven by
  snapshots.
- **`clap` types never appear in `-mcp`, `-api`, or `-core`.** Pass a value, not a parsed arg struct.
- Flavor differences use the runtime capability probe, not compile-time traits or per-flavor
  modules.
- `xtask` may depend on `-mcp`, `-api`, and `-core`, never on the CLI crate. It is the dev-tool
  crate (`publish = false`) and ships nothing.

## Safety contracts

- Every remote mutation is a dry run by default. `--yes` applies. Both preview and apply print
  profile, host, and space.
- **`state push` never deletes remote rules or exception list containers.** A missing local rule
  is not a delete instruction. Delete them only through `rules delete` or `exceptions delete`.
  From 0.2, exception *items* inside a mirrored container reconcile exactly, including deletes,
  because a container's item set is always written in full. Spec 5.4 gives the reasoning.
- State rule identity is **always `rule_id`**, never display name or volatile saved-object `id`.
  Exception list identity is **always `list_id` plus `namespace_type`**. Pull strips a rule's
  `exceptions_list[].id`; push re-resolves it. Spec 4.5.
- Never put credentials in URLs. Debug logs complete URLs, but exclude authorization headers and
  bodies.
- Never print, commit, or copy `.env` values. See [live stacks](instructions/live-stacks.md).

## Git and GitHub

- Run `gh` and `git push` as `dannyota`: prefix them with `GH_TOKEN=$(gh auth token -u dannyota)`.
  This machine's active `gh` account may be a different one. Never run `gh auth switch`.
- Commit or push only when asked, and branch from `master` first.
- Commits are signed with the configured identity. Use Conventional Commits (`fix(deps): ...`,
  `docs(spec): ...`, `ci: ...`, `chore: release X.Y.Z`); history before 2026-11-09 uses plain
  imperative subjects. No `Co-Authored-By` or "Generated with" trailers, and no mention of
  agents or AI.
- Track `AGENTS.md`, its one-line `CLAUDE.md` import, and `instructions/`. The `.gitignore`
  negations override the global ignore default for the first two.
