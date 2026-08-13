<!--
Maintainer notes: keep under 200 lines — this file loads every session. Only
rules that are easy to violate; nothing derivable from code or spec. When a
rule's owner changes (spec section, README runbook), re-sync its copy here in
the same change.
-->

# elasticctl

Rust CLI for operating Elastic Security detection rules as code, across
self-managed, Elastic Cloud Hosted, and Serverless deployments. Sibling to
[splunkctl](https://github.com/dannyota/splunkctl), which is the reference for
operating contracts.

**Read `docs/specs/elasticctl-design.md` before changing anything.** It is the
source of truth for scope, architecture, and verified API behaviour. When code
and spec disagree, the spec wins, and the fix lands in the spec first — never
silently improve. Docs are the contract: a change that alters behaviour
updates the spec in the same commit, and a change that closes a backlog item
removes it from the current backlog. Precedence when guidance
conflicts: the user's current instruction, then the spec, then this file.

| Task | Read first |
| --- | --- |
| Any behaviour change | `docs/specs/elasticctl-design.md` |
| What to work on next | the newest `docs/plans/*-backlog.md`, else the newest plan |
| Releasing | `README.md` "Releasing" |
| Re-recording fixtures | "Testing" and "Sample data" below, `xtask/src/main.rs` |

## Development workflow

Design first: the brief is the product of the design. Design runs on Opus;
implementation runs on Sonnet; pure transcription and single-file mechanical
fixes on Haiku. Review tier scales with the cost of being wrong:
invariant-bearing work — mutation paths, credential handling, release
workflows — gets adversarial review on Opus; ordinary code gets its tests,
the gates, and a Sonnet review. A well-split task never needs a stronger
model — if a task seems to, the split is wrong, not the tier. When unsure,
dispatch Sonnet and escalate on its report. Set the model explicitly on
every dispatch — omitted, it silently inherits the session's tier. Opus
agents decide, split, and review; they never implement — every dispatch to
one states this restriction in the brief itself, never left to inference.

Parallelism is earned by the design, not the deadline: when the plan pins
each task's files and interfaces, tasks that share no files can run as
parallel implementers. Agents own named files, never directories — a slice
needing a test alongside another's creates a new file rather than editing a
shared one. One directive, one agent: never fold new work into a running
agent just because it owns the files. Every task is reviewed before the next
builds on it.

## Architecture rules

Dependency direction is strictly one way and must not be broken:

```
elasticctl-cli  →  elasticctl-api  →  elasticctl-core
```

- **Command functions return typed values. They never print.** Rendering
  belongs to `elasticctl-cli::render`. This is what keeps a future MCP server
  additive — it will call the same functions and serialize the same structs. A
  command that prints gives MCP nothing but a string to re-parse.
- **`clap` types never appear in `-api` or `-core`.** If a command needs a
  value, pass the value, not the parsed arg struct.
- Flavor differences are handled at runtime through the capability probe, not
  by compile-time traits or per-flavor modules.
- `xtask` may depend on `-api` and `-core`, never on the CLI crate, and ships
  nothing — it is the dev-tool crate (`publish = false`).

## Safety contracts

- Every mutation is a dry run by default. `--yes` applies. Both the preview and
  the apply print a banner naming profile, host, and space.
- **`state push` never deletes remote rules.** A rule missing locally is not a
  delete instruction. Deletion is only ever the explicit `rules delete`.
- Rule identity for state matching is **always `rule_id`** — never the display
  name, never the volatile saved-object `id`.
- Secrets are redacted in all output, including `--debug` HTTP logs.

## Credentials

`.env` holds live credentials for whatever stack you develop against. It is
gitignored and mode `0600`; `.env.example` is the template to copy.

- Never commit it, never copy its contents into tracked files, never echo the
  key into terminal output or commit messages.
- `.env.example` is the committed template and must contain placeholders only.
- An **organization-level** Cloud API key is not enough. The `essu_` prefix
  does not imply project scope. Such a key reads fine and can create *disabled*
  rules, but **it cannot enable a rule** — the alerting framework refuses to
  mint a rule API key on behalf of an organization key. Enable, disable-apply,
  and `state push` need a **project-scoped Elasticsearch API key** created
  inside Kibana.
- `.env` defines `ELASTICCTL_API_KEY` (project-scoped — use this) and
  `ELASTICCTL_ORG_API_KEY`. A git worktree has no `.env`; source it from the
  main checkout rather than copying it.

## Elastic API gotchas

These cost real time if forgotten:

- `kbn-xsrf: true` is required on every non-GET Kibana request or it is
  rejected.
- `elastic-api-version: 2023-10-31` is required on versioned public APIs.
- **Two error envelope shapes exist.** The Cloud edge proxy returns
  `{"ok":false,"message":"Unknown resource."}`; Kibana returns
  `{"statusCode":...,"error":...,"message":...}`. The classifier must handle
  both. The edge shape also appears for a hostname that no longer resolves,
  which happens after a project rename.
- `rules/_export` ends with a `{"exported_count":N,...}` summary object. It is a
  trailer, not a rule. With zero rules it is the entire body.
- `_bulk_action` targets rules by the stable `rule_id` through the query form,
  `alert.attributes.params.ruleId: "<rule_id>"`, so no server-id lookup is
  needed. It also accepts `?dry_run=true` for a server-computed preview.
- Rule export includes volatile fields (`id`, `created_at`, `updated_at`,
  `updated_by`, `version`, `revision`, `execution_summary`). Normalize them
  away on `pull` or every diff reports fake drift.
- A real self-managed stack reports `version.build_flavor: "traditional"`, not
  `"default"`. Only `"serverless"` is matched exactly; everything else falls
  through to hostname detection.
- `rules/preview` returns `{preview_id, invocations, errors, warnings}` and
  **no hit count** — four hits and zero hits are byte-identical responses.
  Hits land in the preview alerts index and must be queried separately with
  the `preview_id`. The only in-band hit signal is the `max_signals` warning
  at 100+.
- Re-importing existing rules without overwrite is a per-rule 409 storm, not
  a skip: N "already exists" errors and exit 1.

## Testing

```bash
cargo test                                    # unit + fixture, offline, no stack needed
ELASTICCTL_LIVE=1 cargo test -- --ignored     # live suite against a real stack
cargo xtask record                            # re-record fixtures from a live stack
cargo fmt --all --check                       # the CI gate, alongside:
cargo clippy --workspace --all-targets -- -D warnings
```

Fixtures are recorded from real traffic, never hand-written, and are tagged
with flavor and stack version. Do not hand-edit a fixture to make a test pass —
re-record it.

Recording rules, because fixtures are public: scope every request to the probe
rule — an unscoped `_find` or `_export` writes real rule content into the repo —
and scrub identity (`username`, `full_name`, `email`, `created_by`,
`updated_by`) as well as credentials. The export fixture holds NDJSON as an
opaque string, so it needs its own scrub pass.

## Development target

Serverless is the primary target; nothing needs to run locally day to day. The
`lab/` podman stack is an on-demand session (~3 GB, ~20 minutes) used only to
record self-managed fixtures. Do not assume it is running.

`podman compose` works by delegating to `docker-compose`; `podman-compose` is
not installed. Kibana's entrypoint only maps `UPPER_SNAKE` env names — the
dotted `xpack.encryptedSavedObjects.encryptionKey` form is silently ignored,
and every rule creation then fails.

## Live testing against the dev project

The Serverless dev project holds ~2,066 Elastic prebuilt rules, seeded for
scale testing. They are read-only ground truth: never mutate an untagged
rule. Every object a live test creates carries the `elasticctl-sample`
marker — a `rule_id` prefix and tag for rules, `*elasticctl-sample*` in the
name for indices — every mutation targets explicit ids, and a run ends by
verifying the project is back to baseline: prebuilt rule count unchanged, no
sample rules, no sample indices.

## Sample data

Fetch, never vendor: third-party rule and event content stays out of this
public repo; scripts download it on demand. Verified licenses (2026-08-13):
SigmaHQ/sigma is DRL 1.1 — attribution and license notice required;
OTRF/Security-Datasets is MIT (its README's GPL-3.0 line is stale);
elastic/detection-rules is Elastic License v2 — never commit its content;
sbousseaden/EVTX-ATTACK-SAMPLES has no license — do not use it at all.

`sigma-cli` with `-t lucene -p ecs_windows -f siem_rule_ndjson` converts
Sigma rules straight to importable NDJSON. Mordor events use pre-ECS
winlogbeat field names (`EventID`, `CommandLine`, `Image`): remap to ECS and
rewrite `@timestamp` to now before ingest, or no rule will ever match.

## Release

The binary crate's package is named `elasticctl` (directory
`crates/elasticctl-cli`), so `--package elasticctl-cli` no longer resolves.
Publish with `cargo publish --workspace` (dry-run first): it packages and
verifies all three crates against a temp registry before uploading any. Never
publish crate-by-crate — a sequence that fails partway strands crates on
crates.io, where versions cannot be deleted, only yanked. cargo-dist installs
as `dist`; `cargo dist` does not resolve. `dist build --artifacts=host` builds
the host target only.

## Git

`CLAUDE.md` is tracked by the owner's decision, carried by the one existing
`.gitignore` negation. Never force-add, track, or add negations for any other
globally ignored file, and never extend that one.
