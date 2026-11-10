# Documentation

Each fact has one home. Link to that home instead of repeating it. [AGENTS.md](../AGENTS.md#map) routes readers to current authorities, and [docs/README.md](../docs/README.md) indexes `docs/`.

## Placement

|Content|Home|
|-|-|
|Project summary, install, quick start, coverage, and links|[README.md](../README.md)|
|User guides for the CLI and MCP server|[docs/wiki/](../docs/wiki/Home.md), published to the GitHub wiki|
|Scope, architecture, contracts, and verified API behavior|[docs/specs/](../docs/specs/elasticctl-design.md)|
|Release work plans and research|[docs/plans/](../docs/plans/)|
|Live conformance evidence and release reviews|[docs/conformance/](../docs/conformance/) and [docs/reviews/](../docs/reviews/)|
|Changes by version|[CHANGELOG.md](../CHANGELOG.md) and [docs/changelog/](../docs/changelog/)|
|Contributor setup, gates, and review rules|[CONTRIBUTING.md](../CONTRIBUTING.md)|
|Vulnerability reporting|[SECURITY.md](../SECURITY.md)|
|Release procedure|[docs/releasing.md](../docs/releasing.md)|
|Environment variables|[.env.example](../.env.example)|
|Shared agent work rules|The relevant file in `instructions/`|

The README stays short: it links each capability area to its wiki page instead of repeating the page. Command details, flags, and examples belong in the wiki; reasoning and measured API behavior belong in the specs.

## Writing rules

- Lead with the answer or purpose. Use plain, exact words, active voice, consistent terms, and short paragraphs. Name the command, flag, file, or value instead of "it" or "some".
- Use bullets for parallel items, numbered steps for ordered work, tables for comparisons, and prose for connected reasoning. No em dashes, filler, or closing recaps.
- Facts must match the code, the specs, and `--help`. Document behavior when its code lands; never describe designed but unbuilt features as available.
- Living docs (README, wiki, `docs/README.md`) describe the current state without dates, status history, "now", or "no longer". Versioned facts go in `CHANGELOG.md`.
- Never cite plans, tasks, review findings, or their ids in the README, the wiki, code, comments, or tests. Cite a spec section or state the rule. Human docs never mention AI or agents as authors.
- Examples run `elkctl` and use the placeholders in `.env.example` and the README. Never use real hostnames, deployment ids, account data, or credentials.
- Agent-only files (`AGENTS.md`, `CLAUDE.md`, `instructions/`) use one line per paragraph or list item and unpadded tables in text you write or rewrite. Human docs wrap at 80 columns; tables and URLs may run longer.
- Every Markdown file stays at or under 400 lines. [File size and splits](rust.md) sets the gate and the split rules.

## Public surface and wiki

A change to a public CLI or MCP surface (a command, flag, default, output field, error, tool, tool input, or limit) updates the matching `docs/wiki/` page in the same change. Fix any disagreement between the code and the wiki in that change.

A new wiki page is listed in `docs/wiki/_Sidebar.md` and `docs/wiki/Home.md`, and a new capability area also gets a row in the README "Coverage" table.

`scripts/wiki-sync.sh` publishes `docs/wiki/` to the GitHub wiki; the wiki is a mirror, so edits made in its web UI are overwritten. Run `bash scripts/wiki-sync.sh --dry-run` after editing a page: it rejects relative links that leave `docs/wiki/` and links to missing pages. The `Wiki` workflow runs the same preview on a pull request and publishes on a push to `master`.

## Links

- Between wiki pages, link `Page-Name.md`, with `#anchor` when needed. The links work in the repository, and the sync script strips `.md` for the published wiki.
- From a wiki page to a repository file, use an absolute `https://github.com/dannyota/elasticctl/blob/master/<path>` URL. A relative path out of `docs/wiki/` fails the sync.
- From the README to the wiki, use reference-style links to `https://github.com/dannyota/elasticctl/wiki/<Page-Name>`, defined at the bottom of the README.
- Elsewhere, use relative links. Check every link and heading anchor after a rename or move.
