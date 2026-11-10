# Documentation

Each fact lives in one place. Link to it instead of copying it.

| Path | Holds | Lifecycle |
| --- | --- | --- |
| [`wiki/`](wiki/Home.md) | User guides for the CLI and MCP server, published to the [GitHub wiki](https://github.com/dannyota/elasticctl/wiki) | Updated in the same change as the public surface it describes |
| [`specs/`](specs/elasticctl-design.md) | Scope, architecture, contracts, verified API behavior, and one design per capability area | Updated first, in the same commit as any behavior change |
| [`plans/`](plans/) | Work plan and research for each release | Steps are marked done with their evidence; kept after release |
| [`conformance/`](conformance/) | Scrubbed live conformance reports and findings for each release | Release evidence; never edited |
| [`reviews/`](reviews/) | Release review records | Release evidence; never edited |
| [`changelog/`](changelog/) | Changelog sections for older minor versions, linked from [`CHANGELOG.md`](../CHANGELOG.md) | Kept as released |
| [`releasing.md`](releasing.md) | Maintainer release and crates.io publishing procedure | Updated with the release process |

The specs define behavior; when code and spec disagree, the spec wins. When the
README or a wiki page disagrees with the code or a spec, fix it in the same
change.
