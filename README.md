# elasticctl

[![CI](https://github.com/dannyota/elasticctl/actions/workflows/ci.yml/badge.svg)](https://github.com/dannyota/elasticctl/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dannyota/elasticctl/actions/workflows/codeql.yml/badge.svg)](https://github.com/dannyota/elasticctl/actions/workflows/codeql.yml)
[![crates.io](https://img.shields.io/crates/v/elasticctl)](https://crates.io/crates/elasticctl)
[![Release](https://img.shields.io/github/v/release/dannyota/elasticctl)](https://github.com/dannyota/elasticctl/releases)
[![License](https://img.shields.io/github/license/dannyota/elasticctl)](LICENSE)

A safety-first command-line tool and Model Context Protocol (MCP) server for
operating Elastic Security as code on self-managed stacks, Elastic Cloud Hosted
deployments, and Elastic Cloud Serverless projects. Keep detection rules and
exception lists in Git, triage alerts and cases, move data views, dashboards,
and Fleet policies between stacks, and query Elasticsearch. It is a sibling to
[splunkctl](https://github.com/dannyota/splunkctl) and shares its operating
contracts: dry-run-by-default changes, named profiles, stable output, and typed
errors.

This is a personal, unofficial project, not affiliated with or endorsed by
Elastic. Expect breaking changes in minor releases until `1.0.0`.

Examples run `elkctl`, a short alias for the same binary as `elasticctl`.
Every install method puts both names on `PATH`. The project, the crate on
crates.io, and the GitHub repository stay named `elasticctl`.

## Install

From crates.io, with the stable Rust toolchain:

```bash
cargo install elasticctl
```

This installs both binaries. Not every release reaches crates.io, so this can
be a version behind. GitHub Releases always carry the newest version.

Or use a prebuilt binary. Each
[release](https://github.com/dannyota/elasticctl/releases/latest) ships
archives for Linux (glibc and musl), macOS (Intel and Apple Silicon), and
Windows, each containing both binaries. The installer scripts put them on
`PATH`:

```bash
# macOS and Linux
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/dannyota/elasticctl/releases/latest/download/elasticctl-installer.sh \
  | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/dannyota/elasticctl/releases/latest/download/elasticctl-installer.ps1 | iex"
```

## Quick start

Create a profile from `ELASTICCTL_*` environment variables;
[`.env.example`](.env.example) documents them. Use an Elasticsearch API key
created inside Kibana, scoped to the project or deployment. An
organization-level Cloud key is not supported: Hosted refuses it, and MCP
planning refuses it on every flavor, though Serverless 9.7.0 accepts it for
CLI rule changes.

```bash
export ELASTICCTL_KIBANA_URL=https://YOUR-PROJECT.kb.YOUR-REGION.aws.elastic.cloud
export ELASTICCTL_API_KEY=...
elkctl config init --from-env
elkctl doctor   # checks reachability, key scope, and rule access
```

Keep rules in a directory and review drift before pushing:

```bash
elkctl state pull --dir state   # writes state/rules/ and state/exceptions/
# edit rules, or add new ones
elkctl state diff --dir state   # field-level drift, no changes made
elkctl state push --dir state   # preview only
elkctl state push --dir state --yes
```

Every remote change previews first and applies only with `--yes`. `state push`
never deletes a remote rule or exception list. See [Getting Started][start]
and [Rules as Code][state].

## Coverage

| Area | Supports | Guide |
| --- | --- | --- |
| Rules as code | Pull, diff, and push rules and their exception lists, with change-evidence reports | [Rules as Code][state] |
| Rules | List, get, validate, enable, disable, delete, export, import, preview; prebuilt status and install | [Rules][rules] |
| Exceptions | List, get, validate, export, import, and delete exception lists with their items | [Exceptions][exceptions] |
| Search | ES\|QL and Query DSL peeks and full exports | [Search][search] |
| Alerts and cases | Alert status, tags, and assignees; case create, comment, attach, close, reopen, delete | [Alerts and Cases][triage] |
| Data views and dashboards | Portable files, the default data view, reference-safe delete, Saved Objects bundles | [Data Views and Dashboards][content] |
| Fleet | Agent and integration policies as portable files | [Fleet][fleet] |
| MCP | Twenty-four read-only tools, among them the task tools `alert_context`, `rule_health`, `detection_coverage`, and `rule_readiness`; two opt-in query tools; opt-in rule enable and disable through stored plans a person confirms | [MCP][mcp], [MCP Mutations][mcp-mutations] |
| Stack | Profiles, `doctor`, and `info` | [Configuration][config] |

## MCP server

`elkctl mcp serve` serves read-only tools over stdio for one profile and space
chosen at startup:

```bash
elkctl --profile analyst --space default mcp serve
```

The default catalog has twenty-four tools. Four task tools answer questions
that span several objects: `alert_context` triages one alert, `rule_health`
checks whether a rule runs and alerts, `detection_coverage` counts rules by
MITRE ATT&CK technique, tactic, index pattern, or integration, and
`rule_readiness` checks whether a rule has data and integrations. Twenty
inspection tools read stack diagnostics, rules, exception lists, alerts,
cases, data views, dashboards, and Fleet policies; `rules_list` also filters
by ATT&CK `technique` or `tactic`. `--allow-query-tools` adds synchronous
ES|QL and Query DSL tools. By default no tool changes the stack, and no tool
selects local files or changes the target. See [MCP][mcp] for the client
stanza, limits, and tested clients.

`--allow-mutations rules-toggle` adds tools that enable or disable named rules.
A planner tool reads the stack and stores a plan; `plan_apply` takes only the
plan id and asks the person at the client to confirm it in a form. No tool
argument confirms a change, and a client without form elicitation cannot
apply: the plan names the CLI command to run instead. The profile needs
`es_url`. A rule without an API key that is enabled this way then runs with the
server's credential; a rule that has a key keeps it.
See [MCP Mutations][mcp-mutations] for the flow, the audit trail, and the
limits of this consent model.

The server also offers five resources, four resource templates, and four
prompts. Their lists are fixed: listing them sends no Elastic request and
needs no credential. Reading a resource such as `elasticctl://stack/info` runs
one read-only tool with fixed arguments and returns that tool's JSON, under the
same call limit and `--timeout`. A prompt such as `triage_alert` reads nothing;
it returns fixed text that asks the model to call one task tool. In Claude
Code, with the server registered as `elasticctl`, type `@` to pick a resource
or write `@elasticctl:elasticctl://stack/info`, and type `/` to run a prompt
such as `/mcp__elasticctl__triage_alert <alert_id>`. See Claude Code's
[resources][cc-resources] and [prompts][cc-prompts] pages, and
[MCP][mcp-resources] for the full lists.

## Scripts and AI agents

- **Stable output:** a table by default, in a terminal and in a script alike.
  `--json` or `--format json|yaml|csv|jsonl` for machine output, and
  `--fields` to keep only named fields.
- **Typed errors:** a failure prints one JSON object on stderr with a stable
  `kind`, such as `permission` or `not_found`.
- **Exit codes:** `0` success, `1` error, `2` usage error.
- **Dry run by default:** every remote change previews and names the profile,
  host, and space; `--yes` applies it.
- **Named profiles:** keep development, UAT, and production stacks apart.
- **Discovery:** `elkctl commands` prints the command tree as JSON.

```bash
elkctl --profile uat rules list --source custom --json
```

See the [CLI reference][cli] for output, errors, and selectors, and
[Security][security] for credential handling and the dry-run guard.

## Documentation

- [Getting Started][start]: install, create a profile, first commands.
- [Configuration][config]: profiles, environment variables, spaces, API keys.
- [CLI reference][cli]: command tree, output formats, errors, exit codes.
- Guides: [Rules as Code][state], [Rules][rules], [Exceptions][exceptions],
  [Search][search], [Alerts and Cases][triage],
  [Data Views and Dashboards][content], [Fleet][fleet], [MCP][mcp],
  [MCP Mutations][mcp-mutations].
- [Security][security]: the dry-run guard, credentials, and MCP reach.
- [Limitations][limitations]: Elastic behaviors the tool works around.
- [Changelog](CHANGELOG.md): changes by version.
- [Design](docs/specs/elasticctl-design.md): scope, architecture, and measured
  API behavior.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks a pull request
must pass, and the rules review holds changes to. Report security problems
privately through [SECURITY.md](SECURITY.md). Maintainers cut releases with
[docs/releasing.md](docs/releasing.md).

Licensed under [Apache 2.0](LICENSE).

[start]: https://github.com/dannyota/elasticctl/wiki/Getting-Started
[config]: https://github.com/dannyota/elasticctl/wiki/Configuration
[cli]: https://github.com/dannyota/elasticctl/wiki/CLI
[state]: https://github.com/dannyota/elasticctl/wiki/Rules-as-Code
[rules]: https://github.com/dannyota/elasticctl/wiki/Rules
[exceptions]: https://github.com/dannyota/elasticctl/wiki/Exceptions
[search]: https://github.com/dannyota/elasticctl/wiki/Search
[triage]: https://github.com/dannyota/elasticctl/wiki/Alerts-and-Cases
[content]: https://github.com/dannyota/elasticctl/wiki/Data-Views-and-Dashboards
[fleet]: https://github.com/dannyota/elasticctl/wiki/Fleet
[mcp]: https://github.com/dannyota/elasticctl/wiki/MCP
[mcp-resources]: https://github.com/dannyota/elasticctl/wiki/MCP#resources-and-prompts
[mcp-mutations]: https://github.com/dannyota/elasticctl/wiki/MCP-Mutations
[cc-resources]: https://code.claude.com/docs/en/mcp#use-mcp-resources
[cc-prompts]: https://code.claude.com/docs/en/mcp#use-mcp-prompts-as-commands
[security]: https://github.com/dannyota/elasticctl/wiki/Security
[limitations]: https://github.com/dannyota/elasticctl/wiki/Limitations
