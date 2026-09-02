# elasticctl

**A safety-first CLI to operate Elastic Security as code.**

Examples in this document run `elkctl`, a short alias for the same binary as
`elasticctl`. Every install method below puts both names on `PATH`. The
project, the crate on crates.io, and the GitHub repository stay named
`elasticctl`.

`elasticctl` is a Rust CLI for managing Elastic Security detection rules as
code across self-managed stacks, Elastic Cloud Hosted deployments, and Elastic
Cloud Serverless projects. It is a sibling to
[splunkctl](https://github.com/dannyota/splunkctl) and shares its operating
contracts:

- **Remote mutations are dry runs by default.** Nothing is applied until you
  pass `--yes`, and every preview names the profile, host, and space it would
  touch.
- **Configuration as code.** Pull live rules, review structured drift, push
  approved changes with a change-evidence report. Push never deletes remote
  rules.
- **Stable machine output.** Table by default, `--json` on request, typed error
  envelopes on stderr.
- **Named profiles** for separate development, UAT, and production instances.

An MCP server is planned once the CLI surface is stable.

## Install

Install from crates.io or download a prebuilt binary.

### From crates.io

Requires the stable Rust toolchain.

```bash
cargo install elasticctl
```

This installs both the `elasticctl` and `elkctl` binaries. Not every release
reaches crates.io, so this can be a version behind. GitHub Releases always
carry the newest version.

### From GitHub Releases

Each release ships prebuilt binaries for Linux (glibc and musl), macOS
(Intel and Apple Silicon), and Windows. Every archive contains both the
`elasticctl` and `elkctl` binaries. Download the archive for your platform
from the [latest release](https://github.com/dannyota/elasticctl/releases/latest),
put both binaries on your `PATH`, or use an installer script, which does that
for you:

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

## Quickstart

Create a profile from `ELASTICCTL_*` environment variables; `.env.example`
documents them. The key must be a project-scoped Elasticsearch API key created
inside Kibana. An organization-level Cloud key can read and create disabled
rules but cannot enable one.

```bash
export ELASTICCTL_KIBANA_URL=https://YOUR-PROJECT.kb.YOUR-REGION.aws.elastic.cloud
export ELASTICCTL_API_KEY=...
elkctl config init --from-env
```

Confirm the stack is reachable, the key scope is right, and rules are readable:

```bash
elkctl doctor
```

## Manage rules as code

```bash
elkctl state pull --dir state   # writes state/rules/*.ndjson
# edit rules, or add new ones
elkctl state diff --dir state   # field-level drift, no changes made
elkctl state push --dir state   # preview; add --yes to apply
```

`push` and every other remote mutation preview by default and apply only with
`--yes`.

All state commands accept positional selectors, `--tag`, and
`--source custom|customized|prebuilt|all`. `--source` defaults to `custom`;
`--source all` includes the full rule corpus. `--source` limits an unselected
state command to matching rules. Positional selectors and `--tag` override
that unselected source scope: they first resolve rule IDs, then read those
rules:

```bash
elkctl state diff --dir state my-rule-id      # one rule
elkctl state push --dir state --tag prod      # one tag
```

`diff` and `push` resolve a selector against the directory first, so a rule you
have only written locally is selectable by name before it exists on the stack.

Inspect and manage individual rules:

```bash
elkctl rules list
elkctl rules get <rule_id-or-name>
elkctl rules validate --path rule.yaml
elkctl rules enable <rule_id> --yes
elkctl rules export --tag my-corpus --out rules.ndjson
elkctl rules preview my-rule-id --sample 3
```

## Manage data views

Data views use stable ids and portable JSON or YAML files. Legacy scripted
fields are not portable and are rejected before any remote request.

```bash
elkctl data-views list --search logs
elkctl data-views get logs-default
elkctl data-views validate --path data-views.yaml
elkctl data-views export logs-default --format-file yaml > data-views.yaml

elkctl data-views import --path data-views.yaml --yes
elkctl data-views default set logs-default --yes
elkctl data-views default unset --yes
elkctl data-views delete old-logs --replace-with logs-default --yes
```

`import`, `delete`, and `default set|unset` are guarded mutations. They print
a preview unless `--yes` is supplied. Delete refuses a referenced or current
default data view until its references/default are safely replaced or unset.

## Triage alerts and cases

```bash
elkctl alerts list --status open --severity critical
elkctl alerts ack <alert_id> --yes
elkctl alerts close <alert_id> --reason false_positive --yes

elkctl cases create --title "Suspicious PowerShell activity" --severity high --yes
elkctl cases attach <case_id> --alert <alert_id> --yes
elkctl cases comment <case_id> --message "Confirmed benign, closing." --yes
```

## Command surface

```
elkctl config init | list | show | test
elkctl doctor
elkctl info

elkctl rules list [--source custom|customized|prebuilt|all]
  | get | validate | enable | disable | delete
elkctl rules export [<selector>...] [--tag TAG] [--source custom|customized|prebuilt|all]
  | import [--skip-existing] | preview [--sample N]
elkctl rules prebuilt status|install

elkctl exceptions list | get | validate | export | import | delete

elkctl data-views list [--search TEXT] | get <id-or-exact-name> | validate --path FILE
elkctl data-views export [<id-or-exact-name>...] [--format-file json|yaml]
  | import --path FILE [--overwrite|--skip-existing] --yes
  | delete <id-or-exact-name>... [--replace-with ID] --yes
  | default get | set <id-or-exact-name> --yes | unset --yes

elkctl state {pull|diff|push} --dir DIR [<selector>...] [--tag TAG]
  [--source custom|customized|prebuilt|all]

elkctl search esql <QUERY> [--data-view DV | --index IDX] [--limit N]
elkctl search dsl <BODY> [--data-view DV | --index IDX] [--limit N] [--with-meta]

elkctl alerts list [--status open|acknowledged|closed] [--severity S] [--rule R]
                   [--tag T] [--assignee USER] [--since DUR|ISO] [--search TEXT]
elkctl alerts get <alert_id>
elkctl alerts ack|open|close (<alert_id>... | --query <dsl|@file>) --yes
elkctl alerts close <alert_id>... --reason false_positive --yes
elkctl alerts tag <alert_id>... --add triaged --remove noise --yes
elkctl alerts assign <alert_id>... --add USER --yes

elkctl cases list [--status open|in-progress|closed] [--severity S]
                  [--tag T] [--search TEXT]
elkctl cases get <case_id>
elkctl cases create --title T [--description D] [--tag T]... [--severity S]
                    [--assignee USER]... --yes
elkctl cases close|open <case_id>... --yes
elkctl cases delete <case_id>... --yes
elkctl cases attach <case_id> --alert <alert_id>... --yes
elkctl cases comment <case_id> --message TEXT --yes

elkctl completion bash|elvish|fish|powershell|zsh
elkctl commands
```

## Global flags

`--profile`, `--config`, `--space`, `--json` / `--format`, `--fields`, `--out`,
`--yes`, `--timeout`, `--debug`. Run `elkctl help` for details.

## Development

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cargo test
```

Setup, the gates a pull request must pass, and the rules review holds you to:
[`CONTRIBUTING.md`](CONTRIBUTING.md). Cutting a release:
[`docs/releasing.md`](docs/releasing.md).

## License

Apache-2.0
