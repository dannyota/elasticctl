# elasticctl

**A safety-first CLI to operate Elastic Security as code.**

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

Not every release reaches crates.io, so this can be a version behind. GitHub
Releases always carry the newest version.

### From GitHub Releases

Each release ships prebuilt binaries for Linux (glibc and musl), macOS
(Intel and Apple Silicon), and Windows. Download the archive for your platform
from the [latest release](https://github.com/dannyota/elasticctl/releases/latest)
and put the `elasticctl` binary on your `PATH`, or use an installer script:

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
elasticctl config init --from-env
```

Confirm the stack is reachable, the key scope is right, and rules are readable:

```bash
elasticctl doctor
```

Manage rules as code:

```bash
elasticctl state pull --dir state   # writes state/rules/*.ndjson
# edit rules, or add new ones
elasticctl state diff --dir state   # field-level drift, no changes made
elasticctl state push --dir state   # preview; add --yes to apply
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
elasticctl state diff --dir state my-rule-id      # one rule
elasticctl state push --dir state --tag prod      # one tag
```

`diff` and `push` resolve a selector against the directory first, so a rule you
have only written locally is selectable by name before it exists on the stack.

Inspect and manage individual rules:

```bash
elasticctl rules list
elasticctl rules get <rule_id-or-name>
elasticctl rules validate --path rule.yaml
elasticctl rules enable <rule_id> --yes
elasticctl rules export --tag my-corpus --out rules.ndjson
elasticctl rules preview my-rule-id --sample 3
```

## Command surface

```
elasticctl config init | list | show | test
elasticctl doctor
elasticctl info

elasticctl rules list [--source custom|customized|prebuilt|all]
  | get | validate | enable | disable | delete
elasticctl rules export [<selector>...] [--tag TAG] [--source custom|customized|prebuilt|all]
  | import [--skip-existing] | preview [--sample N]
elasticctl rules prebuilt status|install

elasticctl exceptions list | get | validate | export | import | delete

elasticctl state {pull|diff|push} --dir DIR [<selector>...] [--tag TAG]
  [--source custom|customized|prebuilt|all]

elasticctl alerts list [--status open|acknowledged|closed] [--severity S] [--rule R]
                       [--tag T] [--assignee USER] [--since DUR|ISO] [--search TEXT]
elasticctl alerts get <alert_id>
elasticctl alerts ack|open|close (<alert_id>... | --query <dsl|@file>) --yes
elasticctl alerts close <alert_id>... --reason false_positive --yes
elasticctl alerts tag <alert_id>... --add triaged --remove noise --yes
elasticctl alerts assign <alert_id>... --add USER --yes

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands
```

Global flags: `--profile`, `--config`, `--space`, `--json` / `--format`,
`--fields`, `--out`, `--yes`, `--timeout`, `--debug`. Run `elasticctl help` for
details.

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
