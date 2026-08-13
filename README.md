# elasticctl

**A safety-first CLI to operate Elastic Security as code.**

`elasticctl` is a Rust CLI for managing Elastic Security detection rules as
code across self-managed stacks, Elastic Cloud Hosted deployments, and Elastic
Cloud Serverless projects. It is a sibling to
[splunkctl](https://github.com/dannyota/splunkctl) and shares its operating
contracts:

- **Every mutation is a dry run by default.** Nothing changes until you pass
  `--yes`, and every preview names the profile, host, and space it would touch.
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

`push` and every other mutation preview by default and apply only with `--yes`.

All three take the same positional selectors and `--tag` as `rules export`.
A selection narrows both sides before drift is computed. A scoped run reads one
filtered query instead of the whole corpus:

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

elasticctl rules list | get | validate | enable | disable | delete
elasticctl rules export [<selector>...] [--tag TAG] | import [--skip-existing] | preview [--sample N]

elasticctl state pull | diff | push  [<selector>...] [--tag TAG] --dir DIR

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands
```

Global flags: `--profile`, `--config`, `--space`, `--json` / `--format`,
`--fields`, `--out`, `--yes`, `--timeout`, `--debug`. Run `elasticctl help` for
details.

## Development

Requires a stable Rust toolchain.

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cp .env.example .env    # fill in your Elastic endpoints and API key
cargo test
```

`.env` is gitignored. Never commit credentials.

Maintainers cutting a release: [`docs/releasing.md`](docs/releasing.md).

## License

Apache-2.0
