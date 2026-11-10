# Getting Started

Install the tool, point it at a stack, and confirm it can read rules.

## Install

From crates.io, with the stable Rust toolchain:

```bash
cargo install elasticctl
```

Or use a prebuilt binary. Each
[release](https://github.com/dannyota/elasticctl/releases/latest) ships
archives for Linux (glibc and musl, x86_64 and aarch64), macOS (Intel and Apple
Silicon), and Windows x86_64. The installer scripts download the right archive
and put the binaries on `PATH`:

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

Every method installs two names for one binary: `elasticctl` and the shorter
`elkctl`. `elkctl --version` prints `elasticctl <version>`.

## Create an API key

Create an Elasticsearch API key inside Kibana: Project Settings, Management,
API keys on Serverless, or Stack Management, API keys on Hosted and
self-managed. An organization-level Elastic Cloud key is not enough. See
[which key to use](Configuration.md#which-api-key-to-use).

## Create a profile

A profile stores one stack's URL, credential, and space. Create one from
environment variables:

```bash
export ELASTICCTL_KIBANA_URL=https://YOUR-PROJECT.kb.YOUR-REGION.aws.elastic.cloud
export ELASTICCTL_API_KEY=...
elkctl config init --from-env
```

On Elastic Cloud, also set `ELASTICCTL_ES_URL` to the Elasticsearch endpoint.
[Search](Search.md) and the MCP query tools need it. On a self-managed stack
the Kibana host serves both and the variable stays unset.

Name the profile with `--name`, and select it later with `--profile`:

```bash
elkctl config init --from-env --name prod
elkctl --profile prod info
```

## Check the connection

```bash
elkctl doctor
```

`doctor` checks configuration, connectivity, the deployment flavor,
authentication, the key's scope, and rule access. Fix what it reports before
going further. `elkctl info` shows the stack version, flavor, license tier, and
spaces.

## First commands

```bash
elkctl rules list --source custom
elkctl rules get <rule_id-or-name>
elkctl alerts list --status open --since 24h
```

Reads print a table. Add `--json` for JSON.

Changes are previews until you pass `--yes`:

```bash
elkctl rules disable <rule_id>         # prints what would change
elkctl rules disable <rule_id> --yes   # applies it
```

Both lines name the profile, host, and space they target.

## Next steps

- Keep rules in Git: [Rules as Code](Rules-as-Code.md).
- Learn the output and error contract for scripts: [CLI](CLI.md).
- Connect an MCP client: [MCP](MCP.md).
