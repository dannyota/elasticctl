# Configuration

A profile names one stack. Flags and environment variables override it for a
single command.

## Profiles

Profiles live in `~/.elasticctl/config.toml`. The file is written with mode
`0600`, and a read warns when group or other can read it. Use `--config` to
point at another file.

```bash
elkctl config init --from-env --name prod   # create or replace a profile
elkctl config list                          # list profiles
elkctl --profile prod config show           # one profile, secrets redacted
elkctl --profile prod config test           # reach and authenticate
```

Without `--name`, `config init` writes the profile `default`. Without
`--profile`, commands use the configuration file's current profile, or
`default` when none is set.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `ELASTICCTL_KIBANA_URL` | Kibana base URL |
| `ELASTICCTL_ES_URL` | Elasticsearch URL. Set it on Elastic Cloud |
| `ELASTICCTL_API_KEY` | Elasticsearch API key |
| `ELASTICCTL_SPACE` | Kibana space; defaults to `default` |
| `ELASTICCTL_TIMEOUT` | Request timeout in seconds; defaults to 30 |

[`.env.example`](https://github.com/dannyota/elasticctl/blob/master/.env.example)
documents every variable, including the ones only the development tools read.

## Resolution order

Each setting resolves in this order: flag, environment variable, profile,
default.

The Kibana URL and the Elasticsearch URL resolve together, because they are two
hosts of one stack. Overriding `ELASTICCTL_KIBANA_URL` alone clears the
profile's Elasticsearch URL instead of keeping a host from another deployment.

A `user:password@` prefix in either URL is removed before the URL is used or
saved. Credentials come only from the API key, or from a username and password
on a local lab.

## Spaces

`--space` selects the Kibana space for one command. Rules, exception lists,
data views, dashboards, alerts, and cases belong to a space. Elasticsearch
index access does not: `search` and the MCP query tools read whatever the
credential allows, in any space.

## Which API key to use

Use an Elasticsearch API key created inside Kibana. On Elastic Cloud three key
types exist, all with the same `essu_` prefix, and they are not
interchangeable:

| Key | Created in | Works for |
| --- | --- | --- |
| Elasticsearch API key | Kibana, under API keys | Everything `elkctl` does |
| Organization-level Cloud API key | Elastic Cloud console | Not supported. Serverless 9.7.0 accepts it for CLI reads and rule changes; Hosted and MCP planning refuse it |
| Cloud API key with provisioning rights | Elastic Cloud console | Not used by `elkctl` |

Use the first type. An organization-level key reaches every deployment and
project in the organization, and MCP planning refuses it because its role scope
cannot be read; see [Limitations](Limitations.md#an-organization-level-cloud-key-is-not-supported).
`elkctl doctor` reports which realm the key authenticates through.

## Global flags

These flags are accepted before or after the subcommand.

| Flag | Meaning |
| --- | --- |
| `--profile <NAME>` | Use a named profile |
| `--config <FILE>` | Use a specific configuration file |
| `--space <SPACE>` | Kibana space to operate in |
| `--json` | Force JSON output |
| `--format <FORMAT>` | `table`, `json`, `yaml`, `csv`, or `jsonl` |
| `--fields <A,B>` | Comma-separated fields to include |
| `--out <FILE>` | Write output to a file instead of stdout |
| `-y`, `--yes` | Apply a mutation after reviewing its preview |
| `--timeout <SECONDS>` | Request timeout |
| `--debug` | Log HTTP requests and responses, with secrets redacted |

`mcp serve` accepts only the target and timeout flags. See [MCP](MCP.md).
