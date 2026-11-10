# CLI

Commands follow `elkctl <area> <verb> [arguments] [flags]`. Run
`elkctl <area> --help` for every flag, and `elkctl commands` for the command
tree as JSON.

## Command tree

| Area | Verbs | Guide |
| --- | --- | --- |
| `config` | `init`, `list`, `show`, `test` | [Configuration](Configuration.md) |
| `doctor`, `info` | | [Getting Started](Getting-Started.md) |
| `state` | `pull`, `diff`, `push` | [Rules as Code](Rules-as-Code.md) |
| `rules` | `list`, `get`, `validate`, `enable`, `disable`, `delete`, `export`, `import`, `preview`, `prebuilt status`, `prebuilt install` | [Rules](Rules.md) |
| `exceptions` | `list`, `get`, `validate`, `export`, `import`, `delete` | [Exceptions](Exceptions.md) |
| `search` | `esql`, `dsl` | [Search](Search.md) |
| `alerts` | `list`, `get`, `ack`, `open`, `close`, `tag`, `assign` | [Alerts and Cases](Alerts-and-Cases.md) |
| `cases` | `list`, `get`, `create`, `close`, `open`, `delete`, `attach`, `comment` | [Alerts and Cases](Alerts-and-Cases.md) |
| `data-views` | `list`, `get`, `validate`, `export`, `import`, `delete`, `default get`, `default set`, `default unset` | [Data Views and Dashboards](Data-Views-and-Dashboards.md) |
| `dashboards` | `list`, `get`, `validate`, `export`, `import`, `delete`, `bundle export`, `bundle import` | [Data Views and Dashboards](Data-Views-and-Dashboards.md) |
| `fleet agent-policies` | `list`, `get`, `validate`, `export`, `import`, `delete` | [Fleet](Fleet.md) |
| `fleet integration-policies` | `list`, `get`, `validate`, `export`, `import`, `delete` | [Fleet](Fleet.md) |
| `mcp` | `serve` | [MCP](MCP.md) |
| `completion` | `bash`, `elvish`, `fish`, `powershell`, `zsh` | |
| `commands` | | |

[Configuration](Configuration.md#global-flags) lists the global flags.

## Dry run and apply

Every command that changes the stack prints a preview and changes nothing.
Pass `--yes` to apply. The preview and the apply both name the profile, host,
and space:

```text
$ elkctl --profile prod rules disable 'Suspicious PowerShell'
[DRY RUN] Disable 1 rule (profile: prod @ kibana.corp.internal:5601, space: default)
  a1b2c3d4-...  Suspicious PowerShell  enabled -> disabled
Pass --yes to apply.
```

## Output

Tables are the default in a terminal and in a script; output does not change
when stdout is not a terminal. `--json` forces JSON, and `--format` selects
`table`, `json`, `yaml`, `csv`, or `jsonl`. `--fields` keeps only the named
fields. `--out` writes the output to a file.

`--json` and `--format` shape a command's report. They never reshape exported
file content. `rules export` without `--out` writes the rule file itself to
stdout, in the format `--format-file` selects, so this produces a file Kibana
can import:

```bash
elkctl rules export --tag prod > rules.ndjson
```

`alerts list`, `cases list`, and `search` show at most 100 rows as a peek and
say so on stderr when they cut the result. With `--out` they export every row,
unless `--limit` sets a cap.

## Errors

A failure prints one JSON object on stderr:

```json
{"error": {"kind": "permission", "http_status": 403, "message": "..."}}
```

| Kind | Meaning |
| --- | --- |
| `auth` | The credential was rejected |
| `permission` | The credential lacks a privilege |
| `not_found` | The object, or a selector's target, does not exist |
| `conflict` | A name matches several objects, or an object already exists |
| `unsupported` | The tool understands the request and refuses it, with a remedy |
| `http` | The server answered with an unexpected status or body |
| `connection` | The stack could not be reached |
| `timeout` | The request or the wait ran out of time |
| `error` | Anything the classifier could not place |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error |
| `2` | Usage error |

## Selectors

Rule commands accept a `rule_id` or an exact rule name. The `rule_id` is tried
first. A name never matches by prefix or substring, and a name that several
rules share fails with `conflict` and lists the candidates. Data views,
dashboards, and Fleet policies accept an id or an exact name or title the same
way.

## Shell completion

```bash
elkctl completion zsh > ~/.zfunc/_elkctl
```

Completions and help text use the name the binary was invoked as.
