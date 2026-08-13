# Changelog

## 0.1.0 — 2026-08-13

First release. Manages Elastic Security detection rules as code.

### Added

- Profiles with `config init`, `list`, `show`, `test`. Secrets stored at mode
  `0600` and redacted in all output.
- `doctor` checks connectivity, authentication, API key scope, deployment
  flavor, and rule access. It reports every failure in one pass.
- `info` shows the CLI version, profile name, Kibana URL, the configured space,
  stack version, flavor, and license tier.
- `rules list`, `get`, `validate`, `enable`, `disable`, `delete`, `export`,
  `import`, `preview`.
- `state pull`, `diff`, `push` with a change-evidence report.
- Output as table, JSON, YAML, CSV, or JSONL, with `--fields` and `--out`.
- Shell completion for Bash, Elvish, Fish, PowerShell, and Zsh, and a
  machine-readable command tree.

### Contracts

- Every mutation previews by default and applies only with `--yes`.
- `state push` never deletes a remote rule.
- Rules are matched by `rule_id`, never by name or by the server-side `id`.

### Known limitations

- An organization-level Elastic Cloud API key cannot enable rules. Use a
  project-scoped Elasticsearch API key created in Kibana. `doctor` reports
  which one is configured.
- Elastic Cloud Hosted is detected by hostname rather than by a stack-reported
  signal.
