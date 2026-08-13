# Changelog

## 0.1.1 — 2026-08-13

Improvements and fixes inside the existing command surface. No breaking
changes: every new flag has a default that preserves the previous behaviour.

### Added

- `rules preview` reports how many events matched. The API returns a preview id
  and no count, so the alerts the preview wrote are read back and counted;
  `--sample N` returns the matched documents themselves. When the count cannot
  be read the preview still reports its id, errors, and warnings, with
  `hits: null` and `hits_error` saying why.
- `rules export` takes rule ids or names as positional selectors and a `--tag`
  filter, and exports only those. A selection that matches nothing is refused
  rather than widened to the whole space.
- `rules import --skip-existing` leaves rules that already exist alone instead
  of failing on each of them. The dry run names what would be created and what
  would be skipped. Mutually exclusive with `--overwrite`.
- `info` reports the space list and a real licence tier, both probed, instead
  of no spaces and a hardcoded null.
- `--debug` logs a line before each request is sent and on the timeout and
  connection-error branches.
- A `samples/` harness that fetches a Sigma rule slice and three MIT event
  datasets on demand, with the ECS remap and timestamp rewrite `preview` needs.

### Changed

- Resolving a rule by name filters server-side instead of reading every page of
  the corpus: a lookup that took 8.8 seconds against 2,066 rules is now one
  request. A selector matching neither an id nor a name reports "No rule with
  rule_id or name".
- `state pull` reports every filename collision in one error and writes nothing
  when any collide, instead of failing on the first pair after writing the
  files before it.
- `doctor` truncates the credential id in its auth check. It is not the secret
  half, but it identifies the key.

### Fixed

- A `rule_id` that is present but not a string is rejected when the rule is
  constructed, and an NDJSON decode error names the line.
- Userinfo in a profile's `kibana_url` or `es_url` is stripped at resolution
  and never written to the config file, so a hand-written URL that embeds
  credentials in its authority cannot reach the guard banner or a `--debug`
  line.

### Documented

- `rules export` without `--out` writes the exported file to stdout verbatim
  under every report format. `--json` does not wrap it.

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
