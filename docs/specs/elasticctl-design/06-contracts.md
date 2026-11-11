[Back to elasticctl-design](../elasticctl-design.md)

## 6. Contracts

### 6.1 Safety

Every remote mutation previews before it applies.

```
$ elasticctl --profile prod rules disable 'Suspicious PowerShell'
[DRY RUN] Disable 1 rule (profile: prod @ kibana.corp.internal:5601, space: default)
  a1b2c3d4-...  Suspicious PowerShell  enabled -> disabled
Pass --yes to apply.
```

The banner names the profile, host, and space on both the preview and the
apply, so neither a human nor an agent can mistake which instance is about to
change.

### 6.2 Output and errors

Table output is the default, and `--json` is explicit. This matches splunkctl
instead of detecting a TTY, so a command behaves identically in a terminal and
a script.

`--json` and `--format` control a command's *report* rendering. They never
reshape file content. `rules export` without `--out` has no report; its stdout
**is** the exported rule file, emitted verbatim in the selected `--format-file`.
Wrapping it — `{"ndjson": "..."}` — would make `elasticctl rules export --json
> rules.ndjson` produce a file Kibana cannot import. The raw body is therefore
the contract in this mode under every value of `--format`.

Credential identifiers are not secrets, but must be protected. For example,
the API key id `doctor` reads from `_security/_authenticate` is truncated in
output when longer than twelve characters. The secret half is never printed.

Failures emit one JSON object on stderr:

```json
{"error": {"kind": "permission", "http_status": 403, "message": "..."}}
```

From 0.9.0 the error for a version conflict on `cases close` or `cases open`
carries Kibana's status, 409, in `http_status`. Its message wraps Kibana's:

```json
{"error":{"kind":"conflict","message":"a case changed since the preview (<Kibana message>); re-run the command","http_status":409}}
```

The MCP apply path needs that status to classify the conflict
([mutation design 7](../elasticctl-mcp-mutation-design/07-api-reuse.md#cases)).
It is the one change to existing command output in 0.9.0. The other CLI
changes are the `mcp` description and the `--allow-mutations` flag in help and
the command tree.

Kinds: `auth`, `permission`, `not_found`, `conflict`, `unsupported`, `http`,
`connection`, `timeout`, `error`.

`unsupported` covers any request the tool understands and deliberately refuses,
not only a deployment flavor that lacks a capability. Section 3.1 introduces it
for the flavor case because that is where it first appears, but a local output
format that cannot represent a result — `rules export --format-file yaml` on a
bundle carrying exception lists — is the same kind of answer: a definite refusal
naming a remedy, rather than an unclassified failure. `error` is the bucket for
failures the classifier could not place, which is a different thing.

Exit codes: `0` success, `1` error, `2` usage.

### 6.3 Fail-closed boundaries

A success-shaped response or a readable local file is not evidence that the
content is trustworthy. The client fails closed at each boundary rather than
coercing a malformed value to zero, "unknown", or an empty result:

- **Mutation outcomes.** `_bulk_action` requires an object summary with four
  unsigned counters whose total equals `succeeded + failed + skipped`; import
  responses require a numeric `success_count` and an `errors` array. Case
  status apply refuses a public plan with duplicate ids or an update status
  that differs from the plan target before sending it. Its response must then
  return each requested case id exactly once at that target status. A
  contradictory, missing, duplicate, or unexpected result is an `http` error,
  never "nothing happened".
- **Read outcomes.** A recognized export trailer decodes or fails with its
  line number; a preview-hits body requires `hits.total.value` and
  `hits.hits`; an `_authenticate` body requires `username` and
  `authentication_realm.type`. The live `preview_hits` and `doctor` paths use
  the checked decoders; the tolerant `decode_preview_hits` wrapper remains for
  offline callers.
- **Mirror reads.** The `rules` and `exceptions` roots must be real
  directories, never symlinks. A recognized extension must be a regular file,
  never a symlink or directory, and a lost `read_dir` entry fails rather than
  being skipped. An incomplete or escaped mirror cannot start a destructive
  `push`.
- **Pull-journal recovery.** Each journal entry advances one phase at a time
  (`Prepared` → `BackingUp` → `BackedUp` → `Installing` → `Installed`). A
  record that jumps ahead is corrupt and fails recovery without touching the
  target or discarding the journal.

