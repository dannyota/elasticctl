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
change. The preview goes to stderr, so piped JSON on stdout stays valid;
`crates/elasticctl-cli/tests/guard_writes_to_stderr.rs` rejects a stdout print
in the guard.

The command tree from `elasticctl commands` marks `mutates: true` on every
guarded remote mutation and on `config init`, which writes a local file without
a guard. `guard::check` panics on a guarded path missing from that list, so
tests catch a guarded command the tree would report as read-only.

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

The workspace builds `serde_json` with `preserve_order`, declared once in the
root `Cargo.toml` so every crate shares the same map semantics. Map insertion
order and report struct field order are therefore the JSON key order and the
table and CSV column order, and are part of the output contract; reordering
fields or sorting keys changes output. `crates/elasticctl-api/tests/serde_json_map_order.rs`
fails if the feature stops being unified.

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

A command that succeeds but reports a partial failure also exits `1`: a
report whose `failed` is a non-empty array or a positive count, or whose
`lossy` is a non-empty array. `skipped` is not a failure, because the server
left the object in its target state. A command whose stdout is an exported
file reports a short export through the exit code alone. `alerts get` and
`cases get` print raw server documents, so a `failed` key there never sets the
exit code.

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
  never "nothing happened". Alert report failure counters use checked addition;
  an overflowing sum is a statusless `http` decode error saying the counters
  are unreadable.
- **Numbers.** A JSON response with an integer literal above `u64::MAX` or
  below `i64::MIN` is an `http` error, never an imprecise float. A number with
  a decimal point or an exponent stays a float.
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
  `push`. On Unix a mirror file is opened with `O_NOFOLLOW`, so a file swapped
  for a symlink after listing is refused at the open. Elsewhere, and for the
  root directories, the check is a non-atomic `symlink_metadata`; swapping a
  root needs write access to the mirror, which already allows editing its
  files.
- **Pull-journal recovery.** Each journal entry advances one phase at a time
  (`Prepared` → `BackingUp` → `BackedUp` → `Installing` → `Installed`). A
  record that jumps ahead is corrupt and fails recovery without touching the
  target or discarding the journal. Removing the transaction directory is the
  commit point: it discards the only rollback evidence, so a mirror-directory
  sync that fails after the removal leaves the installed mirror as the result
  and the pull succeeds. File payloads and journal appends are
  synced on every platform; directories are synced on Unix only, because
  `std::fs::File` cannot sync a directory on Windows. The `state push
  --report` file uses the same rule.

