[Back to elasticctl-design](../elasticctl-design.md)

## 3. Architecture

**API orchestration returns typed values; CLI adapters handle command context
and mutation guards, then serialize values for the renderer.** splunkctl
generates MCP tools by reflecting over its Click tree. Its callbacks print
through `click.echo`, and the MCP runner captures stdout. Rust commands that
print directly would leave an MCP server only a string to parse again. Typed
values let the MCP crate call the same API functions and project their data
into explicit tool schemas.

```
elasticctl/
  Cargo.toml                 workspace
  crates/
    elasticctl-core/         config, profiles, auth, transport, errors, capabilities
    elasticctl-api/          typed endpoints, canonical Rule model, NDJSON/YAML codecs
    elasticctl-cli/          clap commands, render layer, mutation guard, main()
    elasticctl-mcp/          stdio protocol, tool schemas, projections, call limits
  xtask/                     fixture recorder
  tests/fixtures/            recorded HTTP exchanges, tagged by flavor and version
  lab/                       podman compose stack for self-managed recording
  docs/specs/                design documents
```

Dependency direction is strictly one way: `cli` → `mcp` → `api` → `core`.
The CLI also calls API orchestration directly. Both frontends may use core
configuration and transport; API and core never depend on either frontend.
The published MCP library has no binary or `clap` dependency. `xtask` may
depend on MCP for test tooling, never on the CLI.

That direction only pays off if the logic worth reusing sits below the line.
**API orchestration belongs in `-api` and returns typed values. `cli/cmd/`
adapters handle command context and mutation guards, then serialize values for
the renderer.**
Measured on 2026-08-14, v0.1 does not meet this: 1,528 lines of orchestration
live in `cli/src/cmd/`, and 18 of 23 command functions return
`serde_json::Value` rather than a struct. `Drift::compute` is correctly in
`-api`; the code that resolves a selection, loads a directory, and builds a
report is not.

0.2 closes this rather than deferring it, for every command an MCP server could
call. Two stay in `-cli` on purpose: `meta` reflects over the `clap` tree and
cannot leave the crate that defines it, and `config_cmd` manages the user's
local profile file, which is a property of the operator's machine rather than
of a stack. The state engine is rewritten in 0.2
to carry exception lists, so `cmd/state.rs` is reworked regardless, and
retrofitting a file while rewriting it costs less than doing either alone.
`cmd/rules.rs` follows in the same release because the two share the selection
and render paths, and splitting them would leave the render layer serving two
shapes at once.

The retrofit lands before any 0.2 feature, proven by snapshot tests showing
byte-identical rendered output for every existing command. Built the other way
round, each new command is written once against `serde_json::Value` and again
against a struct. It is also independently shippable if the rest of 0.2 runs
long.

### 3.1 elasticctl-core

Does not know about detection rules.
A space id is empty, which means the default space, or matches
`[a-z0-9_-]+`, the Kibana space id format. Profile resolution and transport
construction refuse any other value with kind `error` and the static message
`invalid space id`, so a space such as `..` cannot reach another space's
routes.

- **`config`** — profiles in `~/.elasticctl/config.toml`, `0600` enforced on
  write and warned on read. Writes go through a same-directory temporary file
  and an atomic rename, so a save never truncates an existing file in place or
  writes through a symlink. Resolution order: flags → environment
  (`ELASTICCTL_*`) → profile → defaults. The CLI reads `ELASTICCTL_*` through a
  checked loader that fails on invalid Unicode and a non-integer timeout
  instead of silently dropping the value; `from_env` remains the lossy loader
  for direct library callers. Returns the effective config *and its
  provenance*, so the guard banner can name the profile about to be mutated.
  `kibana_url` and `es_url` are both identity: on a Cloud deployment they are
  two hosts of one stack, and on self-managed `es_url` is absent and the Kibana
  host serves both. They resolve together. An environment or flag override of
  one without the other does not inherit the profile's value for the other.
  Overriding `kibana_url` alone clears `es_url` instead of retaining a host
  from another deployment. Otherwise, one client could target two stacks and
  send the overridden credential to a host the operator did not name.
  Any `user:password@` prefix in `kibana_url` or `es_url` is stripped at
  resolution and before a profile is written. Credentials come from `api_key`
  or `username`/`password`; a URL has never been an authentication channel
  here. A URL carrying userinfo would surface in the guard banner and every
  `--debug` line. Scrubbing is enforced at every public sink, not only at
  resolution: `Profile::redacted`, `Profile::host`, `Config::save`, and
  `Transport::with_debug` each strip userinfo before deriving output, so a
  direct library caller that constructs a `Profile` with embedded userinfo
  cannot leak it. Userinfo is the `user:password@` in the authority, delimited
  by the scheme's `://` and the first `/`, `?`, or `#` after it. A later `://`
  in the path, query, or fragment is not the scheme and must not defeat the
  strip: `https://user:pass@kb.example.com/?next=https://idp` scrubs to
  `https://kb.example.com/?next=https://idp`. A doubled scheme
  (`https://https://user:pass@kb.example.com`, a copy-paste slip) anchors on its
  last `://` and scrubs the same way rather than leaking. An unencoded `/`,
  `?`, or `#` inside userinfo is malformed (RFC 3986 requires percent-encoding)
  and is out of contract; percent-encoded userinfo scrubs correctly.
- **`auth`** — `ApiKey` (`Authorization: ApiKey <base64(id:key)>`) or `Basic`.
  API key is the default; basic auth exists for the local lab.
- **`transport`** — `reqwest` with `rustls` on `tokio`. Injects `kbn-xsrf: true`
  on every non-GET request, `elastic-api-version` where required, and prefixes
  space-scoped paths as `/s/<space>/api/...`. A request path must start with
  `/`: the Kibana and Elasticsearch URL builders refuse any other path with
  `ErrorKind::Error` before a request is built or a credential attached,
  because a path such as `@other.example/x` appended to the base URL would
  send the request and its credential to another host. Retries with backoff on 429 and
  5xx only, never on 4xx. JSON POST, PUT, and DELETE also expose one-shot
  variants for ownership-guarded mutations that cannot be replayed safely.
  One-shot sends the request once with redirects, connection pooling, and the
  HTTP client's protocol-level retries disabled; its caller resolves an
  ambiguous outcome with an exact read instead of repeating the mutation.
  Elasticsearch PUT, POST, and DELETE have the same one-shot form,
  `put_absolute_es_once`, `post_absolute_es_once`, and
  `delete_absolute_es_once`, for a write whose
  outcome must not be blurred by a retry, such as an index create whose answer
  decides who owns the index.
  JSON, raw-export, multipart-import, and Elasticsearch responses share that
  retry loop and timeout/connection classification. A body-read failure is
  therefore classified the same way as a failure before the response headers.
  Under `--debug` it logs one line before each request is sent and one on every
  outcome, including timeout and connection errors. Those are the cases an
  operator uses `--debug` to diagnose. It logs the method, complete URL, and
  status; it never logs a header or body. URL query strings must not contain
  credentials.
  `Transport::with_options` adds opt-in decoded response-body limits,
  redirect suppression, and retry suppression. Existing constructors retain
  their defaults. A configured body limit covers success and error bodies on
  every request path: reject an excessive declared size, then count streamed
  decoded chunks before extending the buffer. Exceeding it returns
  `unsupported` with `response body exceeds configured byte limit` and is
  never retried. Retry suppression allows one application attempt and disables
  HTTP-client retries. Redirect suppression applies to both clients; one-shot
  requests retain their stricter transport settings.
  Response headers are captured and returned alongside the body, because the
  deployment flavor is not derivable from any response body — see
  `capabilities` below. They are carried, never logged: `--debug` still prints
  no header because headers carry credentials.
- **`capabilities`** — one probe at connect time reading `GET /api/status`.
  Yields `Capabilities { flavor, version }` and is cached once per transport.
  Exception-list, prebuilt-rule, and rule-source routes require the feature's
  verified version before their first request. In 0.2.1 all three floors are
  9.5.1, the oldest version with complete fixtures; an older version returns a
  typed `Unsupported` error naming the feature, flavor, reported version, and
  floor instead of the server's generic 404. The comparison is on the numeric
  `major.minor.patch`: a leading `v` and a pre-release or build suffix
  (`-SNAPSHOT`, `-beta`, `-rc`) are ignored, so a 9.5.1 lab or snapshot build
  is not refused, and a version with no numeric `major.minor.patch` is
  unreadable and fails the same way. An
  all-rules query does not gain a source-scoping requirement, and local-only
  validate or dry-run work does not pay for the probe.
  Flavor is decided in this order, and the order is load-bearing:

  1. `version.build_flavor == "serverless"` → Serverless.
  2. The response carries `x-found-handling-cluster` → Elastic Cloud Hosted.
  3. Otherwise → self-managed.

  Elastic Cloud Hosted reports `build_flavor: "traditional"`, the same value a
  self-managed stack reports, so no field of the status body separates them.
  The distinguishing signal is a header injected by the Cloud edge proxy, which
  a self-managed Kibana has nothing to add. Serverless sits behind the same
  proxy and carries the same header. The `build_flavor` test must come first;
  reversing them would classify every Serverless project as Hosted. Hostname
  matching against known Cloud suffixes is the last resort for a deployment
  reached through a proxy that strips the header. The extracted hostname is
  matched case-insensitively after one final DNS dot is removed; suffix
  boundaries still reject lookalike domains. This fallback is not normally
  needed.
  Spaces and license tier are *not* part of this probe because each costs a
  request, and `doctor` and `config test` need neither. `info` probes them
  directly — the space list from `GET /api/spaces/space`, the license tier from
  `GET /_license`, which does not exist on Serverless — and reports `null` for
  either when it cannot be determined. It does not report a hardcoded value
  that happens to be right on one flavor.
- **`errors`** — `thiserror` enums classified at one point into the taxonomy
  below.

### 3.2 elasticctl-api

- **`model::Rule`** — canonical representation covering query, eql, esql,
  threshold, threat_match, machine_learning, and new_terms rule types. It is a
  newtype over `serde_json::Map`, so fields unknown to this client survive a
  round-trip.
- **`normalize`** — strips volatile server-side fields (`id`, `created_at`,
  `updated_at`, `created_by`, `updated_by`, `version`, `revision`,
  `execution_summary`), sorts map keys, and orders rules by `rule_id`.
  Deterministic output is what makes `diff` trustworthy; without it every
  `pull` would report fake drift.
- **`codec`** — NDJSON (canonical, import-ready) and YAML (`serde_yaml_ng`;
  `serde_yaml` is unmaintained) over the same `Rule`. Handles Kibana's trailing
  `{"exported_count":N,...}` summary object as a trailer, not a rule.
- **`rules`** — typed endpoint wrappers returning `elasticctl_core::Result<T>`.
  They never print. Later verticals (cases, fleet) add sibling modules without
  touching this one.
- **`rules_ops`** — the command orchestration above those wrappers. It is a
  separate module from `rules` so that neither file has to be read whole to
  change the other; the endpoints are a stable surface and the orchestration
  is where behavior moves.
- **`ops`** — the plan and report types that more than one vertical genuinely
  shares. A type earns a place here by having a second consumer, in the commit
  that adds it; a shape guessed in advance of one belongs to the vertical that
  needs it. Measured on 2026-08-14, `MutationPlan` and `ExportOutcome` are
  shared and the per-command outcome shapes are not: enable, disable, delete,
  and import each report different counts and different array-valued fields,
  and flattening them into one struct would change output.
- **`exceptions`** — exception list containers and items, shaped like `rules`:
  typed wrappers, orchestration, no printing.
- **`prebuilt`** — prebuilt rule status and installation.
- **`state`** — `pull`, `diff`, and `push` orchestration: selection resolution,
  directory loading, apply ordering, and report construction. `cli/cmd/` calls
  one function here per command.

### 3.3 elasticctl-cli

`clap` v4 derive. CLI adapters call API orchestration, handle context and
mutation guards, and serialize typed values for `render`. `render` produces
table, json, yaml, csv, or jsonl. `guard` implements the dry-run contract.

### 3.4 elasticctl-mcp

The MCP library accepts one already resolved core target. It owns stdio
routing, schemas, safe result projections, static error messages, and call
limits. It calls API orchestration and never uses the CLI renderer or reads
model-selected local files. Both existing binaries delegate to it through
`mcp serve`. The [MCP design](../elasticctl-mcp-design.md) defines protocol,
target validation, tools, and limits.

Each MCP session uses a dedicated runtime thread to suppress SDK tracing
without changing the embedding process's logger. The public entrypoints
retain the same target, stream, and result contracts.

