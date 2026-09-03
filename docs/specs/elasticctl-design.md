# elasticctl — design

`elasticctl` is a Rust CLI for operating Elastic Security from a security
engineer's laptop. It manages detection rules as code against self-managed
stacks, Elastic Cloud Hosted deployments, and Elastic Cloud Serverless
projects.

It is modelled on [splunkctl](https://github.com/dannyota/splunkctl) and
reuses its operating contracts: named profiles, dry-run-by-default mutations,
structured output, and a stable error taxonomy. An MCP server is planned once
the CLI surface is stable; the architecture below exists to make that addition
additive rather than a rewrite.

## 1. Scope

v0.1 delivers the foundation layer and one vertical: **detection rules as
code**.

v0.2 completes that vertical. It adds exception lists as managed objects,
prebuilt rule status and installation, and `--source` scoping for `rules list`,
`rules export`, and the state commands. It also closes section 3's layering
debt by moving all command orchestration into `-api`.

Out of scope (additive later): alert triage, cases, Fleet and agent policies,
ad hoc search, value-list content management, and the MCP server.

## 2. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Language | Rust 2024, stable toolchain | Single static binary per platform, no runtime for the user to install |
| Deployment targets | Self-managed, Elastic Cloud Hosted, Serverless | Security engineers use all three |
| Flavor handling | Runtime capability probe | ~90% of the detection-rules API is identical across flavors; auth, headers, and feature availability differ |
| First vertical | Detection rules as code | Highest daily value for detection engineers; the API is stable across all three flavors |
| On-disk rule format | NDJSON **and** YAML | NDJSON round-trips Kibana's export/import exactly; YAML is what a human reviews |
| Credentials | Config file at `0600` | Portable across Linux, macOS, WSL, headless, and CI; no keyring dependency |
| Testing | Recorded fixtures plus opt-in live suite | Fixtures record Elastic's actual exchanges |
| Primary dev target | Serverless project | No local stack is needed; the local lab is an occasional recording environment |

### 2.1 Why not the alternatives

**Trait-per-flavor** (`SelfManaged` / `Ech` / `Serverless` behind a trait) was
rejected. The flavors barely diverge on the detection-rules API, which would
create three near-identical implementations to maintain.

**A single flat crate** mirroring splunkctl's layout was rejected because
nothing structurally prevents `clap` types leaking into command logic. That
leak makes a later MCP addition expensive.

**TOML one-file-per-rule** (Elastic's own `detection-rules` convention) was
considered and set aside in favor of NDJSON for round-trip fidelity, with
YAML covering human review.

## 3. Architecture

**API orchestration returns typed values; CLI adapters handle command context
and mutation guards, then serialize values for the renderer.** splunkctl
generates MCP tools by reflecting over its Click tree. Its callbacks print
through `click.echo`, and the MCP runner captures stdout. Rust commands that
print directly would leave an MCP server only a string to parse again. Typed
values let a future MCP crate call the same API functions and serialize the
same structs.

```
elasticctl/
  Cargo.toml                 workspace
  crates/
    elasticctl-core/         config, profiles, auth, transport, errors, capabilities
    elasticctl-api/          typed endpoints, canonical Rule model, NDJSON/YAML codecs
    elasticctl-cli/          clap commands, render layer, mutation guard, main()
  xtask/                     fixture recorder
  tests/fixtures/            recorded HTTP exchanges, tagged by flavor and version
  lab/                       podman compose stack for self-managed recording
  docs/specs/                design documents
```

Dependency direction is strictly one way: `cli` → `api` → `core`. A future
`elasticctl-mcp` depends on `api` and `core`, never on `cli`.

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
  space-scoped paths as `/s/<space>/api/...`. Retries with backoff on 429 and
  5xx only, never on 4xx.
  JSON, raw-export, multipart-import, and Elasticsearch responses share that
  retry loop and timeout/connection classification. A body-read failure is
  therefore classified the same way as a failure before the response headers.
  Under `--debug` it logs one line before each request is sent and one on every
  outcome, including timeout and connection errors. Those are the cases an
  operator uses `--debug` to diagnose. It logs the method, complete URL, and
  status; it never logs a header or body. URL query strings must not contain
  credentials.
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

## 4. Command surface

Lines marked `0.2` are added in that release; everything else ships in v0.1.

```
elasticctl config init --from-env            Create a profile from ELASTICCTL_* vars
elasticctl config list | show | test         Inspect profiles; secrets always redacted
elasticctl doctor                            Configuration, connectivity, flavor, auth, key scope, rule access
elasticctl info                              Stack version, flavor, license tier, spaces

elasticctl rules list                        --enabled/--disabled --type --severity --tag --filter --search --source
elasticctl rules get <name|rule_id>
elasticctl rules validate --path FILE        Local schema check, no server contact
elasticctl rules enable  <name|rule_id>...   [guarded]
elasticctl rules disable <name|rule_id>...   [guarded]
elasticctl rules delete  <name|rule_id>...   [guarded]
elasticctl rules export [<name|rule_id>...] [--tag TAG] [--source S] [--out FILE] [--format-file ndjson|yaml]
elasticctl rules import --path FILE [--overwrite | --skip-existing]  [guarded]
elasticctl rules preview <file|name|rule_id> [--invocations N] [--sample N]
elasticctl rules prebuilt status             Installed, missing, outdated, customized             0.2
elasticctl rules prebuilt install            Install missing and update outdated  [guarded]       0.2

elasticctl exceptions list                   --type --tag --namespace --search                    0.2
elasticctl exceptions get <list_id> [--namespace single|agnostic]                                 0.2
elasticctl exceptions validate --path FILE   Local schema check, no server contact                0.2
elasticctl exceptions export [<list_id>...] [--tag TAG] [--namespace NS] [--format-file ndjson]   0.2
elasticctl exceptions import --path FILE [--overwrite | --skip-existing]  [guarded]               0.2
elasticctl exceptions delete <list_id>... [--namespace single|agnostic]   [guarded]               0.2

elasticctl state pull [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/ [--format-file ndjson|yaml]
elasticctl state diff [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/  Field-level structured drift
elasticctl state push [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/ [--report FILE]  [guarded]

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands                          Machine-readable command tree
```

`exceptions` has no `create` verb: authoring is `import --path` or `state
push`, and a flag surface for arbitrary nested `entries` would be worse than a
file. It has no `attach`/`detach` either, because attaching a list to a rule is
a rule mutation and `state push` is how rule mutations are made.

### 4.1 Rule identity

Engineers think in names; the API has `rule_id` (a stable UUID) and `id` (a
volatile saved-object id). Commands accept either a name or a `rule_id`. A
`rule_id` is tried first. A name lookup occurs only when it misses. The lookup
is a **single `_find` filtered server-side on `alert.attributes.name`**, never
a walk of the whole space. Walking took 8.8 seconds against 2,066 rules just
to report no match.

Candidates are matched exactly client-side. A name never resolves by prefix or
substring. A non-unique name returns a typed `conflict` error listing the
candidates instead of silently picking the first match. The candidate page is
capped at 100. If a name has more candidates than that and no exact match, the
command reports that the search was capped. It does not claim that the name is
absent. A selector matching neither an id nor a name is reported as `No rule
with rule_id or name '...'`, because reporting a missed `rule_id` as a missed
*name* misdirects the operator.

State matching is **always** by `rule_id` — never by name, never by `id`.

### 4.2 Global flags

Accepted before or after the subcommand: `--profile`, `--config`, `--space`,
`--json`, `--format`, `--fields`, `--out`, `--yes`/`-y`, `--timeout`,
`--debug`.

### 4.3 Export selection

`rules export` takes the same positional selectors as `enable`, `disable`, and
`delete` — a name or a `rule_id`, resolved the same way — and a `--tag` filter.
Given both, the union is exported. Given neither, the whole space is exported.
This historical behavior remains the default.

Selection is turned into the scoped export body `{"objects": [{"rule_id": ...}]}`
rather than filtered client-side, so a subset export transfers only the subset.

A selection resolving to no rules is refused with `not_found` naming the
selector. It is never widened to "export everything." Treating an empty
selection as "all" has the same failure mode as an unscoped bulk action. A
`--tag` that matches no rules is refused the same way, naming the tag, even
when a selector resolves. Otherwise, a mistyped tag disappears into the union
and the command reports a short export as a success.

A rule deleted between selection and export comes back in the export trailer's
`missing_rules`. Those ids are reported as failures, so the command exits 1
rather than reporting a short export as a success.

### 4.4 Import conflict handling

Re-importing an existing rule returns a per-rule 409 and exit 1. It does not
skip the rule. Two mutually exclusive flags resolve the conflict because they
give opposite answers to the same question:

- `--overwrite` replaces the existing rule.
- `--skip-existing` leaves it alone and reports it as skipped.

`--skip-existing` asks the server which of the file's `rule_id`s already exist,
in chunks, before the guard runs. That is what makes the dry run honest: the
preview names what would be created and what would be skipped, instead of
listing every rule in the file as if it would import. Skipped rules are removed
from the uploaded NDJSON and never affect the exit code — a rule the server was
never asked to change is not a failure.

The default is unchanged: without either flag, a conflict is a reported failure.

### 4.5 Exception list identity

Identity is `list_id` plus `namespace_type`, never the saved-object `id`. The
rule that governs rules governs lists, and here the API forces the point by
disagreeing with itself. Measured 2026-08-14 against Serverless 9.6.0:

| Path | Matches a list by |
|---|---|
| `POST /api/detection_engine/rules` | `id` — required, and any UUID is accepted unvalidated |
| `POST .../rules/_export` | `list_id` — exported the correct list despite a zeroed `id` |
| `POST .../rules/_import` | `list_id` — recreated the list and rewrote the rule's `id` to match |

A rule's `exceptions_list[].id` is therefore a required pointer that two of the
three paths ignore and nothing validates. A rule created with
`"id": "00000000-0000-0000-0000-000000000000"` alongside a live `list_id` is
accepted with a 200 and stores the dangling pointer.

`normalize` strips it, so it can never surface as drift, and `push` resolves
`list_id` against the target stack and injects the current `id`. Nothing else
is safe: omitting the field is a 400, and carrying a pulled stack's `id` to
another stack writes a pointer to an object that does not exist there. That is
the dev-to-prod promotion this tool exists for.

Because the server does not catch a dangling pointer, `diff` does. A rule whose
stored `id` does not match the live container for its `list_id` is reported,
and `push` repairs it.

`namespace_type` is part of identity because `single` and `agnostic` are
separate namespaces in which the same `list_id` may exist independently.

That independence has a consequence for the command surface. A bare `list_id`
is not a selector when the same one exists in both namespaces, so `get`,
`export`, and `delete` each take `--namespace` to qualify it. Without the flag
they refuse such a `list_id` with `conflict` rather than picking a side, and the
error names `--namespace` as the remedy. Read commands default to enumerating
both namespaces and merging, ordered by `(namespace_type, list_id)`: the route's
own default is `single`, so a client that simply omits the parameter would show
an operator a partial list and call it complete.

### 4.6 Prebuilt rules

`rules prebuilt status` reports installed, missing, outdated, and customized
counts. The first three come from
`GET /api/detection_engine/rules/prepackaged/_status`. The fourth costs one
extra `_find` and is the reason the command earns its place: a prebuilt rule
edited in the Kibana UI is invisible to a custom-scoped mirror, and an
unrecorded edit to a detection is exactly what a detection engineer needs to
see.

`rules prebuilt install` installs every missing prebuilt rule and updates every
outdated one. It is one verb because the route is one call:
`PUT /api/detection_engine/rules/prepackaged` does both indivisibly and takes
no selection. There is no per-rule prebuilt upgrade in this tool. The route
offering one is `access: 'internal'`, and its sibling `status` route answers
400 on Serverless 9.6.0 — the same ground on which section 5.2 rejects the
internal search route.

The preview is computed from `_status` rather than from a server dry run,
because this route takes no `dry_run` parameter. It is the only guarded path in
the tool whose preview is client-computed, and the banner names both counts.

### 4.7 Object search

`rules list` gains `--search`, a friendly query over the public `_find` filter
fields. Measured 2026-08-16, that filter reaches `name`, `tags`, `type`,
`enabled`, `ruleId`, `severity`, and the source fields, but **not** `description`
or `query`: either returns 400 (`This key 'alert.attributes.description' … does
NOT exist in alert saved object index patterns`). `--search <text>` therefore
narrows to name substring plus tags:

```
(alert.attributes.name: "*<text>*" OR alert.attributes.tags: "<text>")
```

The parenthesized clause is ANDed with the structured filters, so `--search`
never widens a scoped `_find` past its other clauses. Name is substring-matched
by a quoted wildcard term and matches case-insensitively (measured 2026-08-16
against Serverless 9.6.0: `--search "PowerShell"` and `--search "powershell"`
return the same rules); tags are exact, as in `--tag`, and case-sensitive. The
quotes are
load-bearing: measured 2026-08-16, an unquoted `name: *a b*` matches names
containing both words in any order (a token AND), while the quoted `name: "*a
b*"` matches only the contiguous substring. It is sugar over the same filter as
`--filter` (raw KQL, unchanged); the two are mutually exclusive. `exceptions
list` gains name-substring search through the same flag, over
`exception-list.attributes.name` (or its `-agnostic` counterpart). `--search`
widens list discovery only. Selector resolution stays exact (§4.1), and `state`
gains the flag through §5.3. The internal `_search` route is not used (§5.2).

## 5. State engine

- **`pull`** — read the corpus through `_find`, map to `Rule`, normalize, fetch
  the exception lists those rules reference, and write the tree in the requested
  format. Filenames are planned for every object before
  the first file is written. A `rule_id` pair that sanitises to one filename is
  refused with `conflict`, naming **every** colliding pair at once, before the
  directory is created. Reporting one collision per run hides the next until a
  re-run. Writing files up to a collision leaves a mirror that is neither the
  old state nor the new one. The write is a recoverable local-file transaction:
  a sibling lock and journal preserve or restore the prior tree if replacement
  is interrupted.
- **`diff`** — read local, fetch remote, normalize both, emit field-level
  drift. NDJSON lines are not readable by eye, so `diff` is the human view and
  `git diff` is the fidelity record.
- **`push`** — read local, compute the diff, apply each change through the
  guard, then write a change-evidence report of per-rule before and after
  values plus an applied flag, suitable for attaching to a change ticket.
  The same report records every exception mutation with `create_list`,
  `update_list`, `create_item`, `update_item`, or `delete_item`. For those
  entries the existing `rule_id` field carries the stable `list_id` or
  `item_id`; `name` carries the list name or the item's parent `list_id`.
  Successful creates have no `before`, deletes have no `after`, and successful
  updates carry both. A failed write has no `after`.
  Its report path is preflighted and recoverably replaceable before the first
  remote apply, so an unwritable report cannot leave an unreported mutation.

`push` **never deletes remote rules.** A rule missing locally is not a delete
instruction. Deletion is always the explicit `rules delete`.

### 5.0 Pull path identity and locking

Before it acquires a lock or begins transaction recovery, `pull` resolves the
requested mirror path to one filesystem identity. An existing mirror is fully
canonicalized. For a new mirror, its immediate parent must already exist and
is canonicalized before the one final mirror-name component is appended.
`pull` never creates a missing parent chain; a missing immediate parent returns
the existing typed filesystem error that names that parent.

This resolves `.` and existing `..` components and follows existing symlink
aliases without lexically rewriting a path across a symlink. The resolved root
is used for the sibling lock and every transaction filesystem operation. The
requested spelling is retained only for user-facing output and errors.

The sibling lock is `.<mirror-name>.elasticctl-pull.lock`. A filesystem root
has no safe sibling lock and is refused with `ErrorKind::Error`; its message
contains `filesystem root has no safe sibling lock`. This applies to Unix `/`,
Windows drive roots, and UNC share roots.

### 5.1 Server-applied defaults

Creating a rule with 13 fields returns 36. The server adds 16 defaults and 7
volatile fields. The defaults include `max_signals: 100`, `to: "now"`,
`rule_source: {"type":"internal"}`, and `actions: []`. Normalization also
strips `execution_summary` when other responses include it, bringing the full
volatile-field set to 8.

That means a hand-authored rule file omitting `max_signals` would diff against
its pulled counterpart forever. Two modes resolve it:

- A rule written by `pull` already carries the full field set, so the diff is
  symmetric and exact.
- A hand-authored rule is passed through default-filling before comparison, so
  an omitted field reads as "accept the server default", not as drift.

`rules validate` applies the same default-filling, so an engineer can see
exactly what a sparse file will become before pushing it.

### 5.2 Reading the corpus

`_find` is read in one request, not paged. `per_page` is bounded by
Elasticsearch's result window — `from + size` must not exceed 10,000. A page
size at that window returns every corpus that `_find` can serve.
Measured against 2,066 rules: 21 sequential pages of 100 cost 8.4-11 s; one
request costs 2.4 s.

A corpus larger than 10,000 rules cannot be read through one `_find` by any
combination of `page` and `per_page`, because the limit applies to their sum
rather than to either one. Paging smaller does not evade it and neither does
concurrency. Above the window the corpus is read by partitioning instead.

Every rule `_find` response is decoded as a strict envelope: a JSON object
with array `data`, unsigned integer `total`, positive integer `page`, and
positive integer `perPage`. `perPage` is the spelling in every recorded rule
response. Exception-list `_find` keeps its separate `per_page` contract. Rule
decoding requires the exact `perPage` field: `per_page` cannot substitute when
`perPage` is absent. Unknown fields remain accepted, so a present `per_page`
field is ignored when `perPage` is also present.

Malformed envelopes are not converted to an empty result. Missing or mistyped
fields, `data.len() > total`, and `data.len() > perPage` return
`ErrorKind::Http` messages beginning `decoding rule _find response field` and
naming the invalid field or relationship. Transport JSON-number parse failures
remain transport `ErrorKind::Http` errors rather than envelope errors. All
callers share this decoder, so source-partition verification and prebuilt
customized counts also fail closed on API drift.

`rules export` must not be offered as an escape hatch. It has its own 10,000
cap from `xpack.securitySolution.maxRuleImportExportSize` and returns `Can't
export more than 10000 rules` with a 400. The generic saved-objects export
cannot serve either: the security rule types register `isExportable: false`, so
detection rules are not exportable through that interface. No public API reads
past the window in one call.

#### Partitioned reads above the window

When `total` exceeds the window, the corpus is read as one `_find` per rule
type, filtered on `alert.attributes.params.type`. Every rule has exactly one
type, so the slices are disjoint and together exhaustive — measured against
2,066 rules, the seven types sum to exactly the corpus:

| Type | Rules |
|---|---|
| `query` | 455 |
| `eql` | 1,022 |
| `esql` | 208 |
| `threshold` | 28 |
| `threat_match` | 6 |
| `machine_learning` | 106 |
| `new_terms` | 241 |
| **Total** | **2,066** |

A single type larger than the window is split again on
`alert.attributes.enabled`, which is likewise disjoint and exhaustive (measured
2 enabled, 2,064 disabled). Fourteen slices put the ceiling near 140,000.

Exhaustiveness is enforced, not assumed: the slice totals must sum to the
corpus `total` or the read is refused as a short read, the same rule that
already covers a server returning fewer rules than it counted. This is why the
partition is on type rather than on tags — a rule may carry many tags or none,
so tag slices both double-count and drop rules, and no sum check would hold.

A slice still above the window after both partitions is refused with an error
naming the limit. Returning the first 10,000 rules as though they were the
corpus would make `state diff` report every unread rule as remote-only and
`state pull` write a mirror missing them — silent truncation is the one outcome
worse than failing.

The single-request path is unchanged for a corpus under the window, which
includes every real corpus today. Partitioning is a fallback, not the default.
Seven requests for a 2,066-rule read would forfeit 5.2's result.

Kibana exposes `search_after` on
`POST /internal/detection_engine/rules/_search`, which would remove the ceiling.
It is deliberately rejected. The route is `access: 'internal'` and unversioned,
and this tool spans three deployment flavors whose internal routes need not
agree or survive an upgrade.

### 5.3 Scoped state operations

`pull`, `diff`, and `push` take the same positional selectors and `--tag`
filter as `rules export` (4.3), plus `--search` (4.7). Given neither, they act on
everything inside the active `--source` scope, which from 0.2 is the space's
custom rules rather than the whole space. Section 5.5 covers that change.

Selection narrows both sides before drift is computed, so the remote read
becomes one `rule_id`-filtered `_find` instead of a corpus read. Resolution
differs by command because the commands face opposite directions:

- `pull` reads from the stack, so its selectors name stack rules and resolve
  remotely.
- `diff` and `push` act on the local directory, so a selector matching a local
  `rule_id` or `name` wins and only an unmatched one falls through to a remote
  lookup. Without local-first resolution, a locally added rule that is not yet
  in a remote index could not be selected. Scoped `push` could then not perform
  its principal use.

A selector resolving to nothing is refused, naming the selector, as in 4.3. A
name matching two local rules is refused, naming both `rule_id`s. Identity is
`rule_id`; a display name that is no longer unique is not resolved by guessing.

`RemoteOnly` keeps its meaning inside a selection — `--tag prod` can select a
remote rule with no local file — and `push` still never deletes it.

Scoped runs report what narrowed them. Unscoped runs produce their previous
output. `diff` and `push` report `selected` alongside `local_total`, so a scoped
run cannot be mistaken for a clean tree. `pull` reports `selected` only because
it reads from the stack and has no local set to count against.

The guard banner names the selection. A scoped apply that looked identical to a
full one would defeat the purpose of the banner.

### 5.4 Exceptions in the mirror

The mirror covers the rules in scope plus exactly the exception lists those
rules reference. A list nothing references is not part of a rules-as-code
mirror; `exceptions export` covers it. That closure is what keeps `pull` and
`push` symmetric: `push` manages the set `pull` wrote and never meets a list it
was not told about.

```
config/
  rules/<rule_id>.yaml
  exceptions/<list_id>.yaml
```

A `rule_default` list belongs to exactly one rule and is written inline in that
rule's file. Its own file would be an object whose only consumer is one rule
and whose lifetime is that rule's.

Filenames are planned for every rule and list before the first file is written,
and collisions are refused naming every colliding pair at once — section 5's
existing contract, extended to lists. A `single` and an `agnostic` list sharing
a `list_id` collide on filename and are refused the same way.

`push` applies in a fixed order: containers, then items, then rules. A rule is
never written before the list it points at exists.

A scoped run reconciles items the same way, including in a container shared with
rules outside the scope. That is sound for the same reason the deletion itself
is: `pull` writes a container's items in full whenever it writes the container
at all, and the item read is scoped by `list_id`, never by rule. So a mirror
produced by `state pull r1 --dir config/` holds the complete item set of every
container `r1` references, even one that `r2` also references. The local set is
never a partial view, so an item missing from it is still an instruction.

What a scoped run does *not* do is touch a container no in-scope rule
references — that container is not in the mirror, and its items are never even
read.

**Containers and rules are never deleted. Items inside a mirrored container are
reconciled exactly, deletes included.** The asymmetry follows from what is
mirrored rather than from a softened contract. A rule or a list absent locally
may simply never have been pulled, so its absence carries no instruction. A
container's item set is always written in full — there are no item-level
selectors — so an item present remotely and absent locally *is* an instruction,
in the way a removed entry in a rule's `tags` array is. Removing an exception
is how a detection is un-suppressed. A mirror that cannot express it cannot
converge.

That deletion contract requires a complete, readable local item set. An
exception file may contain one NDJSON object. An omitted `items` field means an
empty hand-authored set, but a present `items` field must be an array. Multiple
objects or a non-array value are refused before remote reconciliation, so
malformed input cannot widen into item deletion.

A standalone top-level exception item in a rule file or export bundle must
have readable, non-empty string `item_id` and `list_id` values. Its absent
`namespace_type` retains the `single` default; if present it must be a
non-empty string. Unknown non-empty namespace strings remain valid so a future
server value can round-trip without being treated as `single`. NDJSON bundle
items and YAML top-level items are validated before they enter the mirror.

This stricter rule is contextual. A nested item inside a container may omit
`list_id`, because splitting the container assigns the authoritative parent
`list_id` and `namespace_type`. Item grouping validates the same identity again
before item reconciliation, so a malformed item returns
`ErrorKind::Error` instead of planning a remote item deletion. Empty fields use
the messages `exception item field item_id must be a non-empty string`,
`exception item field list_id must be a non-empty string`, and `exception item
field namespace_type must be a non-empty string`.

`diff` gains an `exceptions` block mirroring the rules block, and `clean` is
true only when both are.

### 5.5 Scoping by rule source

`--source custom|customized|prebuilt|all` scopes `rules list`, `rules export`,
and the state commands.

| Value | Server-side filter |
|---|---|
| `custom` | `alert.attributes.params.immutable: false` |
| `prebuilt` | `alert.attributes.params.immutable: true` |
| `customized` | `alert.attributes.params.ruleSource.isCustomized: true` |
| `all` | none |

`immutable` carries the custom/prebuilt split rather than
`params.ruleSource.type` because it is present in the measured fixtures. On
Serverless 9.6.0, the fields agreed exactly: 2,066 prebuilt and 0 custom. Its
presence on versions older than 9.5.1 is unmeasured.

The state commands default to `custom`; `rules list` and `rules export` default
to `all`. The defaults differ because the commands differ. A mirror should hold
what the operator authored, and `state pull` writing 2,066 Elastic-owned rules
into a repository is the behavior 0.2 removes. A query command that hid 2,066
rules demonstrably present on the stack would be lying instead.

Section 5.2's exhaustiveness check extends: custom and prebuilt must sum to the
corpus, and when `--source` is active a partitioned read checks its slices
against the filtered total rather than the corpus total.

A local file outside the active scope is reported as `out_of_scope`, naming the
flag, not as `local_only`. A 0.1 mirror holding 2,066 prebuilt rules would
otherwise read as catastrophic drift on the first `state diff` after upgrading.

An empty `custom` or `prebuilt` source is valid when their totals together
exhaust the corpus: then zero is a measured partition result, not a missing
`immutable` field. If the totals do not exhaust the corpus, the source query is
refused naming `alert.attributes.params.immutable`; an older stack could
otherwise silently report "no custom rules" merely because it lacks that
field. `state diff` and `state push` still express excluded local files as
`out_of_scope`.

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

## 7. Verified API facts

Probed against a trial Elastic Cloud Serverless Security project on 2026-08-13.
Deployment identity and location are omitted. Elasticsearch and Kibana both
reported 9.6.0 with `build_flavor: serverless`.

| Fact | Detail |
|---|---|
| Auth | `Authorization: ApiKey <essu_…>` works on both Elasticsearch and Kibana |
| Key identity | realm `_cloud_api_key`, roles `["admin"]`, username equals the key id |
| API version header | `elastic-api-version: 2023-10-31` accepted on detection-engine, alerting, cases, and fleet |
| Space prefix | `/s/default/api/...` works, identical result. One space exists |
| Flavor probe | `version.build_flavor` is present in both `GET /` (Elasticsearch) and `GET /api/status` (Kibana) |
| Signals index | Already bootstrapped as `.alerts-security.alerts-default` |
| Identity probe | `GET /_security/_authenticate` returns username, roles, and realm — the `doctor` primitive |
| Export trailer | With zero rules, `POST /api/detection_engine/rules/_export` returns *only* the summary object |
| Prebuilt rules | The internal route `/internal/detection_engine/prebuilt_rules/status` returns 400 `"exists but is not available with the current configuration"`. Use the public API |
| `_find` result window | `per_page` is bounded by `from + size <= 10000`; 10001 is a 400 naming the window. One request returns all 2,066 rules in 2.4 s against 8.4-11 s for 21 pages of 100 |
| `_find` has no cursor | The public route takes only `page`/`per_page`; `search_after` exists solely on `POST /internal/detection_engine/rules/_search`, which is `access: 'internal'` |
| Export cap | `POST .../rules/_export` is capped at 10,000 by `xpack.securitySolution.maxRuleImportExportSize` and answers `Can't export more than 10000 rules` with a 400. It is not an escape hatch from the `_find` window |
| Export is count-capped only | `xpack.securitySolution.maxRuleImportPayloadBytes` (10 MB) is read by the import route alone; export has no byte cap |
| Rules are not saved-object exportable | The security rule types register `isExportable: false`, so `POST /api/saved_objects/_export` cannot return detection rules regardless of `savedObjects.maxImportExportSize` |
| Partition filters | `alert.attributes.params.type` and `alert.attributes.enabled` are disjoint and exhaustive over the corpus: the 7 types sum to 2,066 and enabled/disabled splits 2/2,064 |
| `rule_id` filtering works | `alert.attributes.params.ruleId: "<id>"` returns exactly 1 for a live id and 0 for an absent one, despite not appearing in the documented filter-field list |

### 7.1 Rule schema, measured

A `query` rule created with 13 fields comes back with 36.

**Volatile — strip before diffing (8):** `id`, `created_at`, `created_by`,
`updated_at`, `updated_by`, `revision`, `version`, `execution_summary`.

Normalization descends into an exception item's `comments` array and strips the
same class of field there. A comment's `id`, `created_at`, and `created_by` are
minted by the server on write, so an item carrying a comment would otherwise
show drift on every stack it is promoted to, and no operator action could
resolve it. `updated_at` and `updated_by` are stripped from a comment too: they
were not present on a freshly created one, but they name the same class on every
other object in this API, and removing an absent key costs nothing.

**Server defaults — fill before diffing a sparse local file (16):** `actions`,
`author`, `exceptions_list`, `false_positives`, `immutable`, `max_signals`,
`output_index`, `references`, `related_integrations`, `required_fields`,
`risk_score_mapping`, `rule_source`, `setup`, `severity_mapping`, `threat`,
`to`.

**Author-controlled (13):** `rule_id`, `name`, `description`, `type`,
`language`, `query`, `index`, `severity`, `risk_score`, `enabled`, `from`,
`interval`, `tags`.

`rule_id` is caller-supplied and may be any string, not only a UUID — the probe
used `elasticctl-schema-probe` and it was accepted.

Export NDJSON is exactly two lines for one rule: the rule object, then a
15-field summary trailer (`exported_count`, `exported_rules_count`,
`missing_rules`, `missing_rules_count`, and the exception-list and
action-connector equivalents).

### 7.2 Rule mutation requires a project-scoped API key

`PATCH /api/detection_engine/rules` and `_bulk_action` with `action: enable`
both fail with an organization-level API key:

```
Cannot use an organization-level API key to create or enable rule
"Alerting: siem.queryRule/...". Organization-level API keys are not supported
for rule operations; use a project-scoped Elasticsearch API key instead.
```

Enabling a rule makes the alerting framework mint a rule-owned API key. It
refuses to do that on behalf of an organization key. The `essu_` prefix does
**not** imply project scope: the key used for the probes reports
`roles: ["admin"]` in realm `_cloud_api_key` and is organization-level.

Consequences:

- Reads, creates of **disabled** rules, deletes, and `dry_run` bulk actions all
  work with an organization key.
- Enable, disable-with-apply, and anything that schedules a rule need a
  project-scoped Elasticsearch API key, created inside Kibana rather than in
  the Cloud console.
- `doctor` must detect this and say so plainly. A user whose key cannot enable
  rules should learn it from `doctor`, not from a 400 in the middle of a push.

**Resolved.** A project-scoped key created inside Kibana authenticates through
realm `_es_api_key` rather than `_cloud_api_key`, and every remote mutation
path works.
End-to-end verification created a disabled rule, patched it to `enabled: true`
by `rule_id` (200, `enabled: true`), disabled it through `_bulk_action`
(`succeeded: 1`, `enabled: false`), then deleted it.

`doctor` should use the realm as the signal: `_cloud_api_key` means rule
mutation will fail; `_es_api_key` means it will work. This check is cheaper and
clearer than attempting a mutation and classifying the 400.

Enabling a rule does not bump `revision` — it stayed 0 across the enable.

### 7.3 Targeting rules by rule_id in bulk actions

`_bulk_action` accepts `ids`, which are the volatile server-side saved-object
ids, or a `query`. Targeting by the stable `rule_id` works through the query
form and needs no id resolution step:

```json
{"action": "disable", "query": "alert.attributes.params.ruleId: \"my-rule-id\""}
```

Verified: one rule matched, `summary.succeeded` was 1.

`_bulk_action` also accepts `?dry_run=true`, which reports what would change
without applying it. The dry-run preview can therefore be server-computed
instead of inferred.

### 7.4 Two error body shapes

The Elastic Cloud edge proxy and Kibana return different error envelopes. The
classifier must parse both, or an edge failure gets misreported as a Kibana
error.

```
edge proxy:  {"ok":false,"message":"Unknown resource."}
kibana:      {"statusCode":400,"error":"Bad Request","message":"..."}
```

The edge proxy shape also appears for a hostname that no longer resolves to a
live project, which is a realistic failure mode after a project rename.

### 7.5 Preview results

`POST /api/detection_engine/rules/preview` returns
`{previewId, logs: [{errors, warnings}]}` and **no hit count**. A rule that
matched four documents and one that matched none produce byte-identical
responses. The only in-band signal is the `max_signals` warning, which fires
only at 100 or more. This prevents the command from serving a detection
engineer iterating on a query.

The hits are therefore read back. The alerts a preview writes land in a
per-space preview alerts index and are searched with the returned `previewId`:

| Fact | Value | Status |
|---|---|---|
| Preview alerts index | `.preview.alerts-security.alerts-<space>` | **Measured** by the `rules_preview_hits` fixture |
| Field carrying the preview id | `kibana.alert.rule.uuid` | **Measured** by the same fixture |
| Readable with a project-scoped Elasticsearch API key | yes | **Measured** by the same fixture |
| Visible to search when the preview response returns | Observed on the first search of the recorded run | **Measured**; the fixture records `attempts_until_hits: 1` for that run |

In the recorded run, alerts were visible to the first search. A slower stack
may not be, so the retry below accounts for that uncertainty. It does not claim
the same result for every stack.

The read uses Elasticsearch rather than a Kibana route. The evaluation already
recovered true hit counts from Elasticsearch with the same project-scoped key,
so the credential and transport are proven. Only these names remain open.

Every simulated invocation completes before the preview response returns; each
has its own `logs` entry. There is nothing to poll. The remaining race is
Elasticsearch's one-second default refresh interval. A first search with zero
hits is retried once after one second. A matching rule pays nothing.

A failed read degrades instead of failing: `hits` is `null`, `hits_error`
carries the classified message, and the preview's id, errors, and warnings are
reported as before. Preview is a diagnostic. Losing the count must not lose the
run.

### 7.6 Elastic Cloud Hosted, measured

Probed against a trial Hosted deployment on 2026-08-13; deployment identity and
location are omitted. Elasticsearch and Kibana were both 9.5.1. The full
fixture set is recorded under `tests/fixtures/ech-9.5.1`.

| Fact | Detail |
|---|---|
| Kibana `build_flavor` | `"traditional"` — the same value a self-managed stack reports. The status body cannot distinguish the two |
| Elasticsearch `build_flavor` | `"default"`, `build_type: "docker"` |
| Edge headers | `x-found-handling-cluster`, `x-found-handling-instance`, and `x-cloud-request-id` on both the Kibana and Elasticsearch endpoints |
| Same headers on Serverless | Present, so the header means "behind the Cloud edge proxy", not "Hosted". `build_flavor` must be tested first |
| Error envelope | A 404 on a live deployment is Kibana's `{"statusCode","error","message"}`. The Cloud edge `{"ok":false,"message":...}` shape belongs to hostnames that do not resolve, not to live deployments |
| License | `GET /_license` returns `type: "enterprise"`, unlike Serverless where the endpoint does not exist |

The negative half is also measured. `traditional-9.5.1`, recorded from the
`lab/` stack on 2026-08-13, carries a `headers` object with the headers that
stack sends but without `x-found-handling-cluster`. The header's absence is
therefore evidence, not an assumption that no Cloud proxy fronts a
self-managed deployment.

This distinction must remain: an absent `headers` key means "not recorded,"
which proves nothing. The classification test requires the key on every fixture
set, so a re-record that drops it fails instead of reverting this to an
inference.

### 7.7 Exceptions, measured

Probed against the same Serverless 9.6.0 project on 2026-08-14. Every object
was created, measured, and deleted, and the project was verified back to its
baseline: 2,066 prebuilt rules, no sample rules, no exception lists.

| Fact | Detail |
|---|---|
| Rule export bundles exceptions | A scoped `_export` of one rule carrying a list returns four lines: the rule, the list container, the item, then the trailer |
| The bundle breaks 0.1.3 | `rules export` answers `line 2: a rule must have a rule_id`. Every rule with an exception list fails to export |
| Export resolves by `list_id` | A rule carrying a zeroed `id` and a live `list_id` exported the correct list, with `missing_exception_lists: []` |
| Import re-resolves | Deleting both objects and importing the bundle recreated the list under a new `id` and rewrote the rule's `exceptions_list[].id` to match |
| `id` is required on create | Omitting it is a 400: `exceptions_list.0.id: Invalid input: expected string, received undefined` |
| A dangling `id` is accepted | A zeroed UUID beside a live `list_id` returns 200 and is stored verbatim |
| The exception export trailer differs | `POST /api/exception_lists/_export` ends with `exported_exception_list_count` and carries no `exported_count`, so the rules trailer test does not match it |
| Container volatile fields | `id`, `_version`, `tie_breaker_id`, `version`, `created_at`, `created_by`, `updated_at`, `updated_by` |
| Item volatile fields | The same set less `version`. A measured item response has `_version` but no `version` |
| Comment shape | A comment created as `{"comment": "..."}` comes back as `{id, comment, created_at, created_by}`. The volatile part is `id`, `created_at`, and `created_by`; `comment` is the author's text |
| `created_by` on Serverless | A bare numeric user id. It is identity and must be scrubbed from fixtures |
| Value-list data streams | `.lists-default` and `.items-default` do not exist by default. `POST /api/lists/index` creates them, `GET` reports `{list_index, list_item_index}`, `DELETE` removes them |
| Summary route | `GET /api/exception_lists/summary` returns `{windows, linux, macos, total}` |
| Item find envelope | `GET /api/exception_lists/items/_find?list_id=&namespace_type=&page=&per_page=` returns `{data, page, per_page, total}`, the same envelope as the list find. Paging works: `per_page=2` against 3 items returned 2 with `total: 3` |
| Container update | `PUT /api/exception_lists` updates by `list_id` alone. No `id` is required |
| Item update | `PUT /api/exception_lists/items` updates by `item_id` alone. No `id` is required |
| Item delete | `DELETE /api/exception_lists/items?item_id=&namespace_type=` returns the deleted item and leaves its siblings alone |
| Exception import | `POST /api/exception_lists/_import?overwrite=true` accepts an export file **including its trailer** and returns `{errors, success, success_count, success_exception_lists, success_count_exception_lists, success_exception_list_items, success_count_exception_list_items}` |
| **Exception export needs `id`** | `POST /api/exception_lists/_export` **requires the `id` query parameter**. `list_id` and `namespace_type` alone are a 400: `id: Invalid input: expected string, received undefined` |
| List find is filterable server-side | `GET /api/exception_lists/_find` accepts a KQL `filter` over the namespace's saved-object type: `exception-list.attributes.<field>` for `single` and `exception-list-agnostic.attributes.<field>` for `agnostic`. Measured against three sample lists: `type: detection` returned 2 of 3, `tags: alpha` returned 2 of 3, and a quoted `list_id` returned 1 |
| List `name` is keyword, not analyzed | `exception-list.attributes.name: "Probe"` (quoted token) returned 0 against a list named `elasticctl-sample Probe Exception List`, while `*Probe*` returned it (measured 2026-08-16). Name substring therefore needs the wildcard form, unlike the rules vertical's analyzed `name` |
| An empty filter is a 400 | Passing `filter=` with an empty value fails with `KQLSyntaxError: Expected "(", NOT, field name, value, whitespace but ")" found`. The parameter must be **omitted** when there is nothing to filter on, never sent empty |
| Multi-list export concatenates | Exporting two lists and joining the bodies gives six lines — list, item, trailer, list, item, trailer — with a trailer **per list**, interior to the file. `_import?overwrite=true` accepts it: `success_count: 4`, both containers and both items restored |
| `rule_default` lists are ordinary on the wire | `POST /api/exception_lists` with `"type": "rule_default"` creates one like any other container, and a rule references it through the same `exceptions_list` entry with `"type": "rule_default"`. Nothing about the route or the reference is special |

That last row matters to the mirror. Spec 5.4 writes a `rule_default` list inline
in its owning rule's file, and the obvious worry is that `push` could not put one
back — making `pull` produce a mirror `push` rejects. It can: the container is
created exactly like a `detection` list, before the rule that points at it, in
the same containers-then-items-then-rules order. The inlining is a layout choice
about where the object is written, not a claim that the object is unrestorable.

The interior trailers matter to `decode_bundle`, which keeps the last trailer it
sees. For a multi-list export that means `Bundle.summary` describes only the
final list, and the earlier counts are lost. Nothing in 0.2 reads that summary
for a multi-list export, so it is recorded rather than fixed — but a future
caller that trusts `summary` to describe the whole file would be wrong, and the
decoder should grow a `Vec<ExportSummary>` before anyone does.

The prefixes differ from the rules vertical, which filters on
`alert.attributes.<field>`. Each exception namespace also has its own
saved-object type. A client that reuses the `single` prefix for an explicit
`agnostic` lookup receives `This type exception-list is not allowed`.

The empty-filter 400 is worth stating because it fails in the direction that
looks like working code: a caller that builds a filter string by joining
clauses and always sends it works perfectly under every filter and breaks on the
unfiltered case, which is the default path.

That last row is the fourth place this API disagrees with itself about
exception-list identity, and it points the opposite way from the rest. Rules
export and rules import both resolve a list by `list_id` and ignore `id`;
container and item *updates* work by `list_id` and `item_id` with no `id` at
all; but exception-list export refuses to run without the volatile `id`.

The consequence for this client is concrete: `exceptions export` cannot be
served from a `ListKey` alone. It must resolve each key to the live container
`id` first and pass both. That resolution is the same lookup `push` already
performs for the opposite reason, so the two share one code path — identity
stays `list_id` plus `namespace_type` everywhere in this tool, and the `id` is
fetched at the boundary where a route demands it.

The export result trusts its trailer counts, not the keys resolved before the
request. A container can disappear between resolution and export; only the
server's `missing_exception_lists` and exported-count trailer describes what
the export actually produced.

`rules import` preserves the complete exported bundle and re-resolves each
reference by `list_id`. Before upload it supplies a schema-valid placeholder
for a known exception reference whose volatile `id` was stripped from disk;
the server replaces that pointer with the target container's id. Export and
import are therefore a correct cross-stack promotion path. `state push` writes
through the rules API directly and is the only path that must resolve `list_id`
on its own.

Value lists are referenced from an exception entry by a caller-supplied `id`
that is stable across stacks, so such an entry round-trips without resolution.
Their *content* is data rather than configuration and is not managed here.
When the data streams exist, `push` verifies each active referenced value-list
`id` and reports every missing one; it does not rely on a coarser list-level
lookup. `doctor` reports whether the data streams are bootstrapped.

### 7.8 Prebuilt rules, measured

Same project, same date.

| Fact | Detail |
|---|---|
| Public status route | `GET /api/detection_engine/rules/prepackaged/_status` returns 200 with `rules_installed: 2066`, `rules_custom_installed: 0`, `rules_not_installed: 0`, `rules_not_updated: 0`, and three timeline counters |
| Public install route | `PUT /api/detection_engine/rules/prepackaged` returns 200 with `{rules_installed, rules_updated, timelines_installed, timelines_updated}`. It installs and updates in one call and takes no selection |
| The install route ignores its body | `PUT .../prepackaged` returns the same 200 whether sent an explicit `null` body or no body at all. The transport has no bodyless PUT, so the client sends `null`; this records that the route does not care |
| No `dry_run` | The route has no dry-run parameter, so the guard preview is computed from `_status` |
| Internal routes unavailable | `/internal/detection_engine/prebuilt_rules/status` answers 400, `exists but is not available with the current configuration` |
| Customization is filterable | `params.ruleSource.isCustomized` splits 0 / 2,066. A prebuilt rule carries `rule_source: {type, is_customized, customized_fields, has_base_version}` |
| `immutable` agrees with `ruleSource.type` | 2,066 / 0 under either field |

### 7.9 ES|QL async query, measured

Same project, 2026-08-16.

| Fact | Detail |
|---|---|
| `format` is rejected | `POST /_query/async` returns 400 `unknown field [format]` for a `format: csv` body |
| `columnar` is accepted | `columnar: true` works on the async route, so CSV export is a client-side transpose of the columnar response, not a raw server CSV |

## 8. Testing

| Tier | Runs | Covers |
|---|---|---|
| Unit | Always, no I/O | Normalization, codecs, rule round-trip, config precedence, error classification |
| Fixture | Always, offline | Full command paths against `wiremock` replaying recorded exchanges, plus `assert_cmd` and, from 0.2, `insta` snapshots of rendered output |
| Live | `ELASTICCTL_LIVE=1 cargo test -- --ignored` | Real stack. The conformance check that catches API drift |

Fixtures are **recorded, not hand-written**. `cargo xtask record` drives a live
stack, dumps the real exchanges, and scrubs credentials, URL userinfo, and the
recording host in configured-authority and normalized-default-port forms,
using URL hostname case-insensitive matching. Each fixture records its
deployment flavor and stack version so drift is visible.

The status fixture removes the top-level instance `name`, deployment `uuid`,
and runtime `metrics` object. Product build fields under `version` remain as
the public capability evidence. Recorder progress and retry diagnostics use
static labels plus error class and HTTP status only; they never print a
server-provided message or response body.

Fixture scrubbing treats every configured recording authority as sensitive.
Matching is ASCII case-insensitive, including exact authorities in plain text.
For HTTP port 80 and HTTPS port 443, zero-padded forms included, the matching
bare host is also scrubbed. A non-default port never creates a bare-host alias.
Authority-safe boundaries prevent a configured host from being replaced inside
a longer hostname or `ops@example.com` text. URL token scanning recognises
commas, semicolons, quotes, parentheses, angle and square brackets, and
whitespace as delimiters; it consumes a complete bracketed IPv6 literal and
optional port before treating `]` as a delimiter. Userinfo is removed from
every URL token before the authority is replaced.

The directory is `tests/fixtures/<flavor>-<version>`, where flavor is the
*deployment* flavor, not the value a stack reports. Hosted and self-managed
both report `build_flavor: "traditional"`, so a Hosted recording would
overwrite the self-managed set. `ELASTICCTL_FIXTURE_FLAVOR` overrides the
derived name and tags fixtures at record time. Tagging them afterwards would
require editing recorded fixtures, which is never allowed.

### 8.1 Sample corpora

Rules and events are required to make a rule fire, but neither belongs in this
repository. `samples/` holds scripts that fetch them on demand. The repository
never vendors them:

- A slice of SigmaHQ/sigma Windows `process_creation` rules, converted to
  importable Kibana NDJSON by `sigma-cli` with the `lucene` target and the
  `ecs_windows` pipeline. Detection Rule License 1.1: redistribution requires
  the per-rule `author`, a link to the rule set, and the license text, which is
  why the harness fetches rather than commits.
- Three MIT-licensed OTRF Security-Datasets event sets. Their events use
  pre-ECS Winlogbeat field names, so a remap and a timestamp rewrite run before
  ingest — without them no rule can ever match.

`sbousseaden/EVTX-ATTACK-SAMPLES` is excluded: the repository carries no
license at all. `elastic/detection-rules` content is Elastic License v2 and is
never committed here.

### 8.2 CI and release preflight

CI runs on pushes to `master`, pull requests, the weekly schedule, and manual
dispatch. Every Cargo command that resolves or builds dependencies uses the
committed lockfile. The stable job runs formatting, Clippy, workspace tests,
and package-content checks. Package-content checks inspect every publishable
crate — `elasticctl-core`, `elasticctl-api`, and `elasticctl` — and fail if any
packages its integration tests or the private test-support crate. A separate
job reads
`workspace.package.rust-version` from `Cargo.toml` and checks every workspace
target with that exact toolchain. Windows runs the API state and transaction
regressions plus the full `elasticctl` package test suite, including raw export
and report-file paths. The fixture-leak job scans recorded exchanges for
credentials and project identity.

Before a version tag, the exact `master` commit must pass CI and the manually
dispatched release-preflight workflow. Preflight runs
`cargo publish --workspace --dry-run --locked` from a clean checkout with
read-only repository permission. It receives no crates.io credential and
uploads no crate.

The live tier remains opt-in. Run applicable live conformance before releases
that change live behavior; a release limited to tests, documentation, and
release tooling does not need it.

### 8.3 Cross-flavor live conformance

The target-neutral release-evidence entrypoint is:

```bash
cargo xtask conformance --flavor <serverless|ech|traditional> \
  --report-dir <path>
```

It runs the same nine contracts serially against each target: diagnostics,
pull-then-diff stability, exception CRUD and bundle round-trip, stale-pointer
repair, source scoping, rule export/import round-trip, search, triage
(`elasticctl-triage-design.md` section 9), and content transfer
(`elasticctl-content-design.md` section 13). Before the first mutation, it
captures custom, prebuilt, and customized rule counts, the exact default data
view, and all marker partitions. It refuses a target with existing live-marker
objects. It checks marker cleanup and default stability after every contract,
then compares the final state with that baseline. Dashboard marker capture is
gated below the verified dashboard floor so the content contract can report an
explicit capability skip; every other required baseline route fails closed.

An ordinary contract failure is valid 0.2.3 evidence when cleanup succeeds. A
cleanup, harness, or baseline failure invalidates the run and blocks further
mutation on that target. A capability skip is explicit: it names the
unsupported feature and the verified 9.5.1 floor.

The runner writes one deterministic JSON report per target only after the
final cleanup audit. The only allowed keys are `flavor`, `version`,
`contracts`, `contract`, `result`, and `error_class`. Raw output stays under
the ignored `target/conformance-private/` directory. Reports never contain a
target URL, deployment or account identifier, credential, location, user
identity, live object content, or raw failure.

The release matrix is Elastic Cloud Serverless, Elastic Cloud Hosted, and a
disposable self-managed 9.5.1 lab. The Cloud targets come from ignored local
configuration. The lab installs its complete prebuilt pack before baseline
capture and is destroyed with its volumes after the run.

`cargo xtask conformance-matrix --report-dir <path> [--flavors
serverless,ech,traditional]` runs this release matrix as three concurrent
child processes of the same `xtask` binary instead of three sequential
invocations. The three flavors are independent targets: proving serverless
correctness never depends on the state of Elastic Cloud Hosted or the local
lab, so nothing forces them to run in turn. Before spawning any leg, the
runner builds the `live` integration test binary once (`cargo test --locked
--test live --no-run`) in the workspace root; without this, the three
children's own `cargo test` invocations would race to compile that binary and
serialize behind Cargo's workspace build lock, stalling exactly the
concurrency this command exists to provide.

The self-managed leg boots `lab/up.sh` alongside the other two legs, since its
boot dominates the combined wall clock. Once it succeeds, the leg mints its
own Elasticsearch API key against the lab's bootstrap user rather than
parsing `up.sh` output, then uses the same shared prebuilt convergence helper
as `cargo xtask seed`. A fresh lab boots with no rules, and `lab/down.sh`
always destroys the previous session's volumes, so `source_scoping` would
otherwise have nothing to partition. Each logical cycle sends one exact,
one-shot `PUT .../prepackaged` body `{}`, then GETs prepackaged status. Success requires
all four outstanding counters — `rules_not_installed`, `rules_not_updated`,
`timelines_not_installed`, and `timelines_not_updated` — to be present,
non-negative integers, and zero. A false status starts another cycle. The GET
retains the normal read-only transport retry policy, but each PUT is one-shot;
PUT, terminal GET, or schema failure stops immediately. Five PUTs is the strict
actual-mutation budget. The 2026-09-02
fresh-lab check proved one PUT can leave the pack noncurrent, so the PUT
response never proves convergence. Exhaustion fails at this named step without
putting a raw status in public output. The leg then activates a Kibana user
profile by logging in as the lab's bootstrap user
(`POST /internal/security/login`, `elasticctl-triage-design.md` section 9),
since the lab boots headless with no browser session ever logging in and the
`triage` contract's assign/unassign step needs one activated profile to
resolve; Serverless and Hosted already carry one from the operator's own SSO
login. Only then does it run the conformance child, with
`ELASTICCTL_SPACE=default`. This whole boot-through-conformance
sequence races against Ctrl-C, and either outcome — completion or
interruption — is followed by `lab/down.sh`, which also covers a plain panic
anywhere in the sequence. Because `lab/down.sh` runs `compose down -v`,
starting the traditional leg destroys any `lab/` session already up on this
machine, including its volumes, whether or not this run started it. Once
that race resolves, the runner immediately arms a fresh interrupt listener
that exits the process outright, so a later Ctrl-C — for example while a
sibling flavor is still running — still terminates the run instead of being
silently swallowed by the OS's now-replaced default disposition.

`lab/up.sh` and `lab/down.sh` output is never streamed live: `up.sh` prints a
plaintext superuser-derived API key in its final summary block. Both scripts'
output is instead captured to a private, redacted log under
`target/conformance-private/traditional/`, with any line naming
`ELASTICCTL_API_KEY=` blanked before it is written; the matrix prints only a
short public status line per script.

The Hosted leg maps `ELASTICCTL_ECH_*` onto the generic `ELASTICCTL_*` names
the child expects, including `ELASTICCTL_ECH_SPACE` (defaulting to
`"default"`), and fails before spawning anything if a required piece is
missing. When `ELASTICCTL_ECH_USERNAME` and `ELASTICCTL_ECH_PASSWORD` are
both set and non-empty, it also activates that user's profile first, the
same step and code path the self-managed leg runs at boot; without the pair
it relies on whatever profile the deployment already carries from an
operator's own SSO login, and the `triage` contract's own empty-profile
check stays the backstop. `--flavors` accepts a comma-separated subset of the three names,
trimmed and de-duplicated; an unknown or repeated name is rejected. Recording
(`cargo xtask record`), unlike conformance, must never run concurrently: one
recording session owns the marker objects on one live stack, and a second
session recording that stack at the same time would race that ownership.

The 0.2.3 measured matrix is:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 6 pass | Verified | [report](../conformance/v0.2.3/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 6 pass | Verified | [report](../conformance/v0.2.3/ech-9.5.1.json) |
| Self-managed | 9.5.1 | 6 pass | Verified | [report](../conformance/v0.2.3/traditional-9.5.1.json) |

All 18 contract rows passed with no skip. The validated
[findings](../conformance/v0.2.3/findings.md) therefore justify no live defect,
while a later static review justified the bounded 0.2.4 patch; the 0.3.0 search
design is the next capability-area work.

The 0.3.1 measured matrix adds the `search` contract; all seven pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 7 pass | Verified | [report](../conformance/v0.3.1/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 7 pass | Verified | [report](../conformance/v0.3.1/ech-9.5.1.json) |
| Self-managed | 9.5.1 | 7 pass | Verified | [report](../conformance/v0.3.1/traditional-9.5.1.json) |

The 0.4.2 measured matrix adds the `triage` contract; all eight pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 8 pass | Verified | [report](../conformance/v0.4.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 8 pass | Verified | [report](../conformance/v0.4.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 8 pass | Verified | [report](../conformance/v0.4.2/traditional-9.5.1.json) |

## 9. Local lab

Serverless is the primary development target, so no local stack is needed day
to day. The `lab/` podman stack records self-managed fixtures. This prevents
v0.1 from shipping a Serverless-only tool under a three-flavor label.

`lab/compose.yaml` runs Elasticsearch and Kibana 9.5.1, single node, security
enabled, roughly 3 GB for the twenty minutes it is up.

Two required settings:

- Kibana needs `xpack.encryptedSavedObjects.encryptionKey` set to 32 or more
  characters. Without it the alerting framework cannot persist rule API keys
  and **every rule creation fails**, with an error that never mentions
  encryption.
- The detection engine needs its signals index bootstrapped through
  `POST /api/detection_engine/index` before rules will run.

Scripts: `lab/up.sh` (compose up, wait for green, set the `kibana_system`
password, bootstrap the signals index, start a 30-day trial license, mint an
API key, print a ready-to-paste `config init`), `lab/seed.sh` (provisions the
complete Elastic prebuilt pack for local rule-source tests; it does not install
sample events), `lab/down.sh`.

Lab certificates are self-signed, so profiles carry a `verify` field. Setting
`verify = false` prints a warning on every request. It cannot quietly become a
production habit.

## 10. Distribution

`cargo-dist` produces GitHub Releases for Linux gnu and musl (x86_64,
aarch64), macOS (x86_64, aarch64), and Windows x86_64, plus
`cargo install elasticctl`. Static musl supports locked-down Linux laptops.
macOS aarch64 is likely the common case. Add a Homebrew tap when there is demand.

The package builds two binaries from the same `src/main.rs` entrypoint:
`elasticctl`, the canonical name, and `elkctl`, a shorter alias. Both ship in
every archive and both install from `cargo install elasticctl`. Because they
compile from one entrypoint, the two surfaces cannot drift; the `commands`
JSON output is byte-identical between them. Help text and shell completions
follow whichever name invoked the process — `elkctl --help` and
`elkctl completion zsh` both name `elkctl`, never `elasticctl` — derived from
`argv[0]` at runtime, not from a compiled-in literal. `elasticctl` remains the
canonical name for the package, the crates, artifact names, error text, and
the `commands` JSON's own `name` field, which stays `"elasticctl"` regardless
of invocation so that field stays part of the byte-identical surface.
User-facing documentation and its command examples lead with `elkctl`.
`--version` follows the same
rule as that `name` field, not the help/completions rule: both binaries print
`elasticctl <version>`, the canonical name, regardless of which one was
invoked — only help usage text and completions follow `argv[0]`. Sharing one
entrypoint across two `[[bin]]` targets has a known, harmless build-time cost:
`cargo build`/`cargo install` print a "file present in multiple build
targets" notice for `src/main.rs`. It is a manifest-level Cargo notice, not a
lint — `cargo clippy -D warnings` does not see it and there is no way to
suppress it short of duplicating the entrypoint file.

## 11. Versioning

The project follows Cargo SemVer and stays in `0.x` until the command surface
settles. Under the `0.x` rule, the minor position is the breaking position.
Cargo implements this directly: `^0.1.2` resolves to `>=0.1.2, <0.2.0`, so
every `0.1.x` is compatible and `0.2.0` is a break.

Development is iterative — ship small, ship often.

- **Patch** (`0.1.1`, `0.1.2`, …) carries fixes and small additive changes
  *inside* the capability areas that already exist: a new flag on
  `rules list`, a new output field, a bug fix.
- **Minor** (`0.2.0`, `0.3.0`, …) marks a **new capability area** — `search`,
  `dashboards`, `cases`, `fleet` — or an actual break.

A minor bump is *required* when something breaks. It is not *restricted* to
breaks. Marking each new capability area with a minor bump tells users what the
tool can do.

The dividing line is scale, not novelty. A new flag on an existing command is
a patch. A whole new command group is a minor.

Manifests always carry three components: `version = "0.1.0"`, never `"0.1"`.

Planned shape. 0.2 is fixed; the order after it is not:

| Version | Capability area |
|---|---|
| `0.1` | Detection rules as code |
| `0.2` | Exceptions, prebuilt rules, and the `-api` retrofit |
| `0.3` | Search — ES\|QL and DSL |
| `0.4` | Alert triage and cases |
| `0.5` | Dashboards and data views |
| `0.6` | Fleet and agent policies |
| `0.7` | MCP server — read-only tools over the existing verticals |
| `0.8` | Task-shaped and cross-vertical tools; resources and prompts |
| `0.9` | Mutation through plan-and-confirm |
| `1.0` | Everything stable |

The 0.3 search capability area is specified in
[`elasticctl-search-design.md`](elasticctl-search-design.md). The 0.4 alert
triage and cases capability area is specified in
[`elasticctl-triage-design.md`](elasticctl-triage-design.md). The 0.5 dashboard
and data-view capability area is specified in
[`elasticctl-content-design.md`](elasticctl-content-design.md).

The temporary trial-deployment window changes execution order, not capability
boundaries. The near-term evidence ladder is:

1. 0.2.2 hardens locked CI, declared-toolchain proof, Windows smoke coverage,
   and non-publishing package preflight.
2. 0.2.3 runs the guarded 0.2 live contracts across Serverless, Hosted, and the
   self-managed 9.5.1 compatibility floor.
3. 0.2.4 ships the bounded post-release review patch: the boundary defects found
   by a static review of the post-0.2.3 codebase, each with a regression.
4. 0.3.0 delivers the complete ES|QL and Query DSL search vertical.
5. 0.3.1 publishes the search conformance matrix and completes the deferred
   search items: ES|QL export payload, DSL hit metadata, and object search
   (`--search` and substring name matching) over rules, exceptions, and state.
6. 0.4.0 and 0.4.1 deliver alert triage and cases; 0.4.2 publishes their
   cross-flavor proof and bounded review patch.
7. 0.5.0 delivers complete data-view administration and transfer; 0.5.1 adds
   typed dashboard administration plus opaque dependency bundles; 0.5.2
   publishes the content matrix and bounded review patch.

Later minor capability areas begin only after the current area is complete.
The trial window still prioritizes live 0.5 measurements before 2026-09-08
08:56 UTC; it does not weaken a release gate.

The privacy, cleanup, evidence, and release gates for this sequence are defined
in §8.3, §11.2, and §12.

MCP holds its own band rather than landing at 1.0, because a 1.0 that
introduces the MCP server would declare the surface stable in the same release
that adds the least-proven code in the project. Three minors rather than one
because they are three capability areas, not one iterated three times: 0.7
proves the transport and the layering, 0.8 is where tools stop mirroring
commands and start mirroring questions, and 0.9 answers what consent means when
the caller is a model. That last one stands alone deliberately —
`--yes` has no honest MCP analogue, and a model choosing to pass it is the
failure the guard exists to prevent. Room past 0.9 is expected; if 0.8 shows the
tools want reshaping, that is a fourth area, not a reason to compress.

### 11.1 What counts as breaking

SemVer is written for library consumers, but users depend on elasticctl's CLI
surface, not its Rust types. The CLI surface is the public API that the version
number describes.

Breaking, requiring a minor bump:

- Renaming or removing a command, subcommand, or flag
- Renaming or removing a field in `--json` output
- Changing or removing an error `kind` value
- Changing an exit code's meaning
- Changing the on-disk rule format in a way older files cannot round-trip

Additive, allowed in a patch release: new commands, new flags with defaults,
new fields in JSON output, new error kinds for previously unclassified
failures.

0.2 breaks two things under this list. The state commands default to
`--source custom` instead of the whole space, and the `diff` report gains an
`exceptions` block whose presence narrows what `clean` asserts. Both are named
in the changelog beside the flag that restores the previous behavior. The
mirror layout also grows a directory, but an 0.1 mirror still round-trips: a
tree with no `exceptions/` describes a corpus with no exception lists, which is
what it was.

### 11.2 Publishing

One shared workspace version, so all three crates move together.

All three crates are publishable and publish together with
`cargo publish --workspace`. It packages and verifies every crate against a
temporary registry before uploading any. Otherwise, a failure partway through
could strand a crate on crates.io, where a version can be yanked but never
deleted. `xtask` stays `publish = false`; it is a dev tool and ships nothing.

`elasticctl-api-test-support` remains private and unpublished. The published
`elasticctl-api` and `elasticctl` manifests exclude `tests/**`, because Cargo
cannot resolve those integration tests after it omits their path-only private
dev-dependency from the package. Inline unit tests under `src/` remain in the
archives. `scripts/check-packages.sh` runs the locked, allow-dirty
`cargo package --package <name> --list` check separately for those two crates.
It rejects every `tests/` entry and every `elasticctl-api-test-support` path,
and requires `Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, plus `src/lib.rs`
for the API crate or `src/main.rs` for the CLI crate. Cargo's package list is
the archive-content authority for this release gate.

Publishing was deferred through 0.1.2 because a crates.io version is forever
while a tag costs nothing. Publishing `elasticctl-core` and `elasticctl-api`
would also make their Rust APIs a contract while those boundaries still moved.
0.1.3 claimed the three names and proved the path.

**Publishing is not part of a release.** A release ends at the tag and the
GitHub Release binaries. Putting a version on crates.io is a separate step
needing the owner's explicit approval for that version, and approval never
carries forward from a previous one. The reason is the asymmetry rather than
any doubt about the crates: a withheld version can still be published
tomorrow, while a published one can only be yanked — hidden from resolution,
never removed. Where one direction is recoverable and the other is not, the
default belongs on the recoverable side and the irreversible step is taken
deliberately, per version.

The original deferral is nonetheless dropped, because its central cost is
already accounted for.
Under Cargo's `0.x` rules, the minor position is the breaking position, so
`0.1.x` → `0.2.0` is a break a consumer must opt into. Section 11 already
bumps the minor for every new capability area. The crate boundaries can move as
much after publishing as before.

Name ownership does not reverse. All three names were unclaimed, and anyone can
claim a name until it is taken. That cost cannot be recovered, unlike a bad
version, which can still be yanked.

Publishing runs *after* the tag, because it is the only irreversible step in a
release. A tag and a GitHub Release can be deleted; a crates.io version can
only be yanked, and yanking hides a version from resolution rather than
removing it. Tagging first has the binary matrix prove the build while both the
tag and the Release are still disposable, which is the check a release
candidate used to buy separately.

All three publish or none do. The binary crate depends on both libraries by
version, so publishing it alone leaves `cargo install elasticctl` unable to
resolve.

## 12. Credentials in this repository

Development credentials live in `.env`, which is gitignored and has mode `0600`.
`.env.example` is committed and contains placeholders only. The Elastic key in
use is a **project-scoped** serverless key: it authenticates API calls but
cannot create, list, or resize projects. Managing projects and deployments
needs an organization key with Cloud API access, created in the Cloud console
under Organization > API keys, against `api.elastic-cloud.com`.

All three key types carry the `essu_` prefix; the console offers no other. The
prefix therefore identifies nothing. Only `GET /_security/_authenticate`
reports the realm, which is the discriminator.

Provisioning a Hosted deployment through the Cloud API does not currently work
for this organization. `GET /deployments/templates` serves a catalogue whose
every entry `POST /deployments` rejects as `legacy_dt`. The result is the same
for two organization keys and for the documented `template_id` query parameter,
which has the server expand the template. No AWS region resolves for Hosted
templates. The console creates the same deployment without complaint, so Hosted
deployments are created there and driven by API afterwards, which works normally.

## 13. Risks

**Serverless-first bias — resolved.** Serverless is the most divergent of the
three flavors — no license tiers (features gate on project tier instead),
different auth, and some endpoints versioned differently. Developing only
against it risks baking Serverless assumptions into code that claims to support
self-managed. The mitigation is fixture tagging by flavor and version,
capability-gated divergent behavior, and recordings for each flavor.

All three flavors now have 29 fixtures: `serverless-9.6.0`,
`traditional-9.5.1`, and `ech-9.5.1`. Coverage is even, so no flavor is least
tested. Each set records custom and prebuilt `immutable` filters against the
same probe rule and proves their totals sum to the unscoped total. The two
9.5.1 sets therefore establish the rule-source compatibility floor; older
versions remain unsupported until an equally complete recording lowers it.

Both halves of the Hosted signal are now measured, not inferred. Every set
records response headers: `traditional-9.5.1` has headers but lacks
`x-found-handling-cluster`, and the other two include it. The self-managed
recording also closed the last open question about `rules preview`, which had
previously been exercised only against Serverless.

**`rules preview` stability — resolved.** The concern was that the preview
endpoint has moved between public and internal paths across Elastic versions.
Measured on Serverless 9.6.0: `POST /api/detection_engine/rules/preview` is
public and returns 200 with a `previewId` and a `logs` array carrying per
execution `errors` and `warnings`. The internal path returns 404.

`elastic-api-version` must be a date string. `1` and `2` are both rejected
with "Invalid version. Received \"1\", expected a valid date string". Internal
Kibana routes are versioned numerically, which is a second reason they are
unreachable here. `2023-10-31` is the only version this client needs.

The command stays in 0.1.0 and off the trim line. It is now also confirmed on a
self-managed stack: `traditional-9.5.1` carries recorded `rules_preview` and
`rules_preview_hits` fixtures.

**Empty project — resolved.** The serverless development project now holds
2,066 prebuilt Elastic rules covering all seven rule types, seeded for scale
testing. Measured against them, `state pull` writes 2,066 files in ~8.4 s, a
second pull is byte-identical, `state diff` reports zero drift, and export
round-trips every type exactly. They are read-only ground truth. A live test
never mutates an untagged rule; every object it creates carries the
`elasticctl-sample` marker, and a run ends by verifying that the project is
back to that baseline.

**A large retrofit shipped beside two new capability areas — mitigated by
ordering.** 0.2 moves 1,528 lines of orchestration into `-api` in the same
release that adds exceptions and prebuilt rules. The mitigation is sequence and
evidence rather than care: the retrofit lands first as its own wave, and
snapshot tests prove every existing command renders byte-identically before any
0.2 feature is written. If the rest of 0.2 runs long, the retrofit ships alone.

**Fact G — runtime exception identity — resolved.** Measured on Serverless
9.6.0 on 2026-08-15: a matching exception suppressed the test event with both
the live pointer and a zero UUID pointer, producing zero preview hits in each
case. Runtime exception lookup therefore follows `list_id` on the measured
stack; the stored `exceptions_list[].id` is not its runtime discriminator.

`diff` still reports the stale pointer and `push` repairs it, so a mirror
converges on the target stack's current saved-object id. The same serialized
live test deletes the exception container, imports the exported rule bundle,
and proves that import rewrites the upload placeholder to the recreated
container's live id. This behavior needs a rule that fires against a real
stack, so it remains live conformance rather than a recorded response fixture.
