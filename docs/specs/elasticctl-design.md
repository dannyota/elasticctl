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

Out of scope for v0.1 (additive later): exceptions, prebuilt rule management,
alert triage, cases, Fleet and agent policies, ad hoc search, and the MCP
server.

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
considered and set aside in favour of NDJSON for round-trip fidelity, with
YAML covering human review.

## 3. Architecture

**Command functions return typed values; a separate render layer turns them
into text.** splunkctl generates MCP tools by reflecting over its Click tree.
Its callbacks print through `click.echo`, and the MCP runner captures stdout.
Rust commands that print directly would leave an MCP server only a string to
parse again. Typed values let a future MCP crate call the same functions and
serialize the same structs.

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
**Command orchestration belongs in `-api`, returning typed structs; `cli/cmd/`
parses arguments, calls one API function, and hands the result to render.**
Measured on 2026-08-14, v0.1 does not meet this: 1,528 lines of orchestration
live in `cli/src/cmd/`, and 18 of 23 command functions return
`serde_json::Value` rather than a struct. `Drift::compute` is correctly in
`-api`; the code that resolves a selection, loads a directory, and builds a
report is not.

The rule applies to new work from 0.2. Retrofitting the rules vertical is
deferred to the MCP phase, where it is one vertical rather than six. The cost
of ignoring it is not a redesign — it is the same mechanical refactor, priced
per capability area.

### 3.1 elasticctl-core

Does not know about detection rules.

- **`config`** — profiles in `~/.elasticctl/config.toml`, `0600` enforced on
  write and warned on read. Resolution order: flags → environment
  (`ELASTICCTL_*`) → profile → defaults. Returns the effective config *and its
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
  `--debug` line.
- **`auth`** — `ApiKey` (`Authorization: ApiKey <base64(id:key)>`) or `Basic`.
  API key is the default; basic auth exists for the local lab.
- **`transport`** — `reqwest` with `rustls` on `tokio`. Injects `kbn-xsrf: true`
  on every non-GET request, `elastic-api-version` where required, and prefixes
  space-scoped paths as `/s/<space>/api/...`. Retries with backoff on 429 and
  5xx only, never on 4xx.
  Under `--debug` it logs one line before each request is sent and one on every
  outcome, including timeout and connection errors. Those are the cases an
  operator uses `--debug` to diagnose. It logs method, URL, and status only;
  it never logs a header or body.
  Response headers are captured and returned alongside the body, because the
  deployment flavor is not derivable from any response body — see
  `capabilities` below. They are carried, never logged: `--debug` still prints
  no header because headers carry credentials.
- **`capabilities`** — one probe at connect time reading `GET /api/status`.
  Yields `Capabilities { flavor, version }`. Commands consult it and return a
  typed `Unsupported` error naming the flavor instead of a confusing 404.
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
  reached through a proxy that strips the header. It is not normally needed.
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
- **`rules`** — typed endpoint wrappers returning
  `elasticctl_core::Result<T>`. They never print. Later verticals (exceptions,
  cases, fleet) add sibling modules without touching this one.

### 3.3 elasticctl-cli

`clap` v4 derive. Command functions call `api` and return typed values;
`render` produces table, json, yaml, csv, or jsonl. `guard` implements the
dry-run contract.

## 4. Command surface (v0.1)

```
elasticctl config init --from-env            Create a profile from ELASTICCTL_* vars
elasticctl config list | show | test         Inspect profiles; secrets always redacted
elasticctl doctor                            Configuration, connectivity, flavor, auth, key scope, rule access
elasticctl info                              Stack version, flavor, license tier, spaces

elasticctl rules list                        --enabled/--disabled --type --severity --tag --filter
elasticctl rules get <name|rule_id>
elasticctl rules validate --path FILE        Local schema check, no server contact
elasticctl rules enable  <name|rule_id>...   [guarded]
elasticctl rules disable <name|rule_id>...   [guarded]
elasticctl rules delete  <name|rule_id>...   [guarded]
elasticctl rules export [<name|rule_id>...] [--tag TAG] [--out FILE] [--format-file ndjson|yaml]
elasticctl rules import --path FILE [--overwrite | --skip-existing]  [guarded]
elasticctl rules preview <file|name|rule_id> [--invocations N] [--sample N]

elasticctl state pull [<name|rule_id>...] [--tag TAG] --dir config/ [--format-file ndjson|yaml]
elasticctl state diff [<name|rule_id>...] [--tag TAG] --dir config/  Field-level structured drift
elasticctl state push [<name|rule_id>...] [--tag TAG] --dir config/ [--report FILE]  [guarded]

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands                          Machine-readable command tree
```

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

## 5. State engine

- **`pull`** — read the corpus through `_find`, map to `Rule`, normalize, write
  the tree in the requested format. Filenames are planned for every rule before
  the first file is written. A `rule_id` pair that sanitises to one filename is
  refused with `conflict`, naming **every** colliding pair at once, before the
  directory is created. Reporting one collision per run hides the next until a
  re-run. Writing files up to a collision leaves a mirror that is neither the
  old state nor the new one.
- **`diff`** — read local, fetch remote, normalize both, emit field-level
  drift. NDJSON lines are not readable by eye, so `diff` is the human view and
  `git diff` is the fidelity record.
- **`push`** — read local, compute the diff, apply each change through the
  guard, then write a change-evidence report of per-rule before and after
  values plus an applied flag, suitable for attaching to a change ticket.

`push` **never deletes remote rules.** A rule missing locally is not a delete
instruction. Deletion is always the explicit `rules delete`.

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
filter as `rules export`, described in 4.3. Given neither, they act on the
whole space. This existing behavior remains the default.

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

## 6. Contracts

### 6.1 Safety

Every mutation previews before it applies.

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

Exit codes: `0` success, `1` error, `2` usage.

## 7. Verified API facts

Probed against Elastic Cloud Serverless Security project `elasticctl-f0d4d3`
(aws, ap-southeast-1) on 2026-08-13. Elasticsearch and Kibana both 9.6.0,
`build_flavor: serverless`.

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

**Volatile — strip before diffing (7):** `id`, `created_at`, `created_by`,
`updated_at`, `updated_by`, `revision`, `version`.

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
realm `_es_api_key` rather than `_cloud_api_key`, and every mutation path works.
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

Probed against a Hosted deployment in `gcp-asia-southeast1`, Elasticsearch and
Kibana both 9.5.1, on 2026-08-13. The full fixture set is recorded under
`tests/fixtures/ech-9.5.1`.

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

## 8. Testing

| Tier | Runs | Covers |
|---|---|---|
| Unit | Always, no I/O | Normalization, codecs, rule round-trip, config precedence, error classification |
| Fixture | Always, offline | Full command paths against `wiremock` replaying recorded exchanges, plus `assert_cmd` and `insta` snapshots of rendered output |
| Live | `ELASTICCTL_LIVE=1 cargo test -- --ignored` | Real stack. The conformance check that catches API drift |

Fixtures are **recorded, not hand-written**. `cargo xtask record` drives a live
stack, dumps the real exchanges, and scrubs credentials. Each fixture records
its deployment flavor and stack version so drift is visible.

The directory is `tests/fixtures/<flavor>-<version>`, where flavor is the
*deployment* flavor, not the value a stack reports. Hosted and self-managed
both report `build_flavor: "traditional"`, so a Hosted recording would
overwrite the self-managed set. `ELASTICCTL_FIXTURE_FLAVOR` overrides the
derived name and tags fixtures at record time. Tagging them afterwards would
require editing recorded fixtures, which is never allowed.

CI runs unit and fixture tiers on every push; the live tier runs on a schedule
and before releases.

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
API key, print a ready-to-paste `config init`), `lab/seed.sh` (sample rules and
a small event dataset so `rules preview` has data), `lab/down.sh`.

Lab certificates are self-signed, so profiles carry a `verify` field. Setting
`verify = false` prints a warning on every request. It cannot quietly become a
production habit.

## 10. Distribution

`cargo-dist` produces GitHub Releases for Linux gnu and musl (x86_64,
aarch64), macOS (x86_64, aarch64), and Windows x86_64, plus
`cargo install elasticctl`. Static musl supports locked-down Linux laptops.
macOS aarch64 is likely the common case. Add a Homebrew tap when there is demand.

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

Planned shape, order not yet fixed:

| Version | Capability area |
|---|---|
| `0.1` | Detection rules as code |
| `0.2` | Search — ES\|QL and DSL |
| `0.3` | Alert triage and cases |
| `0.4` | Exceptions and prebuilt rule management |
| `0.5` | Dashboards and data views |
| `0.6` | Fleet and agent policies |
| `0.7` | MCP server — read-only tools over the existing verticals |
| `0.8` | Task-shaped and cross-vertical tools; resources and prompts |
| `0.9` | Mutation through plan-and-confirm |
| `1.0` | Everything stable |

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

### 11.2 Publishing

One shared workspace version, so all three crates move together.

All three crates are publishable and publish together with
`cargo publish --workspace`. It packages and verifies every crate against a
temporary registry before uploading any. Otherwise, a failure partway through
could strand a crate on crates.io, where a version can be yanked but never
deleted. `xtask` stays `publish = false`; it is a dev tool and ships nothing.

Publishing was deferred through 0.1.2 because a crates.io version is forever
while a tag costs nothing. Publishing `elasticctl-core` and `elasticctl-api`
would also make their Rust APIs a contract while those boundaries still moved.
From 0.1.3, a release publishes to crates.io as well as tagging.

The deferral is dropped because its central cost is already accounted for.
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

All three flavors now have 14 fixtures: `serverless-9.6.0`,
`traditional-9.5.1`, and `ech-9.5.1`. Coverage is even, so no flavor is least
tested.

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
