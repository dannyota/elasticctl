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

v0.1 delivers a foundation layer plus one vertical: **detection rules as
code**.

Out of scope for v0.1, additive later: exceptions, prebuilt rule management,
alert triage, cases, Fleet and agent policies, ad-hoc search, and the MCP
server.

## 2. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Language | Rust 2024, stable toolchain | Single static binary per platform, no runtime for the user to install |
| Deployment targets | Self-managed, Elastic Cloud Hosted, Serverless | Security engineers are on all three |
| Flavor handling | Runtime capability probe | ~90% of the detection-rules API is identical across flavors; the differences are auth, headers, and feature availability |
| First vertical | Detection rules as code | Highest daily value for a detection engineer; the API is stable across all three flavors |
| On-disk rule format | NDJSON **and** YAML | NDJSON round-trips Kibana's export/import exactly; YAML is what a human reviews |
| Credentials | Config file at `0600` | Portable across Linux, macOS, WSL, headless, and CI; no keyring dependency |
| Testing | Recorded fixtures plus opt-in live suite | Fixtures encode what Elastic actually sent, not what we assumed |
| Primary dev target | Serverless project | Nothing needs to run locally; the local lab becomes an occasional recording session |

### 2.1 Why not the alternatives

**Trait-per-flavor** (`SelfManaged` / `Ech` / `Serverless` behind a trait) was
rejected. The flavors barely diverge on the detection-rules API, so it would
mean three near-identical implementations maintained in triplicate.

**A single flat crate** mirroring splunkctl's layout was rejected because
nothing structurally prevents `clap` types leaking into command logic, and
that leak is precisely what makes adding MCP expensive later.

**TOML one-file-per-rule** (Elastic's own `detection-rules` convention) was
considered and set aside in favour of NDJSON for round-trip fidelity, with
YAML covering human review.

## 3. Architecture

The rule that decides the structure: **command functions return typed values;
a separate render layer turns them into text.** splunkctl can generate MCP
tools by reflecting over its Click tree because Click callbacks print through
`click.echo` and the MCP runner captures stdout. Rust commands that print
directly would give an MCP server nothing but a string to re-parse. Returning
typed values means the future MCP crate calls the same functions and
serializes the same structs.

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

### 3.1 elasticctl-core

Knows nothing about detection rules.

- **`config`** — profiles in `~/.elasticctl/config.toml`, `0600` enforced on
  write and warned on read. Resolution order: flags → environment
  (`ELASTICCTL_*`) → profile → defaults. Returns the effective config *and its
  provenance*, so the guard banner can name which profile is about to be
  mutated.
  `kibana_url` and `es_url` are both identity: on a Cloud deployment they are
  two hosts of one stack, and on self-managed `es_url` is absent and the Kibana
  host serves both. They resolve together. An environment or flag override of
  one without the other does not inherit the profile's value for the other —
  overriding `kibana_url` alone clears `es_url` rather than keeping a host
  belonging to a different deployment, because inheriting it would aim one
  client at two stacks and send the overridden credential to the host the
  operator did not name.
  Any `user:password@` prefix in `kibana_url` or `es_url` is stripped at
  resolution and before a profile is written. Credentials come from `api_key`
  or `username`/`password`; a URL has never been an authentication channel
  here, and one carrying userinfo would surface in the guard banner and in
  every `--debug` line.
- **`auth`** — `ApiKey` (`Authorization: ApiKey <base64(id:key)>`) or `Basic`.
  API key is the default; basic auth exists for the local lab.
- **`transport`** — `reqwest` with `rustls` on `tokio`. Injects `kbn-xsrf: true`
  on every non-GET request, `elastic-api-version` where required, and prefixes
  space-scoped paths as `/s/<space>/api/...`. Retries with backoff on 429 and
  5xx only, never on 4xx.
  Under `--debug` it logs one line before each request is sent and one on every
  outcome, including the timeout and connection-error branches — the cases an
  operator reaches for `--debug` to see. Method, URL, and status only: never a
  header, never a body.
  Response headers are captured and returned alongside the body, because the
  deployment flavor is not derivable from any response body — see
  `capabilities` below. They are carried, never logged: `--debug` still prints
  no header, since headers are where credentials travel.
- **`capabilities`** — one probe at connect time reading `GET /api/status`.
  Yields `Capabilities { flavor, version }`. Commands consult it and return a
  typed `Unsupported` error naming the flavor rather than surfacing a confusing
  404.
  Flavor is decided in this order, and the order is load-bearing:

  1. `version.build_flavor == "serverless"` → Serverless.
  2. The response carries `x-found-handling-cluster` → Elastic Cloud Hosted.
  3. Otherwise → self-managed.

  Elastic Cloud Hosted reports `build_flavor: "traditional"`, the same value a
  self-managed stack reports, so no field of the status body separates them.
  The distinguishing signal is a header injected by the Cloud edge proxy, which
  a self-managed Kibana has nothing to add. Serverless sits behind that same
  proxy and carries the same header, which is why the `build_flavor` test comes
  first: reversing the two would classify every Serverless project as Hosted.
  Hostname matching against known Cloud suffixes remains as a last resort for a
  deployment reached through a proxy that strips the header, but it is no
  longer how the answer is normally obtained. Spaces and licence tier are *not* part of that probe: they cost a request
  each, and `doctor` and `config test` need neither. `info` probes them
  directly — the space list from `GET /api/spaces/space`, the licence tier from
  `GET /_license`, which does not exist on Serverless — and reports `null` for
  either when it cannot be determined, rather than reporting a hardcoded value
  that happens to be right on one flavor.
- **`errors`** — `thiserror` enums classified at one point into the taxonomy
  below.

### 3.2 elasticctl-api

- **`model::Rule`** — canonical representation covering query, eql, esql,
  threshold, threat_match, machine_learning, and new_terms rule types.
  `serde` with `#[serde(flatten)]` for type-specific fields so unknown fields
  survive a round-trip instead of being silently dropped.
- **`normalize`** — strips volatile server-side fields (`id`, `created_at`,
  `updated_at`, `created_by`, `updated_by`, `version`, `revision`,
  `execution_summary`), sorts map keys, and orders rules by `rule_id`.
  Deterministic output is what makes `diff` trustworthy; without it every
  `pull` would report fake drift.
- **`codec`** — NDJSON (canonical, import-ready) and YAML (`serde_yaml_ng`;
  `serde_yaml` is unmaintained) over the same `Rule`. Handles Kibana's trailing
  `{"exported_count":N,...}` summary object as a trailer, not a rule.
- **`rules`** — typed endpoint wrappers. Every function returns
  `Result<T, ApiError>` where `T` is a struct. No printing, no `String`
  returns. Later verticals (exceptions, cases, fleet) add sibling modules
  without touching this one.

### 3.3 elasticctl-cli

`clap` v4 derive. Command functions call `api` and return typed values;
`render` produces table, json, yaml, csv, or jsonl. `guard` implements the
dry-run contract.

## 4. Command surface (v0.1)

```
elasticctl config init --from-env            Create a profile from ELASTICCTL_* vars
elasticctl config list | show | test         Inspect profiles; secrets always redacted
elasticctl doctor                            Connectivity, auth, identity, license, flavor
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

elasticctl state pull --dir config/ [--format-file ndjson|yaml]
elasticctl state diff --dir config/          Field-level structured drift
elasticctl state push --dir config/ [--report FILE]            [guarded]

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands                          Machine-readable command tree
```

### 4.1 Rule identity

Engineers think in names; the API has `rule_id` (a stable UUID) and `id` (a
volatile saved-object id). Commands accept either a name or a `rule_id`. A
`rule_id` is tried first; only when that misses does a name lookup happen, and
that lookup is a **single `_find` filtered server-side on
`alert.attributes.name`**, never a walk of the whole space. Walking cost 8.8
seconds against 2,066 rules just to report that nothing matched.

The returned candidates are still matched exactly client-side, so a name is
never resolved by prefix or substring, and a non-unique name returns a typed
`conflict` error listing the candidates rather than silently picking the first
match. The candidate page is capped at 100; a name with more candidates than
that and no exact match reports that the search was capped rather than claiming
the name does not exist. A selector that matches neither an id nor a name is
reported as `No rule with rule_id or name '...'`, because reporting a missed
`rule_id` as a missed *name* points the operator at the wrong thing.

State matching is **always** by `rule_id` — never by name, never by `id`.

### 4.2 Global flags

Accepted before or after the subcommand: `--profile`, `--config`, `--space`,
`--json`, `--format`, `--fields`, `--out`, `--yes`/`-y`, `--timeout`,
`--debug`.

### 4.3 Export selection

`rules export` takes the same positional selectors as `enable`, `disable`, and
`delete` — a name or a `rule_id`, resolved the same way — and a `--tag` filter.
Given both, the union is exported. Given neither, the whole space is exported,
which is the historical behaviour and stays the default.

Selection is turned into the scoped export body `{"objects": [{"rule_id": ...}]}`
rather than filtered client-side, so a subset export transfers only the subset.

A selection that resolves to no rules is refused with `not_found` naming the
selector. It is never widened to "export everything": an empty selection
silently meaning "all" is the same failure mode an unscoped bulk action would
be. A `--tag` that matches no rules is refused the same way, naming the tag,
even when a selector also resolved: a typo'd tag otherwise disappears into the
union and the command reports a short export as a success.

A rule deleted between selection and export comes back in the export trailer's
`missing_rules`. Those ids are reported as failures, so the command exits 1
rather than reporting a short export as a success.

### 4.4 Import conflict handling

Re-importing rules that already exist is a per-rule 409 for every one of them
and exit 1 — not a skip. Two flags resolve it, and they are mutually exclusive
because they are opposite answers to the same question:

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
  the tree in the requested format. Filenames are planned for every rule before the
  first file is written, so a `rule_id` pair that sanitises to one filename is
  refused with `conflict` naming **every** colliding pair at once, and refused
  before the directory is created. Reporting one collision per run hides the
  second until a re-run, and writing files up to the collision leaves a mirror
  that is neither the old state nor the new one.
- **`diff`** — read local, fetch remote, normalize both, emit field-level
  drift. Because NDJSON lines are not readable by eye, `diff` is the human
  view; `git diff` is the fidelity record.
- **`push`** — read local, compute the diff, apply each change through the
  guard, then write a change-evidence report of per-rule before and after
  values plus an applied flag, suitable for attaching to a change ticket.

`push` **never deletes remote rules.** A rule missing locally is not a delete
instruction. Deletion is always the explicit `rules delete`.

### 5.1 Server-applied defaults

Creating a rule with 13 fields returns 36. The server fills 16 defaults —
`max_signals: 100`, `to: "now"`, `rule_source: {"type":"internal"}`,
`actions: []`, and similar — on top of the 8 volatile fields.

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
Elasticsearch's result window — `from + size` must not exceed 10,000 — so a
page size at the window returns any corpus that `_find` can serve at all.
Measured against 2,066 rules: 21 sequential pages of 100 cost 8.4-11 s; one
request costs 2.4 s.

A corpus larger than 10,000 rules cannot be read through one `_find` by any
combination of `page` and `per_page`, because the limit applies to their sum
rather than to either one. Paging smaller does not evade it and neither does
concurrency. Above the window the corpus is read by partitioning instead.

`rules export` is not the escape hatch and must never be offered as one. It
carries its own 10,000 cap from `xpack.securitySolution.maxRuleImportExportSize`
and answers `Can't export more than 10000 rules` with a 400. The generic
saved-objects export cannot serve either: the security rule types register
`isExportable: false`, so detection rules are not exportable through that
interface at all. No public API reads past the window in a single call.

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

The single-request path is unchanged for any corpus under the window, which is
every real corpus today. Partitioning is a fallback, not the default: paying
seven requests for a 2,066-rule read would forfeit 5.2's whole result.

Kibana does expose `search_after` on `POST /internal/detection_engine/rules/_search`,
which would remove the ceiling outright. It is rejected deliberately: the route
is `access: 'internal'` and unversioned, and this tool's reason to exist is
spanning three deployment flavors whose internal routes need not agree or
survive an upgrade.

### 5.3 Scoped state operations

`pull`, `diff`, and `push` take the same positional selectors and `--tag`
filter as `rules export`, described in 4.3. Given neither, they act on the
whole space, which is the existing behaviour and stays the default.

Selection narrows both sides before drift is computed, so the remote read
becomes one `rule_id`-filtered `_find` instead of a corpus read. Resolution
differs by command because the commands face opposite directions:

- `pull` reads from the stack, so its selectors name stack rules and resolve
  remotely.
- `diff` and `push` act on the local directory, so a selector matching a local
  `rule_id` or `name` wins and only an unmatched one falls through to a remote
  lookup. Without local-first resolution a locally-added rule — one that exists
  in no remote index yet — could never be selected, which would make scoped
  `push` unable to do the thing it is most wanted for.

A selector resolving to nothing is refused naming the selector, as in 4.3. A
name matching two local rules is refused naming both `rule_id`s: identity is
`rule_id`, and a display name that has stopped being unique is not something to
resolve by guessing.

`RemoteOnly` keeps its meaning inside a selection — `--tag prod` can select a
remote rule with no local file — and `push` still never deletes it.

Scoped runs report what narrowed them, and unscoped runs report nothing new —
an invocation without selectors produces the output it produced before. `diff`
and `push` report `selected` alongside `local_total`, so a scoped run cannot be
mistaken for a clean tree. `pull` reports `selected` only: it reads from the
stack and has no local set to count against.

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

Table output by default, `--json` explicit — matching splunkctl rather than
detecting a TTY, so a command behaves identically in a terminal and in a
script.

`--json` and `--format` govern how a command's *report* is rendered. They never
reshape file content. `rules export` without `--out` has no report: its stdout
**is** the exported rule file, emitted verbatim in whatever `--format-file`
selected. Wrapping it — `{"ndjson": "..."}` — would make
`elasticctl rules export --json > rules.ndjson` produce a file Kibana cannot
import, so the raw body is the contract in that mode, under every value of
`--format`.

Identifiers that are not secrets but still identify a credential — the API key
id `doctor` reads back from `_security/_authenticate`, for instance — are
truncated in output when longer than twelve characters. The secret half is
never printed at all.

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

Enabling a rule makes the alerting framework mint a rule-owned API key, and it
refuses to do that on behalf of an organization key. The `essu_` prefix does
**not** imply project scope — the key used for the probes reports
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
realm `_es_api_key` rather than `_cloud_api_key`, and every mutation path then
works. Verified end to end: create a disabled rule, `PATCH` it to
`enabled: true` keyed on `rule_id` (200, `enabled: true`), disable it through
`_bulk_action` (`succeeded: 1`, `enabled: false`), delete it.

The realm is therefore the signal `doctor` should read: `_cloud_api_key` means
rule mutation will fail, `_es_api_key` means it will work. That is a cheaper
and clearer check than attempting a mutation and classifying the 400.

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
without applying it. That pairs directly with the mutation guard — the dry-run
preview can be server-computed rather than inferred.

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
matched four documents and a rule that matched none produce byte-identical
responses; the only in-band signal is the `max_signals` warning, which fires
only at 100 or more. That defeats the command for its main user, a detection
engineer iterating on a query.

The hits are therefore read back. The alerts a preview writes land in a
per-space preview alerts index and are searched with the returned `previewId`:

| Fact | Value | Status |
|---|---|---|
| Preview alerts index | `.preview.alerts-security.alerts-<space>` | **Measured** by the `rules_preview_hits` fixture |
| Field carrying the preview id | `kibana.alert.rule.uuid` | **Measured** by the same fixture |
| Readable with a project-scoped Elasticsearch API key | yes | **Measured** by the same fixture |
| Visible to search when the preview response returns | Observed on the first search of the recorded run | **Measured**; the fixture records `attempts_until_hits: 1` for that run |

Measured: in the recorded run the alerts were visible to the first search. A
slower stack may not be, so the retry below is insurance against that rather
than a claim about every stack.

The read is an Elasticsearch search rather than a Kibana route because the
evaluation already recovered true hit counts from Elasticsearch with the same
project-scoped key, so credential and transport are proven and only these
names are open.

Every simulated invocation has completed by the time the preview response
returns — each has its own `logs` entry — so there is nothing to poll. The one
remaining race is Elasticsearch's one-second default refresh interval, so a
first search that sees zero hits is retried once after one second. A rule that
matched pays nothing.

A failed read degrades rather than fails: `hits` is `null`, `hits_error`
carries the classified message, and the preview's own id, errors, and warnings
are reported as before. Preview is a diagnostic; losing the count must not lose
the run.

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
| Licence | `GET /_license` returns `type: "enterprise"`, unlike Serverless where the endpoint does not exist |

The negative half is measured too. `traditional-9.5.1`, recorded from the
`lab/` stack on 2026-08-13, carries a `headers` object holding the headers that
stack does send while `x-found-handling-cluster` is absent from it — so the
header's absence is evidence rather than an assumption about there being no
Cloud proxy in front of a self-managed deployment.

That distinction is worth keeping: an absent `headers` key would mean "not
recorded", which proves nothing. The classification test therefore requires the
key on every fixture set, so a re-record that dropped it fails rather than
quietly reverting this to an inference.

## 8. Testing

| Tier | Runs | Covers |
|---|---|---|
| Unit | Always, no I/O | Normalization, codecs, rule round-trip, config precedence, error classification |
| Fixture | Always, offline | Full command paths against `wiremock` replaying recorded exchanges, plus `assert_cmd` and `insta` snapshots of rendered output |
| Live | `ELASTICCTL_LIVE=1 cargo test -- --ignored` | Real stack. The conformance check that catches API drift |

Fixtures are **recorded, not hand-written** — `cargo xtask record` drives a
live stack and dumps the real exchanges, scrubbing credentials. Each fixture
records the flavor and stack version it came from so drift is visible.

The directory is `tests/fixtures/<flavor>-<version>`, and the flavor is the
*deployment* flavor, not the value the stack reports. Hosted and self-managed
both report `build_flavor: "traditional"`, so a Hosted recording would
overwrite the self-managed set. `ELASTICCTL_FIXTURE_FLAVOR` overrides the
derived name and tags the fixtures at record time; it exists because tagging
them correctly afterwards would mean editing recorded fixtures, which is never
allowed.

CI runs unit and fixture tiers on every push; the live tier runs on a schedule
and before releases.

### 8.1 Sample corpora

Making a rule fire needs rules and events, and neither belongs in this
repository. `samples/` holds scripts that fetch them on demand and never vendor
them:

- A slice of SigmaHQ/sigma Windows `process_creation` rules, converted to
  importable Kibana NDJSON by `sigma-cli` with the `lucene` target and the
  `ecs_windows` pipeline. Detection Rule License 1.1: redistribution requires
  the per-rule `author`, a link to the rule set, and the licence text, which is
  why the harness fetches rather than commits.
- Three MIT-licensed OTRF Security-Datasets event sets. Their events use
  pre-ECS Winlogbeat field names, so a remap and a timestamp rewrite run before
  ingest — without them no rule can ever match.

`sbousseaden/EVTX-ATTACK-SAMPLES` is excluded: the repository carries no
licence at all. `elastic/detection-rules` content is Elastic License v2 and is
never committed here.

## 9. Local lab

Serverless is the primary development target, so nothing needs to run locally
day to day. The `lab/` podman stack exists for one purpose: recording
self-managed fixtures so v0.1 does not ship a serverless-only tool wearing a
three-flavor label.

`lab/compose.yaml` runs Elasticsearch and Kibana 9.5.1, single node, security
enabled, roughly 3 GB for the twenty minutes it is up.

Two settings that are easy to miss and cost an afternoon:

- Kibana needs `xpack.encryptedSavedObjects.encryptionKey` set to 32 or more
  characters. Without it the alerting framework cannot persist rule API keys
  and **every rule creation fails**, with an error that never mentions
  encryption.
- The detection engine needs its signals index bootstrapped through
  `POST /api/detection_engine/index` before rules will run.

Scripts: `lab/up.sh` (compose up, wait for green, set the `kibana_system`
password, bootstrap the signals index, start a 30-day trial licence, mint an
API key, print a ready-to-paste `config init`), `lab/seed.sh` (sample rules and
a small event dataset so `rules preview` has data), `lab/down.sh`.

Lab certificates are self-signed, so profiles carry a `verify` field. Setting
`verify = false` prints a warning on every request, so it cannot quietly become
the production habit.

## 10. Distribution

`cargo-dist` producing GitHub Releases for Linux gnu and musl (x86_64,
aarch64), macOS (x86_64, aarch64), and Windows x86_64, plus
`cargo install elasticctl`. Static musl matters for locked-down Linux laptops;
macOS aarch64 is the likely common case. A Homebrew tap when there is demand.

## 11. Versioning

Cargo SemVer, staying in `0.x` until the command surface settles. Under the
`0.x` rule the minor position is the breaking position, which Cargo implements
directly: `^0.1.2` resolves to `>=0.1.2, <0.2.0`, so every `0.1.x` is
compatible and `0.2.0` is a break.

Development is iterative — ship small, ship often.

- **Patch** (`0.1.1`, `0.1.2`, …) carries fixes and small additive changes
  *inside* the capability areas that already exist: a new flag on
  `rules list`, a new output field, a bug fix.
- **Minor** (`0.2.0`, `0.3.0`, …) marks a **new capability area** — `search`,
  `dashboards`, `cases`, `fleet` — or an actual break.

A minor bump is *required* when something breaks. It is not *restricted* to
breaks. Using it to mark each new capability area makes the version number
describe what the tool can do, which is what a user reads it for.

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
| `1.0` | Command surface stable; MCP server |

### 11.1 What counts as breaking

SemVer is written for library consumers, but nobody depends on elasticctl's
Rust types — they depend on the CLI surface. That is the public API, and it is
what the version number describes.

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
`cargo publish --workspace`, which packages and verifies every crate against a
temporary registry before uploading any — a sequence that fails partway would
otherwise strand a crate on crates.io, where a version can be yanked but never
deleted. `xtask` stays `publish = false`; it is a dev tool and ships nothing.

Publishing is nonetheless *deferred* while the tool is early: a release tags
and builds GitHub Release binaries and skips crates.io. A tag costs nothing and
a GitHub Release can be deleted; a crates.io version is forever. Publishing
`elasticctl-core` and `elasticctl-api` makes their Rust APIs a real contract,
and those boundaries are still moving.

## 12. Credentials in this repository

Development credentials live in `.env`, which is gitignored and mode `0600`.
`.env.example` is committed and contains placeholders only. The Elastic key in
use is a **project-scoped** serverless key: it authenticates API calls but
cannot create, list, or resize projects. Managing projects and deployments
needs an organization key with Cloud API access, created in the Cloud console
under Organization > API keys, against `api.elastic-cloud.com`.

All three key types carry the `essu_` prefix — the console offers no other —
so the prefix identifies nothing. Only `GET /_security/_authenticate` reports
the realm, which is the discriminator.

Provisioning a Hosted deployment through the Cloud API does not currently work
on this organization: `GET /deployments/templates` serves a catalogue whose
every entry `POST /deployments` then rejects as `legacy_dt`, with the same
result for two distinct organization keys and for the documented `template_id`
query parameter that has the server expand the template itself. No AWS region
resolves for Hosted templates at all. The console creates the same deployment
without complaint, so Hosted deployments are created there and driven by API
afterwards, which works normally.

## 13. Risks

**Serverless-first bias — resolved.** Serverless is the most divergent of the
three flavors — no licence tiers (features gate on project tier instead),
different auth, some endpoints versioned differently. Developing only against
it risks baking serverless assumptions into code that claims to support
self-managed. Mitigated by tagging fixtures with flavor and version, gating
divergent behaviour behind the capability probe, and recording each flavor.

All three flavors now hold 14 fixtures each: `serverless-9.6.0`,
`traditional-9.5.1`, and `ech-9.5.1`. Coverage is even, so no flavor is the
least-tested one.

Both halves of the Hosted signal are now measured rather than inferred. Every
set records response headers: `traditional-9.5.1` carries headers while lacking
`x-found-handling-cluster`, and the other two carry it. The self-managed
recording also closed the last open question about `rules preview`, which had
only ever been exercised against Serverless.

**`rules preview` stability — resolved.** The concern was that the preview
endpoint has moved between public and internal paths across Elastic versions.
Measured on Serverless 9.6.0: `POST /api/detection_engine/rules/preview` is
public and returns 200 with a `previewId` and a `logs` array carrying per
execution `errors` and `warnings`. The internal path returns 404.

`elastic-api-version` must be a date string — `1` and `2` are both rejected
with "Invalid version. Received \"1\", expected a valid date string". Since
internal Kibana routes are versioned numerically, this is a second reason they
are unreachable here. `2023-10-31` is the only version this client needs.

The command stays in 0.1.0 and off the trim line. It is now confirmed against a
self-managed stack too: `traditional-9.5.1` carries recorded `rules_preview`
and `rules_preview_hits` fixtures.

**Empty project — resolved.** The serverless development project now holds
2,066 prebuilt Elastic rules covering all seven rule types, seeded for scale
testing. Measured against them: `state pull` writes 2,066 files in ~8.4 s, a
second pull is byte-identical, `state diff` reports zero drift, and export
round-trips every type exactly. They are read-only ground truth — a live test
never mutates an untagged rule, every object it creates carries the
`elasticctl-sample` marker, and a run ends by verifying the project is back to
that baseline.
