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
- **`auth`** — `ApiKey` (`Authorization: ApiKey <base64(id:key)>`) or `Basic`.
  API key is the default; basic auth exists for the local lab.
- **`transport`** — `reqwest` with `rustls` on `tokio`. Injects `kbn-xsrf: true`
  on every non-GET request, `elastic-api-version` where required, and prefixes
  space-scoped paths as `/s/<space>/api/...`. Retries with backoff on 429 and
  5xx only, never on 4xx.
- **`capabilities`** — one probe at connect time reading `GET /api/status`.
  Yields `Capabilities { flavor, version, license_tier, spaces }`. Commands
  consult it and return a typed `Unsupported` error naming the flavor rather
  than surfacing a confusing 404.
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
elasticctl config init [--profile NAME]      Create or edit a profile
elasticctl config list | show | test         Inspect profiles; secrets always redacted
elasticctl doctor                            Connectivity, auth, identity, license, flavor
elasticctl info                              Stack version, flavor, license tier, spaces

elasticctl rules list                        --enabled/--disabled --type --severity --tag --filter
elasticctl rules get <name|rule_id>
elasticctl rules validate --path FILE        Local schema check, no server contact
elasticctl rules enable  <name|rule_id>...   [guarded]
elasticctl rules disable <name|rule_id>...   [guarded]
elasticctl rules delete  <name|rule_id>...   [guarded]
elasticctl rules export --out FILE [--format ndjson|yaml] [filters]
elasticctl rules import --path FILE [--overwrite]              [guarded]
elasticctl rules preview <file|name|rule_id> Run a rule against history, no alerts written

elasticctl state pull --dir config/ [--format ndjson|yaml]
elasticctl state diff --dir config/          Field-level structured drift
elasticctl state push --dir config/ [--report FILE]            [guarded]

elasticctl completion bash|zsh|fish
elasticctl commands                          Machine-readable command tree
```

### 4.1 Rule identity

Engineers think in names; the API has `rule_id` (a stable UUID) and `id` (a
volatile saved-object id). Commands accept either a name or a `rule_id`. Names
resolve through `_find`; a non-unique name returns a typed `conflict` error
listing the candidates rather than silently picking the first match. State
matching is **always** by `rule_id` — never by name, never by `id`.

### 4.2 Global flags

Accepted before or after the subcommand: `--profile`, `--config`, `--space`,
`--json`, `--format`, `--fields`, `--out`, `--yes`/`-y`, `--timeout`,
`--debug`.

## 5. State engine

- **`pull`** — page through `_find`, map to `Rule`, normalize, write the tree
  in the requested format.
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
`actions: []`, and similar — on top of the 7 volatile fields.

That means a hand-authored rule file omitting `max_signals` would diff against
its pulled counterpart forever. Two modes resolve it:

- A rule written by `pull` already carries the full field set, so the diff is
  symmetric and exact.
- A hand-authored rule is passed through default-filling before comparison, so
  an omitted field reads as "accept the server default", not as drift.

`rules validate` applies the same default-filling, so an engineer can see
exactly what a sparse file will become before pushing it.

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

## 8. Testing

| Tier | Runs | Covers |
|---|---|---|
| Unit | Always, no I/O | Normalization, codecs, rule round-trip, config precedence, error classification |
| Fixture | Always, offline | Full command paths against `wiremock` replaying recorded exchanges, plus `assert_cmd` and `insta` snapshots of rendered output |
| Live | `ELASTICCTL_LIVE=1 cargo test -- --ignored` | Real stack. The conformance check that catches API drift |

Fixtures are **recorded, not hand-written** — `cargo xtask record` drives a
live stack and dumps the real exchanges, scrubbing credentials. Each fixture
records the flavor and stack version it came from so drift is visible.

CI runs unit and fixture tiers on every push; the live tier runs on a schedule
and before releases.

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

Only the `elasticctl` binary publishes to crates.io. `elasticctl-core` and
`elasticctl-api` are `publish = false`. Publishing them would make their Rust
APIs a SemVer contract with real consumers, turning every internal refactor
into a version event, and the boundaries are still moving. They can be
published later; they cannot be un-published.

## 12. Credentials in this repository

Development credentials live in `.env`, which is gitignored and mode `0600`.
`.env.example` is committed and contains placeholders only. The Elastic key in
use is a **project-scoped** serverless key: it authenticates API calls but
cannot create, list, or resize projects. Managing projects would need an
organization API key (`essa_` prefix) against `api.elastic-cloud.com`.

## 13. Risks

**Serverless-first bias.** Serverless is the most divergent of the three
flavors — no licence tiers (features gate on project tier instead), different
auth, some endpoints versioned differently. Developing only against it risks
baking serverless assumptions into code that claims to support self-managed.
Mitigated by tagging fixtures with flavor and version, gating divergent
behaviour behind the capability probe, and recording self-managed fixtures
before v0.1 is called done.

**`rules preview` stability.** The rule preview endpoint has moved between
public and internal paths across Elastic versions. It is the highest-value
command here for a detection engineer, so it is in the plan — but if it proves
internal-only on the target versions it drops to v0.2 rather than shipping
something version-fragile.

**Empty project.** The serverless project currently holds zero rules, so
`state pull` has nothing to read and `rules preview` has no data. The first
implementation step installs a set of prebuilt Elastic rules and seeds sample
events.
