[Back to elasticctl-design](../elasticctl-design.md)

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

A data stream backing index name, `.ds-<stream>-<yyyy.MM.dd>-<generation>`,
carries the date its stream rolled over, which dates the recording stack. The
scrub replaces that date with `REDACTED` in every string that is exactly such a
name and keeps the stream and generation.

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
committed lockfile. Linux runs formatting, Clippy, full workspace nextest tests,
separate doctests, and package-content checks. macOS 15 runs the full workspace
nextest suite and doctests with the pinned `rust-toolchain.toml` compiler.
Windows runs one nextest selection: all `elasticctl` package tests plus API
state integration and transaction tests, including raw export and report-file
regressions. Local `cargo test` remains supported.
CI disables dev/test debug information and saves Rust caches only on `master`.
The primary compiler is read from `rust-toolchain.toml` and verified with
`rustc --version`. A separate job reads `workspace.package.rust-version` and
checks every workspace target with that exact compiler only when it differs
from the primary compiler.

Package-content checks inspect every publishable crate: `elasticctl-core`,
`elasticctl-api`, `elasticctl-mcp`, and `elasticctl`. They fail if any packages
integration tests or the private test-support crate. Fixture checks scan for
credentials and project identity. Separate jobs run full-history gitleaks
(findings fail CI) and actionlint over all workflows. CodeQL analyzes Rust and
Actions with `build-mode: none` on master pushes, pull requests, and weekly. The `lengths` job tests Linux and macOS; Rust excludes only top-level inline test module blocks and `tests/` paths. Baseline caps equal current counts; PRs reject entries added or raised against the target branch.

Release canaries run weekly, on manual dispatch, and on pull requests changing
`dist-workspace.toml` or `.github/workflows/release.yml`. They run `dist plan`,
assert all seven configured targets are planned, build local/global artifacts,
and upload workflow artifacts. Only tag **pushes** may run `host --steps=create`,
`host`, or `announce`; all other events skip publishing, including manual
dispatch on a tag. Repository permission stays read-only except for `host`.

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

It runs the same eleven contracts serially against each target: diagnostics,
pull-then-diff stability, exception CRUD and bundle round-trip, stale-pointer
repair, source scoping, rule export/import round-trip, search, triage
(`elasticctl-triage-design.md` section 9), and content transfer
(`elasticctl-content-design.md` section 13), then Fleet policy transfer
(`elasticctl-fleet-design.md` section 14), followed by
`mcp_reads_existing_verticals`, the MCP read contract defined in
`elasticctl-mcp-design.md` section 8. Before the first mutation, it
captures custom, prebuilt, and customized rule counts, the exact default data
view, and all marker partitions. It refuses a target with existing live-marker
objects. It checks marker cleanup and default stability after every contract,
then compares the final state with that baseline. Dashboard marker capture is
gated below the verified dashboard floor so the content contract can report an
explicit capability skip; every other required baseline route fails closed.
Fleet setup runs once through the one-shot transport before the baseline only
when `FleetPolicies` meets its verified floor. The setup response must confirm
initialization before the runner passes its private setup marker to every
child whose contract requires `FleetPolicies`. After probe validation, the
runner clears a previous target report
before Fleet setup, so a setup failure cannot leave stale success evidence.
Gated Fleet baseline
reads retain only `elasticctl-live-` policy ids and names, and require both
zero Fleet markers and an exact installed-package name/version inventory after
every contract. The shared private test-support module owns these strict Fleet
reads so the controller and live contract use the same non-rendering audit
surface; it depends on core transport and JSON only.

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
| Serverless | 9.6.0 | 6 pass | Verified | [report](../../conformance/v0.2.3/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 6 pass | Verified | [report](../../conformance/v0.2.3/ech-9.5.1.json) |
| Self-managed | 9.5.1 | 6 pass | Verified | [report](../../conformance/v0.2.3/traditional-9.5.1.json) |

All 18 contract rows passed with no skip. The validated
[findings](../../conformance/v0.2.3/findings.md) therefore justify no live defect,
while a later static review justified the bounded 0.2.4 patch; the 0.3.0 search
design is the next capability-area work.

The 0.3.1 measured matrix adds the `search` contract; all seven pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 7 pass | Verified | [report](../../conformance/v0.3.1/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.1 | 7 pass | Verified | [report](../../conformance/v0.3.1/ech-9.5.1.json) |
| Self-managed | 9.5.1 | 7 pass | Verified | [report](../../conformance/v0.3.1/traditional-9.5.1.json) |

The 0.4.2 measured matrix adds the `triage` contract; all eight pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 8 pass | Verified | [report](../../conformance/v0.4.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 8 pass | Verified | [report](../../conformance/v0.4.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 8 pass | Verified | [report](../../conformance/v0.4.2/traditional-9.5.1.json) |

The 0.5.2 measured matrix adds the `content` contract; all nine pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 9 pass | Verified | [report](../../conformance/v0.5.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 9 pass | Verified | [report](../../conformance/v0.5.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 9 pass | Verified | [report](../../conformance/v0.5.2/traditional-9.5.1.json) |

Every content leg restored the exact captured default and left zero marker
dashboards, data views, or indices. Each target's prebuilt-rule count matched
its baseline. The self-managed leg removed its containers and volumes.

The 0.6.2 measured matrix adds the `fleet` contract; all ten pass on every
target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 10 pass | Verified | [report](../../conformance/v0.6.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 10 pass | Verified | [report](../../conformance/v0.6.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 10 pass | Verified | [report](../../conformance/v0.6.2/traditional-9.5.1.json) |

Every Fleet leg left zero marker agent and integration policies and restored
the exact captured installed-package inventory. Existing rule-count, content,
default-data-view, and triage baselines also passed. The self-managed leg
removed its containers and volumes. The [findings](../../conformance/v0.6.2/findings.md)
record the measured scope and the older closed-alert residue allowance.

The 0.7.2 measured matrix adds `mcp_reads_existing_verticals`; all eleven
contracts pass on every target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.6.0 | 11 pass | Verified | [report](../../conformance/v0.7.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 11 pass | Verified | [report](../../conformance/v0.7.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 11 pass | Verified | [report](../../conformance/v0.7.2/traditional-9.5.1.json) |

Every MCP leg exercised twenty default tools on current protocol `2026-07-28`
and both opt-in query tools on legacy `2025-11-25`. All baseline, marker,
Fleet inventory, and default-data-view audits passed. Independent teardown
checks found zero lab containers and volumes. The
[findings](../../conformance/v0.7.2/findings.md) record the two product clients,
the corrected harness failure, and evidence limits.

The 0.7.5 measured matrix reruns the eleven contracts on the current trial
stacks; all pass on every target:

| Flavor | Version | Contracts | Cleanup | Report |
| --- | --- | --- | --- | --- |
| Serverless | 9.7.0 | 11 pass | Verified | [report](../../conformance/v0.7.5/serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 11 pass | Verified | [report](../../conformance/v0.7.5/ech-9.5.6.json) |
| Self-managed | 9.5.1 | 11 pass | Verified | [report](../../conformance/v0.7.5/traditional-9.5.1.json) |

Both Cloud targets held the full prebuilt pack, 2,263 rules, so the MCP
contract read `rules_list` against a corpus larger than the response body
cap. The [findings](../../conformance/v0.7.5/findings.md) record the scope and
one Serverless 9.7.0 behavior change.
