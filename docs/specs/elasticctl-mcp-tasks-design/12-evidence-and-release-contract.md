[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 12. Evidence and release contract

The rules of [0.7 section 8](../elasticctl-mcp-design/08-evidence-and-release-contract.md#8-evidence-and-release-contract)
stay in force: marker-owned objects prepared outside MCP, raw results in
ignored private logs, scrubbed public findings, no skipped target reported as
a pass, four crates at one version, and no release or publication without
separate approval for that exact version.

### 12.1 Evidence per version

| Evidence | 0.8.0 | 0.8.1 | 0.8.2 |
| --- | --- | --- | --- |
| Recorded fixtures | Every new request shape, three flavors, marker-scoped | none new | none new |
| API unit and wiremock tests | `compose`, `rules::window`, new decoders | none new | fixes only |
| MCP router tests over `serve_io` | Four tools: plan order, caps, part failures, schemas | Resources and prompts: lists, reads, errors, admission | Output-schema validation, read and tool text equality, gap tests |
| SDK client tests | Catalog and one call per tool on both protocol paths | Lists, one read, one prompt on both paths | none new |
| Process tests through both binaries | Exact 24 and 26 name catalogs with schemas and annotations; instructions | Exact resource, template, and prompt lists; capabilities | none new |
| Live contract, three flavors | Twelve-contract matrix | Twelve-contract matrix with the extended twelfth contract | Twelve-contract matrix on the release commit |
| Latency gate M9 | required | not repeated | not repeated |
| Real product clients | none | none | Claude Code and Codex CLI on the lab |
| Independent review | Each task, then whole branch with a safety focus | Each task, then whole branch | Each fix, then evidence and privacy |

### 12.2 Fixtures

New fixtures come from `cargo xtask record` with a new `compose` recording
step. Every request is scoped to marker objects: the marker rule id, the
marker index pattern, the marker exception list, the marker case. A fixture
never holds a prebuilt rule, an unscoped `_find`, or an index name that is
not a marker. Fixtures land in `tests/fixtures/<flavor>-<version>/` for the
version each stack reports. The directories for Serverless 9.7.0 and Hosted
9.5.6 hold only the operations recorded for 0.8; the older full sets are not
re-recorded. The owner accepted this on 2026-11-10.

| Fixture | Content |
| --- | --- |
| `rule_get_executed.json` | Marker rule read after one execution, with `execution_summary` |
| `rule_get_failed_execution.json` | Marker rule over a missing index, after one execution |
| `rules_find_sorted_page.json` | `_find` scoped to marker rules with `sort_field=created_at` |
| `rules_find_by_technique.json` | `_find` scoped to marker rules with a technique clause |
| `signals_search_rule_activity.json` | Request and response for the section 4.2 body, with buckets and hits |
| `cases_by_alert.json` | Non-empty response for a marker alert in a marker case |
| `cases_by_alert_none.json` | `[]` for an absent id |
| `exception_items_count.json` | Item `_find` with `per_page=1` on a two-item marker list |
| `resolve_index_match.json` | Marker index pattern |
| `resolve_index_no_match.json` | Marker wildcard that matches nothing |
| `resolve_index_not_found.json` | Missing concrete marker name: the 404 as the transport classifies it (kind and status) |
| `package_not_installed.json` | Status of one package the recorder first proves is not installed |

The transport returns a non-success response as a classified error and keeps
no raw body, so the 404 fixture records that classification. Tests of the 404
path assert the kind and status the caller sees.

Server-authored prose never enters a fixture. Execution summary text other
than `status` and `date`, and every `message` or `reason` string, is replaced
with the placeholder `elasticctl-fixture-server-text`; the original stays in
the private log.

Existing fixtures are reused unchanged and never hand-edited. Synthetic
bodies belong in adversarial tests only.

### 12.3 Twelfth conformance contract

0.8.0 adds `mcp_answers_across_verticals` as the twelfth contract. The root
ignored test in `crates/elasticctl-cli/tests/live.rs` carries the same name,
because the controller invokes tests by exact name. Its required features
are exception lists, prebuilt rules, and Fleet policies.

The harness prepares, outside MCP and under the existing ownership and
cleanup rules, two separate object sets. One is built so every request of a
plan is sent; the other is built so parts degrade. Mixing them would hide
requests: a missing list sends no count request and an exclusion sends no
resolve request.

Shared: a marker index with documents, a marker data view over it, and the
Fleet fixture lease from 0.7.1.

Maximum-work set:

- five marker exception lists that all exist, one with two items;
- rule W, enabled, over the marker index, with a `threat` entry (tactic
  `TA0002`, technique `T1059`, subtechnique `T1059.001`); five exception
  references, all to existing lists; 16 index patterns that are all
  resolvable requests, the marker index and 15 marker wildcards that match
  nothing; and eight `related_integrations` entries with valid package
  names, `system` first;
- one alert from rule W, attached to five marker cases.

Corpus fill, self-managed flavor only: disabled marker rules, each with the
`elasticctl-sample` `rule_id` prefix and tag, created in bulk until the
space holds exactly 4,000 rules, counting every rule already there. The
harness refuses to start the fill when the space already holds more than
4,000 rules. It deletes the fill rules by explicit `rule_id` after the
coverage timing and verifies the count is back to the pre-fill value. The
flavor comes from the capability probe. The fill never runs on Serverless
or Hosted.

Degradation set:

- rule D, enabled, over the marker index, with one reference to an existing
  list and one to a list key that does not exist, an exclusion pattern, and
  one `related_integrations` entry for a package name that no registry
  holds;
- rule V, which uses the marker data view;
- one alert from rule D, in no case.

The child server then runs, on the current protocol for the default catalog
and on the legacy protocol for a second child:

- `alert_context` for the rule W alert: every part `ok`, five list rows
  `ok` with item counts, five case rows, finding `has_related_case`;
- `alert_context` for the rule D alert: the missing list row `unavailable`
  with `not_found`, `cases.total` zero, `partial: true`, finding
  `exception_list_missing`;
- `alert_context` for an absent id: `elastic_not_found`;
- `rule_health` for rule W by name, the three-request selector path:
  `execution` present, `alerts.total` at least one, `recent` holds the
  marker alert, five list rows `ok`;
- `rule_readiness` for rule W by name: 16 rows, one `matches` and 15
  `no_match`, eight package rows, the `system` row with its install status
  and policy count, `partial: false`;
- `rule_readiness` for rule D and rule V: an `exclusion` row, the data view
  found, the unknown package row `unavailable`;
- `detection_coverage` with `source: "custom"` for each grouping: the marker
  keys present with the expected counts; and twice in a row with default
  arguments: on Serverless and Hosted, `summary.rules` at least the
  prebuilt-rule baseline; on the lab, after the corpus fill, `summary.rules`
  exactly 4,000, which is eight pages a call;
- `rules_list` with `technique`, `tactic`, and the subtechnique form: rule W
  returned; and `rules_list` with default arguments: a success result.

The test records the wall time of every call. The calls on the
maximum-work set and the two coverage calls per flavor are measurement M9;
the lab pair is the observed maximum of 16 pages. Request
counts are not observable live; the offline recording-mock tests prove them
for inputs of the same shape.

0.8.1 extends the same test: both lists, the template list, one read of each
of the nine resource shapes with text equal to the matching tool call, one
absent rule id with the path-correct not-found code, the prompt list, and
one `prompts/get` per prompt compared with the literal text.

The contract ends with the existing audits: marker cleanup, prebuilt-rule
count, default data view, and Fleet package inventory. The read-only proof
for live runs is unchanged from 0.7.2: offline recording-mock route proofs,
the child's command line and configuration, and baseline equality. No live
request capture is claimed.

The conformance JSON keys do not change. The report validator gains a
twelve-name list for the `v0.8` family and keeps every earlier list. Reports
live in `docs/conformance/v0.8.0/`, `docs/conformance/v0.8.1/`, and
`docs/conformance/v0.8.2/`, each with three reports and a `findings.md`.

### 12.4 Real clients

0.8.2 runs Claude Code and Codex CLI against the local lab only, each with a
scratch configuration outside the repository and a shim that copies both
stdio directions to private files. The findings record exact client
versions, the negotiated protocol, and, from the captured frames, which
methods each client sent. A behavior is recorded as observed, not sent, or
not testable. Documentation alone never counts as a test.

Required interactions per client: catalog discovery; one call of each task
tool on marker data; one resource read by a listed URI and one by a template
URI, or the captured evidence that the client cannot send it; one prompt
invocation, or the same evidence; one invalid argument; client exit with no
orphan process.

### 12.5 Release gates

Each version runs, one command at a time, the gate set of
`instructions/testing.md`: format, locked Clippy with warnings denied, the
locked workspace tests, `cargo deny`, the package, fixture, and conformance
report scripts, the length gate, the non-publishing workspace dry run, and
`git diff --check`. A version ships only when:

1. every row of section 12.1 for that version has recorded evidence;
2. the twelve-contract matrix passed on Serverless, Hosted, and
   self-managed for that version's commit. This holds for 0.8.0, 0.8.1, and
   0.8.2 alike. A flavor that cannot be reached is an open gate, never a
   pass and never a waiver. The plan is to run all three inside the current
   trial window; if it closes first, the owner supplies replacement stacks
   and the version waits for them;
3. every section 11.1 measurement that blocks it is recorded on three
   flavors, or the version waits;
4. the whole-branch review verdict is merge, or its findings are fixed and
   re-reviewed;
5. the shared spec, this spec, the changelog, and the README match the
   shipped behavior.

A runtime fix after a matrix run (in `crates/elasticctl-mcp/src`, the core
transport, the CLI MCP dispatch, or an API function a tool calls) requires
rerunning both MCP contracts on all three flavors. A fix limited to tests,
docs, scripts, or `xtask` does not.

### 12.6 Execution

Work follows `instructions/workflow.md` and the three plans. A designer or
reviewer never implements the slice they designed or review. Each editing
worker has its own worktree, fixed paths, one directive, and no Git, live
target, or publishing authority. The primary owns the specs, shared-file
integration, live runs, evidence, and release steps. Local builds use two
jobs and four test threads, one build-heavy process at a time.
