[Back to elasticctl-design](../elasticctl-design.md)

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

