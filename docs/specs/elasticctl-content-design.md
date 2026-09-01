# elasticctl dashboards and data views design

`data-views` and `dashboards` form the 0.5 capability area: portable Kibana
content and the administration needed to move it safely between spaces and
deployments. `data-views` manages the stable objects dashboards query through.
`dashboards` manages the typed, reviewable dashboard definition and offers an
explicit opaque bundle path when related saved objects must travel with it.

This spec follows `elasticctl-search-design.md` and
`elasticctl-triage-design.md`. It defers to `elasticctl-design.md` for
architecture, transport, rendering, error, guard, fixture, and release
contracts.

## 1. Scope

0.5.0 is the complete data-view surface:

```text
data-views list | get | validate | export | import | delete
data-views default get | set | unset
```

0.5.1 is the complete dashboard surface:

```text
dashboards list | get | validate | export | import | delete
dashboards bundle export | import
```

0.5.2 adds the content conformance contract, runs the cross-flavor matrix, and
ships the bounded review patch. Each release tells one complete story: data
sources, then dashboards, then proof.

The 0.5 area is transfer and administration, not another mirror. It does not
extend `state pull | diff | push`, reconcile a directory, manage Kibana tags or
library visualizations as independent resources, generate dashboards, manage
PDF/PNG reporting, or expose legacy internal dashboard routes.

## 2. Transfer is not reconciliation

Rules and exception lists have a desired-state mirror because their local
files are deployment intent. Dashboard and data-view files in 0.5 are explicit
export/import artifacts. Their absence never means delete, and importing one
file never scans for or removes remote content that the file omits.

Consequences:

- `state` remains rule and exception-list state only.
- `export` reads a selected set and writes a portable artifact.
- `import` acts only on object ids present in its file.
- `delete` is the only deletion instruction.
- No background dependency remapping occurs. Typed dashboards keep their
  referenced ids; the operator creates matching ids or uses an opaque bundle.

## 3. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Data-view identity | Stored data-view `id` | Dashboard references use this id; title and name are mutable |
| Dashboard identity | Dashboard `id` | `PUT /api/dashboards/{id}` is the stable upsert contract; titles are not unique |
| Selector fallback | Exact data-view name or exact dashboard title | Convenient for humans without weakening stored identity; ambiguity is a conflict |
| Portable format | Stable JSON array by default, YAML sequence on request | Both are reviewable and preserve the same typed values |
| Dashboard primary route | GA Dashboards API | It is the supported, typed, reviewable API from Elastic 9.5 |
| Dependency-inclusive route | Explicit Saved Objects NDJSON bundle | It preserves related objects and migration metadata but is intentionally opaque |
| Import conflicts | Refuse by default; `--overwrite` replaces; `--skip-existing` omits | Matches existing rule and exception import behavior |
| Data-view deletion | Refuse live references unless `--replace-with` is supplied | Kibana otherwise deletes the data view and leaves broken dashboards |
| Typed dashboard loss | A 2xx response that drops submitted state is a failed, lossy apply | Kibana can accept unsupported content while discarding it |
| Version floor | `Feature::Dashboards` requires Kibana 9.5.1 | 9.5 is GA and 9.5.1 is the measured self-managed compatibility floor |

## 4. Command surface

```text
elasticctl data-views list [--search TEXT]
elasticctl data-views get <id|name>
elasticctl data-views validate --path FILE
elasticctl data-views export [<id|name>...] [--format-file json|yaml]
elasticctl data-views import --path FILE [--overwrite|--skip-existing]       [guarded]
elasticctl data-views delete <id|name>... [--replace-with <id|name>]         [guarded]
elasticctl data-views default get
elasticctl data-views default set <id|name>                                 [guarded]
elasticctl data-views default unset                                         [guarded]

elasticctl dashboards list [--search TEXT] [--tag ID] [--limit N]
elasticctl dashboards get <id|title>
elasticctl dashboards validate --path FILE
elasticctl dashboards export [<id|title>...] [--format-file json|yaml]
elasticctl dashboards import --path FILE [--overwrite|--skip-existing]      [guarded]
elasticctl dashboards delete <id|title>...                                  [guarded]
elasticctl dashboards bundle export [<id|title>...]
elasticctl dashboards bundle import --path FILE [--overwrite]               [guarded]
```

The global `--out` selects an export destination, as it does for rules and
exceptions. Without `--out`, stdout is the artifact verbatim under every
global renderer format. `--format-file` controls only the portable file and
defaults to `json`. Bundle export is always NDJSON and rejects
`--format-file`; bundle import chooses no format from the extension.

An export with no selectors means every object of that type in the active
space. Every selector must resolve. A short export is an error rather than a
successful subset.

Mutating commands reject an empty target before building a transport. Bundle
import rejects a file with no dashboard object. `default unset` is explicit;
an empty argument never means unset.

## 5. Data-view model and portable artifact

`GET /api/data_views/data_view/{id}` returns stored settings mixed with
server-owned values and a generated field cache. A portable artifact is a JSON
array, or the same array as a YAML sequence, of `DataViewSpec` objects sorted by
`id`:

```json
[
  {
    "id": "security-events",
    "title": "logs-security-*",
    "name": "Security events",
    "timeFieldName": "@timestamp",
    "allowNoIndex": true,
    "allowHidden": false,
    "sourceFilters": [],
    "fieldFormats": {},
    "runtimeFieldMap": {},
    "fieldAttrs": {}
  }
]
```

`id` and `title` are required non-empty strings. The other writable settings
are optional in input and retain Kibana's camelCase names: `name`,
`timeFieldName`, `allowNoIndex`, `allowHidden`, `sourceFilters`,
`fieldFormats`, `runtimeFieldMap`, `fieldAttrs`, `type`, and `typeMeta`.
Validation canonicalizes missing `allowNoIndex` and `allowHidden` to `false`,
and export always writes both booleans. It canonicalizes an empty `typeMeta`
object to absence. Unknown top-level fields are rejected locally so a
misspelling cannot become a silent omission. Nested maps remain open because
field formatter, runtime-field, and rollup schemas are extensible server
contracts.

`typeMeta`, each `fieldAttrs` value, and each portable `fields` value must be
objects. Every portable `fields` entry must contain `scripted: true`; an
artifact cannot smuggle a generated mapped-field cache back into Kibana.

Normalization removes:

- `version`, because it is a saved-object concurrency token;
- `namespaces`, because the active profile and URL choose the target space;
- generated mapped entries from `fields`, because they are a cache of the
  source stack's mapping and permissions.

Legacy scripted fields are the only possible portable part of `fields`.
Before 0.5.0 ships, the recorder must prove that entries with
`scripted: true` survive create, get, update, and export on all three flavors.
If they do, `DataViewSpec` carries only those entries under `fields`. If any
flavor loses them, portable export refuses a data view containing one with an
`unsupported` error. It never copies the full mapped-field cache.

Import sends explicit ids, so dashboards can keep the same reference across
environments. Create uses `POST /api/data_views/data_view` with the canonical
file spec under `data_view`. Marker probes prove that create preserves
`allowHidden: true` on Serverless 9.6.0 and Hosted 9.5.2 even though the
published create schema omits that property. The self-managed recorder must
confirm the same result before 0.5.0 ships.

Update is not full replacement. `POST /api/data_views/data_view/{id}` is a
partial route that accepts `allowNoIndex`, `fieldFormats`, `fields`, `name`,
`runtimeFieldMap`, `sourceFilters`, `timeFieldName`, `title`, `type`, and
`typeMeta`. elasticctl sends only changed properties from that set with
`refresh_fields: true`. It never sends `id`, `allowHidden`, or `fieldAttrs` to
that route.

Field attributes use a second request:
`POST /api/data_views/data_view/{id}/fields`. elasticctl builds a metadata
delta over the union of the current and desired field names and metadata
keys. Desired values are sent as-is. A current key missing from the desired
spec is sent as `null`, which removes it. An empty delta causes no request.

The public update API has no documented way to clear `name`, `timeFieldName`,
`type`, or a non-empty `typeMeta`. It also has no way to change
`allowHidden`; marker requests with that property answer 400 on Serverless
9.6.0 and Hosted 9.5.2. Missing and `false` `allowHidden` values are
equivalent. Any other overwrite that changes `allowHidden`, or removes one of
the optional properties without a documented clearing value, fails as
`unsupported` during planning. Import never deletes and recreates a data view
to evade that limit.

After create, or after all required update requests, import GETs and
normalizes the stored data view. It requires exact equality with the desired
canonical spec. Once a mutation route has returned a decoded success, a later
metadata failure or comparison mismatch is a failed row with `applied: true`;
elasticctl does not roll back an earlier write.

## 6. Dashboard model and portable artifact

The typed Dashboards API returns `{id, data, meta}`. `meta` is server-owned
creation, update, ownership, and warning context. The portable artifact keeps
only identity and the API-compatible body:

```json
[
  {
    "id": "security-overview",
    "data": {
      "title": "Security overview",
      "description": "Detection activity",
      "panels": []
    }
  }
]
```

`DashboardSpec.id` is a required non-empty string. `DashboardSpec.data` is a
JSON object with a required non-empty string `title`. The dashboard body stays
as an ordered `serde_json::Map`: elasticctl must preserve new GA fields it does
not yet know instead of down-converting the public schema. The wrapper is typed
and validated; the evolving panel union remains the server's typed contract.

Export fetches every selected dashboard individually after list resolution,
sorts by id, removes `meta`, and writes stable JSON or YAML. If the GET response
contains any `warnings[].message`, export refuses the typed artifact and names
the dashboard plus every warning. The error directs the operator to
`dashboards bundle export`, because the public transformation has already
removed the unsupported content.

Portable import rejects `time_range.mode` before mutation. Kibana accepts that
field for validation but does not persist it, so accepting it would guarantee
a false round trip. Other submitted values must survive the server response as
a recursive subset; extra derived response fields are allowed.

## 7. Opaque dashboard bundles

`dashboards bundle export` calls `POST /api/saved_objects/_export` with an
explicit `objects` array of selected `{type: "dashboard", id}` entries,
`includeReferencesDeep: true`, and `excludeExportDetails: false`. It emits the
response bytes unchanged. Deep references can include data views, library
visualizations, searches, tags, and other saved objects.

`dashboards bundle import` calls `POST /api/saved_objects/_import` as multipart
NDJSON. The default leaves `overwrite=false`; `--overwrite` sets it to true.
`createNewCopies` and `compatibilityMode` are out of scope for 0.5 because they
change identity or migration semantics.

The bundle is opaque but not unchecked. Before the guard, elasticctl scans
each non-empty line without rewriting it and requires:

- valid JSON objects;
- string `type` and `id` on every saved-object line;
- at least one `type: "dashboard"` object;
- at most one export-details trailer with numeric `exportedCount` and
  `missingRefCount` plus array `missingReferences`, last when present.

The scan reports object counts and dashboard ids in the preview. It must not
deserialize and reserialize saved-object attributes, remove migration fields,
or reorder lines. The exact file bytes resolved before the guard are the bytes
uploaded after `--yes`.

Saved-object bundles are version-sensitive. Import compatibility is the
server's documented rule: same version, a newer minor in the same major, or
the next major. elasticctl reports the server's per-object errors and does not
attempt migrations itself.

## 8. Selection, listing, and resolution

Data-view list reads `GET /api/data_views`, applies `--search` locally as a
case-insensitive substring over `id`, `name`, and `title`, sorts by id, and
renders summaries with `id`, `name`, `title`, and `time_field_name`. The route
has no pagination.

Data-view resolution tries exact id first. If that misses, it matches exact
name. Zero matches is `not_found`; multiple name matches is `conflict`. The
existing `search --data-view` resolver moves onto this shared implementation
without changing its output or error text.

Dashboard list pages `GET /api/dashboards` with `per_page=1000`, passing
`query`, `tags`, `page`, and the optional user `--limit`. It sorts by id after
collecting. Summaries render `id`, `title`, `description`, and `tags` when
present. `--search` maps to the API's `query` parameter; `--tag` maps to its
repeated tag filter.

Dashboard resolution tries exact id with `GET /api/dashboards/{id}` first. If
that misses, it searches and keeps exact title matches. Zero is `not_found`;
more than one is `conflict` naming the duplicate ids. A title selector never
becomes stored identity.

Selectors are deduplicated by stable id after resolution. All selectors
resolve before an export, delete, or import apply can begin.

## 9. Mutation guard, imports, and races

Every remote mutation uses `guard::check`. Preview and apply print profile,
host, and space. The guarded paths are:

```text
data-views import
data-views delete
data-views default set
data-views default unset
dashboards import
dashboards delete
dashboards bundle import
```

Portable import fully reads and validates the file before any server call.
With neither conflict flag, any existing id makes the plan fail before the
guard. `--skip-existing` reads the server, removes existing ids from the
pending set, and reports them as skipped. `--overwrite` classifies each object
as create, replace, or no-op and previews that exact action.

The resolved file body and preflight snapshots travel in the plan. Apply does
not re-read the path after the guard. Immediately before each write, it re-GETs
that object:

- a planned create refuses if the id appeared since preview;
- a planned replace or no-op refuses if the current canonical value differs
  from the preview snapshot;
- a missing planned replacement is a conflict, not a create.

The public APIs expose no conditional-write token for these operations. A
change can still race the final GET and write. Reports call this out as the
smallest unavoidable window. Multi-object imports are not transactions: they
continue after per-object failures and report every succeeded, skipped,
failed, and lossy object. They do not roll back successful earlier writes.
Each failed row in a portable JSON/YAML import carries `applied: false` until
a mutation route for that object has returned a decoded success, and
`applied: true` after that point. This flag confirms a known earlier write; it
does not claim that a timed-out or malformed response made no remote change.
Opaque bundle errors retain the server's object shape instead.

Dashboard PUT can answer 2xx after discarding submitted content. After every
successful PUT, elasticctl recursively checks that the submitted body is a
subset of `response.data`. A missing or changed submitted value produces a
report row with `applied: true`, `lossy: true`, and a field path. elasticctl
then GETs the dashboard once and appends any `warnings[].message`. Lossy is a
failure and exits non-zero. It is not rolled back because restoring the prior
snapshot could overwrite a concurrent change and still cannot recreate a
panel the public API cannot express.

## 10. Reference-safe data-view deletion

Kibana's direct data-view DELETE succeeds even while dashboards still refer to
the id. The dashboard remains but is broken. elasticctl therefore treats
reference discovery as part of the deletion plan.

For each source id, the client calls
`POST /api/data_views/swap_references/_preview` with `fromId` and `toId` both
equal to the source. Live measurement proves this self-swap is accepted and
returns every referring saved object's `id` and `type` without changing it.

Without `--replace-with`:

- any returned reference refuses the deletion and lists all dependents;
- a source that is the current default also refuses and directs the operator
  to `default unset` or `--replace-with`;
- an unreferenced, non-default source previews a direct DELETE.

With `--replace-with TARGET`:

- the target resolves before the guard and must differ from every source;
- one source may be replaced per command, so multiple source selectors with
  `--replace-with` are rejected;
- the preview lists every affected saved object and a default change when
  applicable;
- apply calls `POST /api/data_views/swap_references` with
  `{fromId, toId, delete: true}`;
- success requires `deleteStatus.deletePerformed == true` and
  `deleteStatus.remainingRefs == 0`;
- if the source was default, apply sets the default to the target only after
  the swap succeeds. A default-set failure is reported as partial: references
  moved and source deleted, default not updated.

`data-views default set` resolves the selector and sends its id with
`force: true`. `default unset` sends `data_view_id: null` with `force: true`.
The client validates ids because Kibana's endpoint does not.

## 11. Architecture

Dependency direction remains:

```text
elasticctl-cli  ->  elasticctl-api  ->  elasticctl-core
```

`elasticctl-api` owns the verticals:

- `content_codec` encodes and decodes portable JSON/YAML without CLI types;
- `data_views` owns route wrappers and response models;
- `data_views_ops` owns selection, normalization, import, default, and delete
  orchestration;
- `dashboards` owns typed dashboard route wrappers and strict decoders;
- `dashboards_ops` owns selection, portable transfer, race checks, loss
  detection, and delete orchestration;
- `saved_objects` owns opaque export/import wrappers and the read-only bundle
  scan.

`elasticctl-cli::cmd::{data_views,dashboards}` resolve context, invoke API
plans, apply the guard, serialize typed results, and hand values to `render`.
They do not orchestrate stacks or parse server response bodies.

`elasticctl-core` gains only a named-filename multipart helper needed by the
Saved Objects import. The existing rules and exceptions wrapper continues to
send the same body and headers through that helper. No content model enters
`-core`.

The `DashboardSpec.data` and extensible nested data-view maps are JSON values,
but command outcomes and route envelopes are typed structs. No orchestration
function returns a pre-rendered string except an artifact body whose verbatim
bytes are the command's product.

## 12. Errors and reports

Existing error kinds apply:

- `not_found`: selector or referenced data-view id missing;
- `conflict`: ambiguous selector, existing import id, changed preflight
  snapshot, or unsafe referenced deletion;
- `unsupported`: Dashboards API below 9.5.1, warning-bearing typed export, an
  unportable legacy scripted field, or a data-view overwrite the public update
  routes cannot express;
- `http`: malformed success response, failed loss invariant, or transport
  response outside the documented shapes;
- `error`: malformed local artifact or invalid command combination.

List and get return ordinary typed values through `render`. Validate returns
`{valid, total}` plus per-kind bundle counts. Export with `--out` returns
`{exported, path, failed}`; without it, stdout is the artifact. Import reports
`{applied, succeeded, skipped, failed, lossy, total}`. Delete reports
`{applied, deleted, failed, total}`. A non-empty `failed` or `lossy` collection
sets exit 1 through the existing main-result policy.

No report contains saved-object attributes from an opaque bundle. Its preview
and result may name only `type`, `id`, counts, and server error text.

## 13. Fixtures and conformance

Fixtures are recorded from real traffic for Serverless, Hosted, and
self-managed deployments. The recorder creates only unique
`elasticctl-sample-*` data-view and dashboard ids and an
`*elasticctl-sample*` index. Every request is explicitly scoped to those ids.
An unscoped dashboard list or Saved Objects export must never enter public
fixtures.

The 0.5.0 fixture set covers:

- data-view list, create with explicit id and `allowHidden: true`, get, partial
  update, field-metadata merge and null deletion, default get/set/unset,
  self-swap preview, replacement swap, direct delete, and 404;
- generated-field normalization and the scripted-field decision in section 5;
- default restoration and zero marker residue.

The 0.5.1 fixture set covers:

- dashboard search, PUT create (201), GET, PUT update (200), DELETE (204), and
  404;
- a typed metric panel using
  `{type: "data_view_reference", ref_id: "elasticctl-sample-data-view"}`;
- strict typed round trip and one measured accepted-but-lossy payload;
- Saved Objects deep export containing exactly the marker dashboard, its
  marker data view, and the export-details trailer;
- Saved Objects import success and conflict response shapes;
- zero dashboard and data-view marker residue.

The ninth matrix contract is
`content_transfers_data_views_and_dashboards_without_residue`. It:

1. refuses a dirty target containing any `elasticctl-live-*` data view or
   dashboard;
2. creates a marker index and explicit-id data view;
3. captures the current default, sets the marker default, then restores it;
4. creates a typed dashboard with one metric panel referring to the marker
   data-view id;
5. gets, lists, exports, updates, and strictly round-trips that dashboard;
6. deep-exports the dashboard and proves the bundle contains its data view;
7. previews the self-swap, creates a second marker data view, replaces the
   dashboard reference while deleting the first, and verifies the dashboard
   now resolves to the second id;
8. deletes the dashboard and second data view;
9. deletes the marker index and proves the original default is restored;
10. concludes with zero marker dashboards, data views, or indices and the
    unchanged prebuilt-rule baseline.

Cleanup registers ids before each mutation. It deletes dashboards before data
views and restores the captured default before deleting a default marker view.
The content contract tolerates no residue.

`xtask::CONTRACTS` grows eight to nine with `name: "content"` and
`features: &[DASHBOARDS]`, where `DASHBOARDS` wraps `Feature::Dashboards`.
`scripts/check-conformance-reports.sh`
adds the nine-contract `v0.5` family. Reports commit under
`docs/conformance/v0.5.2/`.

## 14. Measured behavior

Read and marker-scoped mutation probes ran on 2026-09-02 against Serverless
9.6.0, Elastic Cloud Hosted 9.5.2, and the self-managed lab 9.5.1. Every probe
cleaned up its dashboard and data view; the lab was torn down with its volumes.

| Fact | Measured result |
|---|---|
| Data-view lifecycle | Create with explicit id, list, get, update, and delete succeed on all three flavors; create/update/delete answer 200 |
| Data-view response | Carries `id`, `title`, the configured optional values, formats, runtime fields, field attributes, generated `fields`, `namespaces`, and `version`; absent and false `allowHidden` normalize to false |
| Hidden-index create | `allowHidden: true` is accepted and survives GET on Serverless 9.6.0 and Hosted 9.5.2; both probes cleaned up |
| Hidden-index update | Sending `allowHidden` to the partial update route answers 400 on Serverless 9.6.0 and Hosted 9.5.2; the stored false value is unchanged |
| Field metadata | The `/fields` route updates count and description and removes a label sent as `null` on Serverless 9.6.0 and Hosted 9.5.2; both probes cleaned up |
| Reference preview | Self-swap (`fromId == toId`) answers 200 and returns the marker dashboard dependent without mutation |
| Unsafe direct delete | Direct DELETE of a referenced marker data view answers 200; the dependent dashboard remains readable and broken |
| Dashboard create/update | `PUT /api/dashboards/{id}` answers 201 on create and 200 on replacement; replacement is full, not patch semantics |
| Dashboard response | Top level is `{id, data, meta}` for the measured supported dashboard |
| Dashboard search | `GET /api/dashboards` answers the documented paginated `{data, meta}` shape |
| Dashboard delete | Answers 204 with an empty body on all three flavors, despite documentation that still lists 200 |
| Deep export | Marker dashboard export with `includeReferencesDeep` contains one `dashboard`, one `index-pattern`, and one export-details trailer |
| Transport empty body | Existing response handling maps a successful empty body to `Value::Null`; no dashboard-specific 204 exception is needed |

Still required before the corresponding release ships:

- 0.5.0: scripted-field round trip, default restoration, and the two
  data-view update-route facts above on self-managed 9.5.1;
- 0.5.1: one accepted-but-lossy typed dashboard payload and Saved Objects
  import success/conflict on every flavor;
- 0.5.2: the complete ninth contract and matrix reports.

## 15. Version placement

| Version | Content |
|---|---|
| 0.5.0 | Complete data-view administration and portable transfer; safe reference-aware delete; default get/set/unset |
| 0.5.1 | Complete typed dashboard administration and portable transfer; explicit dependency-inclusive Saved Objects bundles |
| 0.5.2 | Content conformance contract, cross-flavor matrix, bounded review patch |

The release target list is unchanged from 0.4.2 and that release has a complete
asset set, so 0.5.x needs no release candidate unless packaging or targets
change. A release still does not publish to crates.io without explicit approval
for that exact version.

## 16. Decisions log

1. **Product boundary:** transfer and administration, not `state`
   reconciliation.
2. **Format:** typed JSON/YAML by default; separate opaque NDJSON bundles for
   dependency-inclusive migration.
3. **Cut line:** 0.5.0 data views, 0.5.1 dashboards, 0.5.2 proof and review.
4. **Loss:** warning-bearing export refuses; accepted-but-dropped import is an
   applied, lossy failure.
5. **Delete:** referenced data views require explicit replacement; direct
   broken-reference deletion is never exposed.
6. **Floor:** typed dashboards require measured Kibana 9.5.1 or newer.

## 17. References

Consulted 2026-09-02:

- Dashboards API overview and GA status:
  https://www.elastic.co/search-labs/blog/dashboards-as-code-kibana-api
- Dashboard export formats and unsupported-property warning behavior:
  https://www.elastic.co/docs/explore-analyze/dashboards/sharing
- Dashboard import formats and dependency requirements:
  https://www.elastic.co/docs/explore-analyze/dashboards/import-dashboards
- Dashboard-as-code stable-id guidance:
  https://www.elastic.co/docs/explore-analyze/dashboards/manage-dashboards-as-code
- Dashboard API endpoints:
  https://www.elastic.co/docs/api/doc/kibana/group/endpoint-dashboards
- Data-view API endpoints:
  https://www.elastic.co/guide/en/kibana/current/index-patterns-api-update.html
- Create data view request and response:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-createdataviewdefaultw
- Update data view request and response:
  https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-updatedataviewdefault
- Update data-view field metadata:
  https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-updatefieldsmetadatadefault
- Field-metadata merge and null-removal semantics:
  https://www.elastic.co/guide/en/kibana/8.19/index-patterns-fields-api-update.html
- Default data-view mutation:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-setdefaultdatailviewdefault
- Data-view reference swap:
  https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-swapdataviewsdefault
- Data-view deletion warning:
  https://www.elastic.co/docs/explore-analyze/find-and-organize/data-views
- Saved Objects export:
  https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-exportsavedobjectsdefault
- Saved Objects import:
  https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-importsavedobjectsdefault
- Accepted-but-lossy dashboard PUT evidence and subset-audit design:
  https://github.com/elastic/observability-migration-platform/blob/main/docs/targets/kibana.md
