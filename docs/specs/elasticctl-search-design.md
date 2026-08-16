# elasticctl search — design

`search` is the 0.3 capability area: ad hoc data search, the query layer a
detection engineer uses for hunting. It runs ES|QL and Query DSL against an
Elasticsearch deployment and returns results, as a bounded terminal peek or a
bulk export to file. It is read-only — no mutation guard, no `--yes`.

This document is the source of truth for `search`. It sits beside
[`elasticctl-design.md`](elasticctl-design.md), which stays authoritative for
scope, architecture, and the shared transport. Where the two disagree on
search, this document wins.

## 1. Scope

In 0.3.0: `search esql` and `search dsl`, both read-only.

Out of scope (later minor versions): alert triage and cases (0.4), dashboards
and data views management (0.5), and search-time enrichment or saved-search
management. Search *reads* data views; it never creates or edits them.

## 2. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Languages | ES|QL and Query DSL, both in 0.3.0 | Matches the roadmap; DSL is universal, ES|QL is the forward-looking language |
| Result model | Native shape per language | ES|QL is columnar, DSL is documents; forcing one shape invents a flattening policy no one asked for |
| Target | Explicit `--index`, or `--data-view` resolution, or the query's own source, or the space's alerts index | Engineers name indices directly, but data views and the alerts default are the friendly paths |
| Pagination | DSL uses PIT + `search_after`; ES|QL uses `LIMIT` (sync) and the async API for bulk | Measured: ES|QL sync has no cursor (§9) |
| Transport | Reuse `post_absolute_es` / `get_absolute_es` | ES endpoints need no `kbn-xsrf` and no `elastic-api-version`; the existing absolute-ES methods already do this |
| Rendering | Reuse the existing `render` layer (`table`/`json`/`yaml`/`csv`/`jsonl`, `--fields`, `--out`) | One renderer for the whole CLI; ES|QL's columns become row objects, DSL's `_source` becomes documents |

## 3. Command surface

```
elasticctl search esql '<query>'
    [--index NAME] [--data-view NAME] [--limit N]
    [--format table|json|yaml|csv|jsonl] [--fields a,b] [--out FILE]
    [--profile --config --space --timeout --debug --json]

elasticctl search dsl '<json|@file>'
    [--index NAME] [--data-view NAME] [--limit N]
    [--format table|json|yaml|csv|jsonl] [--fields a,b] [--out FILE] [--with-meta]
    [--profile --config --space --timeout --debug --json]
```

`dsl` accepts a JSON body inline or `@path` for a file. The body is the Query
DSL request body (`query`, `sort`, `size`, `_source`, …).

`--limit` caps the number of rows returned to the caller — rendered in a peek,
written in an export. Default is 100 for a peek. It never rewrites the query:
the query's own `LIMIT`/`size` still governs what the server returns.

`--index` and `--data-view` are mutually exclusive. `--fields` and `--format`
behave exactly as on every other command: `--fields` projects the rendered
rows, `--format` picks the encoding.

## 4. Target resolution

Exactly one source names the index/alias/pattern list, in this order:

1. `--index NAME` — explicit, wins over everything.
2. `--data-view NAME` — resolved through the Kibana data views API to its
   `title`, which is the comma-separated index pattern.
3. The query's own source — ES|QL `FROM <source>`. DSL has no in-body
   source: its target is the search path (`POST /<pattern>/_search`).
4. Default — the space's alerts index, `.alerts-security.alerts-default`,
   read from `GET /api/detection_engine/index`.

Injection is language-specific:

- **DSL** — the resolved pattern becomes the search path
  (`POST /<pattern>/_search`).
- **ES|QL** — the query already begins with a source command (`FROM`, `ROW`,
  `SHOW`, `METRICS`); if it does not, `FROM <pattern>` is prepended. A query
  that already names a source is passed through untouched unless `--index` or
  `--data-view` is given, in which case its `FROM` clause is rewritten.

Resolution of a data view is by `id` or `name` (the human label), exact match,
via `GET /api/data_views`. The resolved index pattern is the view's `title`.
A name matching neither is `not_found`; a name matching more than one is
`conflict`. The default applies only when neither `--index` nor `--data-view`
is given and the query names no source.

## 5. Result models

**ES|QL** returns `{columns: [{name, type}], values: [[…], …]}`. The client
converts it to a list of row objects `{name: value}` for the renderer. Column
order comes from `columns`; duplicate column names (a `text` field emits both
`message` and `message.keyword`) are preserved by position and disambiguated by
suffix when rendered.

**DSL** returns `{hits: {hits: [{_index, _id, _score, _source, sort}, …],
total: {value, relation}}}`. The rendered row is the `_source` object; `_index`,
`_id`, `_score`, and `sort` are dropped, because `_score`, `_id`, and `sort` are
per-run noise in a bulk export. Hit metadata is opt-in from 0.3.1: `--with-meta`
surfaces `_id`, `_index`, and `_score` as extra fields. `--fields` projects the
`_source` row, which is what makes `--format csv` meaningful for documents.

## 6. Pagination and export

A **peek** (no `--out`) runs one request and renders what comes back, capped at
`--limit` (default 100). For ES|QL the client appends a server-side `LIMIT` so
a large result is never downloaded and discarded; for DSL the operator's body
is sent verbatim. The client still truncates and reports "capped at N rows"
the same way §4.1 of the main spec reports a capped rule-name search. It never
claims a complete result when it truncated one.

A **bulk export** (`--out`) streams pages to the file:

- **DSL** — open a point-in-time (`POST /<index>/_pit?keep_alive=1m`), then
  page with `search_after` over a total-order `sort`, then close the PIT
  (`DELETE /_pit`). The page `size` is 1000, capped by `--limit`. If the
  operator's body carries a `sort`, the client appends `_shard_doc` (ascending)
  when it is absent so the page order is total; otherwise the client injects
  `sort: [{"_shard_doc": "asc"}]`, a total order available on every index. A
  non-total `sort` makes `search_after` skip or repeat documents across pages,
  so the client never pages over an operator `sort` unchanged. A PIT is opened
  once and closed on every exit path, success or error.
- **ES|QL** — there is no cursor on any flavor (§9), so bulk export runs the
  query through the async API: `POST /_query/async` with a short
  `wait_for_completion_timeout` returns `{id, is_running: true}`, polled at
  `GET /_query/async/<id>` until `is_running: false`, then `DELETE
  /_query/async/<id>`. The full result arrives in one response — there is no
  page-by-page stream. The request sends `columnar: true`, so `values` is
  column-major (one array per column); the client transposes it to row objects
  and writes them to `--out`. When the effective output format is CSV, the
  request sends `format: csv` instead — an alternative to `columnar`, never
  combined with it — and the raw CSV text (header row included) is written to
  `--out` verbatim, never decoded as `{columns, values}`. Both keep the
  payload and memory footprint low. `--limit` does not truncate the raw CSV
  text; the query's own `LIMIT` still governs what the server returns.

Export writes NDJSON (JSONL) by default because it is streaming-friendly; the
operator can override with `--format`.

## 7. Errors

Elasticsearch returns `{"error": {…}, "status": <int>}`. This is a third
envelope shape alongside the Cloud edge `{"ok": false, "message": …}` and the
Kibana `{"statusCode", "error", "message"}` shapes already classified. It is
added to the classifier. A search that the server rejects — bad ES|QL syntax, a
400 on a stray `size` field, an index the key cannot read — is an `Http` error
with the server's `error` payload, not a silent empty result.

## 8. Fixtures and testing

Fixtures are recorded from live traffic through `cargo xtask record`, never
hand-written, tagged by flavor and version as today. A search probe creates a
scratch index `elasticctl-sample-search` (marker-scoped), seeds a few documents
carrying `"marker": "elasticctl-sample"`, refreshes, records the exchanges, then
deletes the index and verifies it is gone. The `require_absent_*` guard pattern
extends to the scratch index: recording refuses to run if it already exists and
is not cleanup-owned.

Volatile fields are normalized away before a fixture is written, the same rule
that strips `execution_summary` from rule exports:

- **ES|QL** — `took`, `start_time_in_millis`, `completion_time_in_millis`,
  `expiration_time_in_millis`, `cpu_nanos`, `read_nanos`, `bytes_read`,
  `values_loaded`, `documents_found`, `rows_emitted`, `is_partial`,
  `is_running`.
- **DSL** — `took`, `_shards`, `_score`, `sort` (contains the per-run
  `_shard_doc`), and any `pit_id` (opaque per run).
- **Status** — the `metrics` object (a runtime snapshot: load, memory, uptime,
  cpu counters, `last_updated`).
- **Rule/list/item** — the saved-object `id`, `created_at`, `updated_at`, and
  `execution_summary`. A space or data-view `id` is stable and stays.
- **Preview** — `previewId`, `duration`, the hit `_id`, the generated `rule_id`,
  and the per-run `kibana.alert.*` uuids, timestamps, name, reason, and url.
  `kibana.alert.rule.uuid` is redacted, not stripped, because the preview-hits
  test asserts it is present and matches the query.

Unit tests run offline against recorded fixtures. Live tests follow the existing
conformance discipline: every object is marker-scoped, the run ends by
verifying baseline — no sample indices remain.

## 9. Measured behavior

Measured 2026-08-15 against Serverless 9.6.0 with a project-scoped
Elasticsearch API key.

| Fact | Detail |
|---|---|
| ES|QL sync shape | `POST /_query` returns `{columns: [{name, type}], values: [[…]], is_partial, rows_emitted, documents_found, …}`. Column types observed: `integer`, `long`, `double`, `boolean`, `keyword`, `text`. A `text` field also emits a `<field>.keyword` column |
| ES|QL `LIMIT` | The only pagination knob is `LIMIT n` inside the query. `LIMIT 2` over 3 docs returned 2 rows |
| **ES|QL has no sync cursor** | With 3–5 docs and `LIMIT 2`, the response has no `cursor` field and `is_partial: false`. There is no `search_after` on the sync route |
| ES|QL `size` body param | Rejected: `{"query": "…", "size": 2}` returns a 400 with `{error, status}` |
| ES|QL async | `POST /_query/async` with body `wait_for_completion_timeout` set short returns `{id, is_running: true}`; `GET /_query/async/<id>` returns the full result (no cursor) with `is_running: false`; `DELETE /_query/async/<id>` cleans up. A fast query with no timeout returns the inline result with `is_running: false` and no `id` |
| ES|QL body params | `columnar`, `wait_for_completion_timeout`, `time_zone`, `locale`, `params`, and `filter` are request-body fields, not query-string params. A URL-placed `columnar` or `wait_for_completion_timeout` is a 400 `unrecognized parameter` |
| ES|QL response formats | `format=csv` (and `tsv`/`txt`) on `/_query` returns CSV directly with a header row; `columnar: true` returns `values` column-major instead of row-major |
| DSL envelope | `{took, timed_out, _shards, hits: {hits: [{_index, _id, _score, _source, sort}], max_score, total: {value, relation}}}`. `pit_id` appears only with a PIT |
| DSL PIT | `POST /<index>/_pit?keep_alive=1m` → `{id, _shards}`; `DELETE /_pit {id}` → `{succeeded, num_freed}`. Search with `pit` + `sort` + `search_after` pages cleanly; `search_after` takes the last hit's flat `sort` array |
| Data views | `GET /api/data_views` → `{data_view: [{id, title, namespaces, …}]}`. `title` is the comma-separated index pattern, e.g. `security-solution-alert-default` → `.alerts-security.alerts-default`. Serverless reports 7 data views |
| Default alerts index | `GET /api/detection_engine/index` → `{name: ".alerts-security.alerts-default", index_mapping_outdated: false}` |
| ES error envelope | `{"error": {…}, "status": <int>}` — distinct from both classified shapes |
| Refresh lag | Newly indexed documents are not searchable until refresh. The probe observed 0 hits immediately after indexing; an explicit `POST /<index>/_refresh` made them visible. Live tests must refresh or poll before asserting a hit count |
| Direct ES auth | `Authorization: ApiKey <key>` alone is sufficient for `/_query` and `/_search`; no `kbn-xsrf`, no `elastic-api-version` |
| Hosted parity | Elastic Cloud Hosted 9.5.1 (`build_flavor: "default"`) returns the same default alerts index, the same data-view `{id, name, title}` shape, and the same ES|QL sync/async contract (no cursor; body `wait_for_completion_timeout` → `{id, is_running: true}`) |

## 10. Resolution notes

The single open question from the design phase is closed. The self-managed
recording (the `traditional-9.5.1` fixture set) confirms the ES|QL sync shape
(`columns`/`values`, no cursor) and the DSL PIT page-and-close contract on a
stack reporting `build_flavor: "traditional"`. §9 records the same shapes on
Serverless and Hosted, including the async contract and the absence of any
cursor, so all three flavors now agree and nothing remains open.
