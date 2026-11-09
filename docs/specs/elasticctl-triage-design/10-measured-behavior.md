[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 10. Measured behavior

Read probes and live triage mutations, most recently 2026-09-01 (Task 8),
against the trial Serverless project (9.6.0), the Hosted deployment (9.5.2 —
9.5.1 when first read-probed, before the deployment moved mid-project), and
the traditional lab (9.5.1), with the stacks' project/deployment API keys.
Task 8 exercised every triage mutation route for real: a marker rule over a
marker index generated genuine alerts on all three flavors, each transitioned
by id, tagged, assigned, then closed by query; every flavor verified baseline
before and after (no leftover marker rule or index, no non-closed marker
alert — closed residue is the accepted deviation, section 9). Rows marked
*unverified* are documented shapes not yet exercised.

Task 6 (0.4.1, 2026-09-01) extended this to the complete case-mutation
family: the recorder attaches one of the alerts probe's still-open marker
alerts to a freshly created case before the alerts probe closes it, driving
create, the scoped find, comment, attach, status change, delete, and the
version/409 conflict path for real on all three flavors. Every flavor still
verified baseline before and after — including the case-specific zero-residue
rule (section 9): unlike alerts, a marker case tolerates no residue at all,
closed or otherwise.

| Fact | Detail |
|---|---|
| Alert search route | `POST /api/detection_engine/signals/search` returns the raw ES envelope `{took, timed_out, _shards, hits}` — 200 with and without `elastic-api-version`, and 200 even without `kbn-xsrf` on Serverless (the transport still always sends it). Measured 2026-09-01 with populated hits from a live marker rule on all three flavors, sending the actual `alerts_ops` production body (`default_sort()` plus `resolve_ids`'s `_source` include, not a hand-rolled shape): the `kibana.alert.uuid` sort tiebreaker does not error, and the dotted `_source` include (`kibana.alert.rule.name`, `kibana.alert.workflow_status`) returns exactly those two flat dotted keys per hit, proving the include works against flat keys rather than being interpreted as a nested path. `_id` uniquely identifies each alert instance |
| Search body acceptance | `sort`, `search_after`, `_source`, `track_total_hits`, `size`, `aggs`, and `runtime_mappings` all accepted (200) |
| Triage fields | The alerts index mapping carries `kibana.alert.workflow_status`, `workflow_tags`, `workflow_assignee_ids`, `workflow_status_updated_at`, `workflow_user`, `workflow_reason`, and `kibana.alert.case_ids`; 50 `kibana.alert.*` field groups total |
| Query-scoped status | `POST /api/detection_engine/signals/status` with `{status, query, conflicts}` → 200 with a raw update-by-query envelope: `{took, timed_out, total, updated, deleted, batches, version_conflicts, noops, retries, throttled_millis, requests_per_second, throttled_until_millis, failures}`. Zero-match returns all-zero counts. Identical shape on Serverless 9.6.0 and Hosted 9.5.2 |
| Status body (docs) | `signal_ids` and `query` are one-of; `conflicts` is `abort` (default) or `proceed`; `status` allows `open`, `acknowledged`, `in-progress`, `closed`; `reason` is a documented enum (`false_positive`, `duplicate`, `true_positive`, `benign_positive`, `automated_closure`, `other`) plus free text 1–1024 chars |
| Status body, `signal_ids` form (measured) | `reason` is accepted alongside `signal_ids`, not just `query` — measured 2026-09-01 on Serverless 9.6.0, Hosted 9.5.2, and the traditional lab 9.5.1: `POST signals/status` with `{signal_ids, status, reason}` returns 200, never a 400. `alerts::status_by_ids` already sends `reason` unconditionally; no code change needed |
| Profile suggest, public | `POST /_security/profile/_suggest` → 200 `{total, took, profiles: [{uid, user: {username, realm_name, roles, …}, data, labels, enabled}]}` on Hosted (9.5.1, then 9.5.2) and the traditional lab (9.5.1, measured 2026-09-01). On Serverless → **410** `api_not_available_exception` "not available when running in serverless mode" |
| Profile suggest, internal | `GET /internal/detection_engine/users/_find?searchTerm=` → 200 `[{data, enabled, uid, user}]` on all three flavors; **without** `x-elastic-internal-origin` the internal route family answers 400 "exists but is not available". `POST /internal/cases/_suggest_user_profiles` (with `{name, size, owners}`) behaves the same |
| Profile activation | Each cloud stack shows exactly one activated profile (the SSO login); the API-key identities used by elasticctl have none. Empty `searchTerm` returns all activated profiles. Measured 2026-09-01 on the traditional lab: a fresh stack activates none — a raw Elasticsearch API key or an HTTP Basic call to a Kibana route does **not** trigger activation; only `POST /internal/security/login` (with `x-elastic-internal-origin: Kibana`, since it is itself a restricted internal route) does |
| Login provider name | `POST /internal/security/login` takes the provider's configured *name*, not its type, and answers `401 Unauthorized` for a name the deployment does not configure. Measured 2026-09-01 with identical credentials: the self-managed lab names it `basic`; Hosted names it `cloud-basic` and rejects `basic` with 401. `GET /internal/security/login_state` reports the configured providers on both, listing the basic provider even when `selector.enabled` is `false` |
| Profile by uid | `GET /_security/profile/<uid>` on Hosted → 200 `{profiles: [...]}` |
| Cases find | `GET /api/cases/_find` → `{cases, page, per_page, total, count_open_cases, count_in_progress_cases, count_closed_cases}`; accepts `perPage`, `page`, `sortField`, `sortOrder`, `status` |
| Cases find, scoped (measured) | The exact params `cases_ops::find_query` sends — `search=<title>&searchFields=title&searchFields=description&tags=<tag>` plus `page`/`perPage`/`sortField`/`sortOrder` — correctly scope the find to the marker case alone on all three flavors. Measured 2026-09-01 (Task 6) |
| Cases reads | `GET /api/cases/tags` and `/api/cases/reporters` → arrays; `GET /api/cases/configure` → array; `GET /api/cases/alerts/<absent id>` → 200 `[]`, not 404 |
| Alerts index | `GET /api/detection_engine/index` → `{name: ".alerts-security.alerts-default", index_mapping_outdated: false}` |
| Tags mutation | `POST /api/detection_engine/signals/tags` with `{ids, tags: {tags_to_add, tags_to_remove}}` → 200 with the same raw update-by-query envelope as `signals/status`. Measured 2026-09-01: added `triage-check` to a real marker alert by `_id` on Serverless 9.6.0, Hosted 9.5.2, and the traditional lab 9.5.1 |
| Assignee mutation | `POST /api/detection_engine/signals/assignees` with `{assignees: {add, remove}, ids}` — uids only, same envelope shape. Measured 2026-09-01: assigned then unassigned a real activated profile uid (from `users/_find`) to a marker alert by `_id` on all three flavors. Add and remove of the same uid in one request was not exercised live; still documented as rejected per the API reference (section 13) |
| Case create (measured) | `POST /api/cases` requires `title`, `description`, `tags`, `assignees`, `connector` (`{id, name, type, fields}`), `settings.syncAlerts`, and `owner`; `severity` is accepted. Measured 2026-09-01 (Task 6) on Serverless 9.6.0, Hosted 9.5.2, and the traditional lab 9.5.1: creating with one profile-uid assignee and `severity: "low"` returns 200 with the full case object, an opaque `version` token, and `totalComment`/`totalAlerts` at 0 |
| Case status mutation and conflict (measured) | `PATCH /api/cases` with `{cases: [{id, version, status}]}` → 200 with an array of updated cases carrying a new `version`. Reusing an already-consumed `version` for a second PATCH answers **409** `conflict`, message `"These cases <id> have been updated. Please refresh before saving additional updates."` — measured 2026-09-01 (Task 6) on all three flavors. The documented optimistic-concurrency contract holds exactly as `apply_status` already assumes; no code change needed |
| Case delete (measured) | `DELETE /api/cases?ids=["<id>"]` (the id array JSON-encoded, then the whole query value URL-encoded) → 204 with an empty body. Measured 2026-09-01 (Task 6) on all three flavors; a `GET` by id afterward is a classified 404 and the scoped find (above) reports zero |
| Case comment and attach (measured) | `POST /api/cases/<id>/comments` with `{type: "user", comment, owner}` or `{type: "alert", alertId, index, rule: {id, name}, owner}` both return 200 with the updated case, whose `comments` array carries the new entry (its own `id`/`version`, `created_at`/`created_by`). Measured 2026-09-01 (Task 6) on all three flavors, attaching a real still-open marker alert. Attaching also writes `kibana.alert.case_ids` back onto that alert document: the alerts probe's own close-by-query, which runs immediately after, can race that write and hit a transient version-conflict 409 on exactly the attached alert — the recorder retries the close (up to 5 times, 3 seconds apart) to absorb it; this is a live-system timing fact, not a contract change |

Remaining live verification: 0.4.0's own routes (`signals/search`, the
`signals/status` id and query forms, `signals/tags`, `signals/assignees`, and
both profile-resolution routes) are measured across all three flavors
(Task 8), and so is the actual `alerts_ops` read body sent on `signals/search`
— `default_sort()`'s `kibana.alert.uuid` sort tiebreaker and the dotted
`_source` include `resolve_ids` sends both round-tripped against a live stack,
not a hand-rolled probe shape. The case mutation family — create, the scoped
find, comment, attach, status change, delete, and the version/409 conflict
behavior — is measured too now (Task 6, 2026-09-01). Still unmeasured against
a live stack: `list`/`export`'s `size: limit + 1` sizing, and the `ids` query
form `resolve_ids`/`get_one` send (`{"query": {"ids": {"values": [...]}}}`).
These remain out of scope for this release but should still land **before
2026-09-08 08:56 UTC** (after that, only a lab session remains and Serverless
evidence is lost), since measured facts outlive the trial.

