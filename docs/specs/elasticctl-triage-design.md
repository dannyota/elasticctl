# elasticctl alerts and cases design

`alerts` and `cases` form the 0.4 capability area: the triage layer a
detection engineer works after a rule fires. `alerts` reads and transitions
detection alerts; `cases` tracks investigations and binds alerts to them. Both
verticals mutate remote state, so both carry the full dry-run guard, unlike
the read-only 0.3 `search` area.

This spec follows the shape of `elasticctl-search-design.md` and defers to
`elasticctl-design.md` for architecture, transport, and shared contracts.

## 1. Scope

0.4.0 is the complete alerts vertical and nothing else:
`alerts list | get | ack | open | close | tag | assign`, including
query-scoped transitions and username-based assignment.

0.4.1 is the complete cases surface in one release:
`cases list | get | create | attach | comment | close | open | delete` and
case assignees. 0.4.2 is the triage conformance contract, the cross-flavor
matrix run, and the bounded review patch.

Each version tells one meaningful story — alerts, then cases, then proven.
0.4.0 is the first independently usable release, and a cases read stub beside
a complete alerts vertical would dilute both.

Out of scope for 0.4 entirely: dashboards and data views (0.5), rule-side
changes of any kind (attaching an exception to a rule stays a `state push`
concern), alert deletion (no public API path worth wrapping), and Timeline or
investigation-guide content.

## 2. Triage is operational, not as-code

The rules and exceptions verticals are as-code: the mirror on disk is the
source of truth and `state push` reconciles the server toward it. Triage must
not get that treatment, and the reason is directional. A rule mirror describes
*intent* — what should be deployed. An alert is an *event record*: it appears
because data matched a rule, and its lifecycle (open, acknowledged, closed) is
a workflow position, not configuration. Reconciling a directory of alerts
against a server would mean either resurrecting closed alerts or mass-closing
live ones every time the mirror went stale — both are triage decisions being
made by a file's absence, exactly the failure `state push` refuses for rules.

Cases sit in the same category: they are collaboration records with authors,
comments, and timestamps. A case pulled to disk is an export, not a mirror.

Consequences:

- No `state` integration. `state pull|diff|push` never touch alerts or cases.
- No `--overwrite`-style reconciliation verbs. Every mutation names an
  explicit id list or an explicit query.
- `alerts list --out` and `cases list --out` are exports for reporting, with
  no import counterpart.

## 3. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Alert read path | `POST /api/detection_engine/signals/search` through Kibana | Works with `kibana_url` alone on every flavor; the body is raw Query DSL so the existing DSL renderer applies; measured to accept `sort`, `search_after`, `_source`, `aggs`, `runtime_mappings` |
| Alert identity | The alert document `_id` | Alerts have no name and no stable human key; `_id` is what every mutation route takes. `rule_id` is a *filter*, not an identity |
| Status transitions | One verb per target state: `ack`, `open`, `close` | Mirrors `rules enable|disable`; the API is one route (`signals/status`) but a `--status` flag on one verb makes the guard banner ambiguous |
| Transition targeting | Explicit `_id` list, or `--query` (section 6) | Both are one route server-side; the query form delegates set resolution to the server's update-by-query, which is atomic per document and reports exact counts |
| Status vocabulary | `open`, `acknowledged`, `closed` | The route also accepts `in-progress`, the pre-8.0 name that `acknowledged` replaced; elasticctl sends only the modern three |
| Close reason | `close --reason R` | The API takes a `reason` (documented enum plus free text, 1–1024 chars); surfacing it costs one flag and the audit trail is worth it |
| Tag and assignee edits | Add/remove deltas (`--add`, `--remove`) | Matches the API shape (`tags_to_add`/`tags_to_remove`, `add`/`remove`); a replace semantic would need a read-modify-write race |
| Assignee input | Username, resolved to a profile uid; `uid:` prefix bypasses | Owner decision: usernames are required. Resolution design in section 7 |
| Case identity | Case `id` plus mandatory `version` on mutation | The cases API is optimistic-concurrency; the client fetches, then PATCHes with the fetched version, and a 409 is a typed `conflict` |
| Case attach | `cases attach <case_id> --alert <id>...` as a case mutation | Attaching is a comment of type `alert` on the case; the alert document is untouched except `case_ids` |
| Renderer | The existing `render` layer | Alert rows are `_source` documents like `search dsl`; case rows are typed structs |

## 4. Command surface

```
elasticctl alerts list   [--status open|acknowledged|closed] [--severity S]
                         [--rule <name|rule_id>] [--tag T] [--assignee USER]
                         [--since DUR|ISO] [--search TEXT] [--limit N]
                         [--format ...] [--fields ...] [--out FILE] [--with-meta]
elasticctl alerts get <alert_id>
elasticctl alerts ack    (<alert_id>... | --query <dsl|@file>)             [guarded]
elasticctl alerts open   (<alert_id>... | --query <dsl|@file>)             [guarded]
elasticctl alerts close  (<alert_id>... | --query <dsl|@file>) [--reason R]
                         [--conflicts abort|proceed]                       [guarded]
elasticctl alerts tag    <alert_id>... [--add T]... [--remove T]...        [guarded]
elasticctl alerts assign <alert_id>... [--add USER]... [--remove USER]...  [guarded]

# 0.4.1 — the complete cases surface
elasticctl cases list    [--status open|in-progress|closed] [--severity S]
                         [--tag T] [--search TEXT] [--limit N]
elasticctl cases get <case_id>
elasticctl cases create --title T [--description D] [--tag T]... [--severity S]
                        [--assignee USER]...                               [guarded]
elasticctl cases close|open <case_id>...                                   [guarded]
elasticctl cases delete <case_id>...                                       [guarded]
elasticctl cases attach <case_id> --alert <alert_id>...                    [guarded]
elasticctl cases comment <case_id> --message TEXT                          [guarded]
```

`alerts list` filters compose into one boolean query over the measured
`kibana.alert.*` fields: `--status` → `kibana.alert.workflow_status`,
`--severity` → `kibana.alert.severity`, `--rule` → `kibana.alert.rule.rule_id`
after the standard name-or-id resolution, `--tag` →
`kibana.alert.workflow_tags`, `--assignee` →
`kibana.alert.workflow_assignee_ids` after username resolution (section 7),
`--since` → `@timestamp` range. `--search` matches the rule name and reason
text, consistent with the 0.3.1 `--search` semantics. Default sort is
`@timestamp` descending. A peek caps at `--limit` (default 100) and reports
when it truncates; `--out` pages with `sort` plus `search_after` through the
same route. `alerts get` is a `_id`-filtered search returning one document.

## 5. Mutation guard

Every mutation previews by default and applies with `--yes`, printing profile,
host, and space, per section 6.1 of the main spec. For an explicit id list the
preview resolves each `_id` first and shows what would change:

```
$ elasticctl alerts close 9f2a... 41c7...
[DRY RUN] Close 2 alerts (profile: dev @ <host>, space: default)
  9f2a...  Suspicious PowerShell   open -> closed
  41c7...  Rare DNS Tunnel         acknowledged -> closed
Pass --yes to apply.
```

An `_id` that resolves to nothing is reported before anything applies; the
command refuses to proceed on a partial resolution rather than closing the
subset (fail-closed, section 6.3). The status route is idempotent per the
update-by-query semantics: a no-op transition counts as processed, so previews
mark `already closed` rows and the apply still succeeds.

Case mutations carry the same guard. `cases delete` is the only destructive
verb in the area and its preview names each case title.

## 6. Query-scoped transitions

An implicit-set mutation must be as safe as an explicit-ids one. The design
makes the set visible before it is mutated and honest about the race window:

1. **Preview (default).** The client runs the operator's query through
   `signals/search` (`size` = sample size, `track_total_hits: true`) and
   prints the matched count plus a sample — `_id`, rule name, severity,
   `@timestamp` — capped at 10 rows:

   ```
   $ elasticctl alerts close --query '{"term":{"kibana.alert.rule.rule_id":"…"}}' --reason false_positive
   [DRY RUN] Close alerts matching query (profile: dev @ <host>, space: default)
     matched now: 1,214   showing 10 of 1,214
     9f2a…  Suspicious PowerShell  high    2026-08-30T21:14:02Z
     …
   The set is resolved again at apply time; this count is advisory.
   Pass --yes to apply.
   ```

2. **Apply (`--yes`).** The client POSTs `signals/status` with
   `{status, query, conflicts, reason?}`. The server resolves the set and
   mutates it in one update-by-query — no client-side id round-trip, so
   there is no window where the client acts on a stale id list.

3. **Report.** The response is a raw Elasticsearch update-by-query envelope
   (measured, section 10): `total`, `updated`, `version_conflicts`, `noops`,
   `failures`. The report renders these counts verbatim and exits non-zero if
   `failures` is non-empty or `version_conflicts > 0` under `--conflicts
   abort`.

`--conflicts` defaults to `abort`, the server default: a document whose
version moved between resolution and write stops the run rather than being
silently skipped. `--conflicts proceed` opts into best-effort, and the report
still prints the conflict count. `--query` takes inline JSON or `@file`, the
`search dsl` convention. `--query` and positional ids are mutually exclusive;
an empty query (`{}` or match-all) is rejected — a mass close of *everything*
must at least say what it matches, e.g. an explicit `match_all`. The preview
count and the apply count can legitimately differ; the report shows both so
the operator sees the drift.

## 7. Assignment and username resolution

The assignees routes take user profile uids, not usernames, and a uid only
exists after its user has *activated* a profile by logging into Kibana at
least once. Usernames are required on the CLI, so elasticctl resolves them.

Resolution is flavor-dependent (measured, section 10):

- **Hosted and self-managed** — the public Elasticsearch suggest API,
  `POST /_security/profile/_suggest` with `{name, size}`, GA since 8.2,
  requiring the `read_security` cluster privilege. Response:
  `{total, took, profiles: [{uid, user: {username, realm_name, roles, …}}]}`.
  Measured working on Hosted 9.5.1.
- **Serverless** — the public route answers 410 `api_not_available_exception`.
  The working path is the Security solution's own suggestion route,
  `GET /internal/detection_engine/users/_find?searchTerm=…`, which requires
  the `x-elastic-internal-origin: Kibana` header (400 "exists but is not
  available" without it) and returns `[{uid, user, data, enabled}]`. This is
  the route the Security UI itself uses for the assignee picker.

The capability probe already knows the flavor; `alerts assign` and `--assignee`
pick the route accordingly. The internal-route dependency is recorded in the
risks section of the spec: it is outside Elastic's compatibility contract, so
the conformance contract exercises it every release and a breakage downgrades
cleanly (below) rather than corrupting anything.

Client-side matching, mirroring rule-name resolution (section 4.1 of the main
spec): the suggestion list is matched **exactly** on `user.username`.

Failure modes, each a typed error:

- **No profile.** Username yields no exact match → `not_found`, with the
  remediation in the message: the user must have logged into Kibana at least
  once to activate a profile, and an API-key identity never has one.
- **Ambiguous.** Two or more profiles match exactly (multi-realm) →
  `conflict`, listing username and realm of each candidate, never picking one.
- **Suggest route unavailable.** 410/404/permission failure on the resolution
  route → `unsupported`, naming the flavor and the remedy: pass
  `uid:<profile_uid>` to bypass resolution. The `uid:` prefix always works and
  is the escape hatch, not the primary interface.

Case assignees (0.4.1) take the same uids in `assignees: [{uid}]` and reuse
the same resolver.

## 8. Architecture placement

Per the standing rule, orchestration returns typed values from `-api` and the
CLI adapter guards and renders:

- `elasticctl-api::alerts` — typed wrappers over `signals/search`,
  `signals/status`, `signals/tags`, `signals/assignees`; sibling of `rules`.
- `elasticctl-api::alerts_ops` — filter construction, id resolution, preview
  plan and outcome types, the query-scoped preview/apply pair.
- `elasticctl-api::profiles` — username-to-uid resolution behind one function;
  owns the flavor switch between the public and internal suggest routes.
- `elasticctl-api::cases` / `cases_ops` — same split for the cases routes.
- `elasticctl-cli::cmd::alerts` / `cmd::cases` — clap parsing, guard, render.
- `elasticctl-core` — untouched except capability floors; `kbn-xsrf`,
  `elastic-api-version`, and (new) per-request extra headers for the
  internal-origin case.

No new crate. The MCP-readiness rule holds: every command returns a struct.

## 9. Fixtures and conformance

Fixtures are recorded live via `cargo xtask record`, marker-scoped as always.
The recorder creates a marker rule over a marker index seeded with matching
events (the sample-data scripts already produce these), waits for the rule to
generate alerts, records the triage exchanges, then closes and cleans up.

Scrubbing gains a new class: profile and cases payloads embed user identity
(`username`, `full_name`, `email`, profile `uid`s, realm names, `created_by`,
`updated_by`). All are scrubbed like the existing identity fields. Alert ids
and profile uids are rewritten wherever they appear **inside** a string
value, not only where the whole value equals one: Kibana embeds the real
alert uuid inside `kibana.alert.url` (`.../redirect/<uuid>?index=…&
timestamp=…`), which a whole-string match misses. `kibana.alert.url` is
additionally replaced outright with a fixed placeholder, since its
`timestamp=` query parameter is a live value nothing decodes.

Volatile fields to normalize: alert `_id`s, `@timestamp`,
`kibana.alert.uuid`, `kibana.alert.url` (replaced outright, see above),
`workflow_status_updated_at`, `kibana.alert.last_detected`,
`kibana.alert.original_time`, `kibana.alert.intended_timestamp`,
`kibana.alert.rule.execution.timestamp`, `kibana.alert.rule.execution.uuid`,
`_score`, `max_score`, `took`, `timed_out`, `_shards` (present on every
triage mutation response, not only `signals/search`), case `id`, `version`,
`created_at`, `updated_at`, comment ids.

The conformance contract (eighth in the matrix) would: seed marker events,
enable the marker rule, wait for an alert, transition it
open → acknowledged → closed by id, re-open and close it by marker-scoped
query, tag and untag it, resolve the operator's own username, create a case,
attach the alert, close and delete the case, then verify baseline.

**Accepted deviation — alert residue (decided).** Generated alerts live in
the shared `.alerts-security.alerts-default` index, the public API has no
alert delete, and none will be built. The conformance contract therefore
closes its marker alerts as its final triage step, and baseline verification
tolerates residual *closed* `elasticctl-sample` alerts instead of proving
absence. This is a deliberate deviation from the strict back-to-baseline rule
the other contracts follow: a closed, marker-tagged alert is inert — it
matches no open-alert workflow, belongs to a deleted marker rule, and is
scoped out of every baseline count — whereas deleting documents from a
dot-prefixed system index would depend on privileges the flavors do not
uniformly grant and on behavior Elastic does not contract.

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

| Fact | Detail |
|---|---|
| Alert search route | `POST /api/detection_engine/signals/search` returns the raw ES envelope `{took, timed_out, _shards, hits}` — 200 with and without `elastic-api-version`, and 200 even without `kbn-xsrf` on Serverless (the transport still always sends it). Measured 2026-09-01 with populated hits from a live marker rule on all three flavors: `hits.hits[]._source` carries 50+ `kibana.alert.*` field groups plus the original event fields, and `_id`/`kibana.alert.uuid` uniquely identify each alert instance |
| Search body acceptance | `sort`, `search_after`, `_source`, `track_total_hits`, `size`, `aggs`, and `runtime_mappings` all accepted (200) |
| Triage fields | The alerts index mapping carries `kibana.alert.workflow_status`, `workflow_tags`, `workflow_assignee_ids`, `workflow_status_updated_at`, `workflow_user`, `workflow_reason`, and `kibana.alert.case_ids`; 50 `kibana.alert.*` field groups total |
| Query-scoped status | `POST /api/detection_engine/signals/status` with `{status, query, conflicts}` → 200 with a raw update-by-query envelope: `{took, timed_out, total, updated, deleted, batches, version_conflicts, noops, retries, throttled_millis, requests_per_second, throttled_until_millis, failures}`. Zero-match returns all-zero counts. Identical shape on Serverless 9.6.0 and Hosted 9.5.2 |
| Status body (docs) | `signal_ids` and `query` are one-of; `conflicts` is `abort` (default) or `proceed`; `status` allows `open`, `acknowledged`, `in-progress`, `closed`; `reason` is a documented enum (`false_positive`, `duplicate`, `true_positive`, `benign_positive`, `automated_closure`, `other`) plus free text 1–1024 chars |
| Status body, `signal_ids` form (measured) | `reason` is accepted alongside `signal_ids`, not just `query` — measured 2026-09-01 on Serverless 9.6.0, Hosted 9.5.2, and the traditional lab 9.5.1: `POST signals/status` with `{signal_ids, status, reason}` returns 200, never a 400. `alerts::status_by_ids` already sends `reason` unconditionally; no code change needed |
| Profile suggest, public | `POST /_security/profile/_suggest` → 200 `{total, took, profiles: [{uid, user: {username, realm_name, roles, …}, data, labels, enabled}]}` on Hosted (9.5.1, then 9.5.2) and the traditional lab (9.5.1, measured 2026-09-01). On Serverless → **410** `api_not_available_exception` "not available when running in serverless mode" |
| Profile suggest, internal | `GET /internal/detection_engine/users/_find?searchTerm=` → 200 `[{data, enabled, uid, user}]` on all three flavors; **without** `x-elastic-internal-origin` the internal route family answers 400 "exists but is not available". `POST /internal/cases/_suggest_user_profiles` (with `{name, size, owners}`) behaves the same |
| Profile activation | Each cloud stack shows exactly one activated profile (the SSO login); the API-key identities used by elasticctl have none. Empty `searchTerm` returns all activated profiles. Measured 2026-09-01 on the traditional lab: a fresh stack activates none — a raw Elasticsearch API key or an HTTP Basic call to a Kibana route does **not** trigger activation; only `POST /internal/security/login` (with `x-elastic-internal-origin: Kibana`, since it is itself a restricted internal route) does |
| Profile by uid | `GET /_security/profile/<uid>` on Hosted → 200 `{profiles: [...]}` |
| Cases find | `GET /api/cases/_find` → `{cases, page, per_page, total, count_open_cases, count_in_progress_cases, count_closed_cases}`; accepts `perPage`, `page`, `sortField`, `sortOrder`, `status` |
| Cases reads | `GET /api/cases/tags` and `/api/cases/reporters` → arrays; `GET /api/cases/configure` → array; `GET /api/cases/alerts/<absent id>` → 200 `[]`, not 404 |
| Alerts index | `GET /api/detection_engine/index` → `{name: ".alerts-security.alerts-default", index_mapping_outdated: false}` |
| Tags mutation | `POST /api/detection_engine/signals/tags` with `{ids, tags: {tags_to_add, tags_to_remove}}` → 200 with the same raw update-by-query envelope as `signals/status`. Measured 2026-09-01: added `triage-check` to a real marker alert by `_id` on Serverless 9.6.0, Hosted 9.5.2, and the traditional lab 9.5.1 |
| Assignee mutation | `POST /api/detection_engine/signals/assignees` with `{assignees: {add, remove}, ids}` — uids only, same envelope shape. Measured 2026-09-01: assigned then unassigned a real activated profile uid (from `users/_find`) to a marker alert by `_id` on all three flavors. Add and remove of the same uid in one request was not exercised live; still documented as rejected per the API reference (section 13) |
| Case mutations (unverified) | `POST /api/cases` (create), `PATCH /api/cases` (bulk update, `version` required), `DELETE /api/cases?ids=...`, `POST /api/cases/<id>/comments` with `{type: "alert", alertId, index, rule, owner}` |

Remaining live verification: 0.4.0's own routes (`signals/search`, the
`signals/status` id and query forms, `signals/tags`, `signals/assignees`, and
both profile-resolution routes) are now fully measured across all three
flavors (Task 8). What is left is out of scope for this release but should
still land **before 2026-09-08 08:56 UTC** (after that, only a lab session
remains and Serverless evidence is lost), since measured facts outlive the
trial:

- **Ships in 0.4.1 but measured now** — the case mutation family: create,
  attach, comment, status change, delete, and the version/409 conflict
  behavior.

## 11. Version placement

| Version | Content |
|---|---|
| 0.4.0 | The complete alerts vertical: `alerts list|get|ack|open|close|tag|assign` including `--query` transitions and username resolution; capability floors; fixtures for all of it |
| 0.4.1 | The complete cases surface: `cases list|get|create|close|open|delete|attach|comment`, case assignees |
| 0.4.2 | Triage conformance contract, cross-flavor matrix run, bounded review patch |

Each version is one meaningful story — alerts, then cases, then proven.
0.4.0 is the first independently usable release; a cases read stub beside a
complete alerts vertical would dilute both. Query-scoped transitions sit in
0.4.0 (rev 1 had them in 0.4.2) because the endpoint shape is measured on
both cloud flavors and the guard design in section 6 is the same preview
machinery the id form needs anyway.

## 12. Decisions log

All four design questions are resolved:

1. **Cut line** — 0.4.0 alerts only, 0.4.1 the complete cases surface,
   0.4.2 conformance and review. Section 11.
2. **Username assignment** — required; resolved per flavor with a `uid:`
   bypass. Section 7.
3. **Alert residue** — residual closed marker alerts are accepted; no
   deletion API exists and none will be built. Section 9.
4. **Query-scoped transitions** — allowed and shipped in 0.4.0 with the
   count-and-sample dry-run guard. Section 6.

## 13. References

Consulted 2026-09-01:

- Set detection alert status — request one-of (`signal_ids` | `query`),
  `conflicts`, `reason` enum:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertsstatus
- Assign/unassign detection alerts — uids, activation requirement,
  update-by-query response:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertassignees
- Suggest user profiles — paths, schema, `read_security` privilege, GA 8.2,
  "designed only for use by Kibana and Elastic solutions" caveat:
  https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-suggest-user-profiles
- User profiles concept and activation:
  https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/user-profiles
