[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 11. Measured behavior

Read-only probes ran on 2026-11-10 against the trial Serverless project
(Kibana 9.7.0) and the trial Hosted deployment (9.5.6). The local lab (9.5.1)
was not started. No object was created or changed. Rows marked unmeasured
are open; a design claim that rests on one is listed in section 11.1 with the
version it blocks.

| Fact | Serverless 9.7.0 | Hosted 9.5.6 | Self-managed 9.5.1 |
| --- | --- | --- | --- |
| Rules in the space | 2,263 | 2,263 | unmeasured |
| `_find?per_page=10000` body | 19,324,131 bytes, 1.8 s | 19,315,015 bytes, 3.4 s | unmeasured |
| `rules_list` default call through the 0.7.4 server | `elastic_unsupported` | not run; same body size | unmeasured |
| `_find` `fields` parameter | `fields=name` is a 500; `fields[]=` is accepted and ignored | same | unmeasured |
| `_find` with `sort_field` `name` or `created_at` | 200 | 200 | unmeasured |
| 500-rule page, largest body | 4,458,395 bytes | 4,435,718 bytes | unmeasured |
| Five 500-rule pages, one connection | 4.1 s | 2.9 s | unmeasured |
| Largest single rule | 60,472 bytes | 60,468 bytes | unmeasured |
| Paging with an explicit sort, distinct `rule_id` equals rows | 10 of 10 runs | 10 of 10 runs | unmeasured |
| Paging with the default order | 7 of 7 runs distinct | 4 of 7 runs distinct, with a concurrent writer | unmeasured |
| KQL on `threat.technique.id`, `threat.technique.subtechnique.id`, `threat.tactic.id` | totals 339, 119, 558 | same totals | unmeasured |
| Rules with `threat`; distinct techniques; tactics | 2,189; 170; 15 | same | unmeasured |
| Most index patterns and related integrations on one rule | 11 and 7 | same | unmeasured |
| Rules with neither `index` nor `data_view_id` | 426: 320 `esql`, 106 `machine_learning` | same | unmeasured |
| `execution_summary.last_execution` keys | `date`, `status`, `status_order`, `message`, `metrics` | same | unmeasured |
| Execution status seen | `partial failure`; message 185 to 190 bytes; `metrics` empty | same | unmeasured |
| Disabled rule that never ran | no `execution_summary` key | same | unmeasured |
| `related_integrations[]` keys | `package`, `version` | same | unmeasured |
| Signals search with `size: 0` and a terms aggregation | 200; `aggregations.status.buckets` present, empty | same | unmeasured |
| `GET /api/cases/alerts/<absent id>` | 200 `[]` | 200 `[]` | 200 `[]` on 9.5.1, triage spec section 10 |
| `GET /api/cases/alerts/<id>` for an alert in a case | unmeasured | unmeasured | unmeasured |
| `kibana.alert.case_ids` on an alert in a case | unmeasured; no alert exists | unmeasured; no alert exists | unmeasured |
| `_resolve/index/<wildcard with no match>` | 200, three empty arrays | 200, three empty arrays | unmeasured |
| `_resolve/index/<missing concrete name>` | 404 `index_not_found_exception` | 404 `index_not_found_exception` | unmeasured |
| `_resolve/index/<remote>:<pattern>` | 404 `no_matching_project_exception` | 404 `no_such_remote_cluster_exception` | unmeasured |
| `_resolve/index/.alerts-security.alerts-default` | 200, one data stream | 200, one alias | unmeasured |
| `GET /api/fleet/epm/packages/endpoint` | 200, `installed` | 200, `not_installed` | unmeasured |
| `GET /api/fleet/epm/packages/<unknown>` | 404 | 404 | unmeasured |
| Exception item `_find` with `per_page=1` | 200 with `total` (zero items) | same | unmeasured |
| Data view list row keys | `id`, `title`, `name`, `timeFieldName`, `namespaces`, `managed` | same | unmeasured |
| Small Kibana GET, one connection per request | 0.17 to 0.25 s | 0.25 to 0.33 s | unmeasured |
| 0.7.4 `tools/list` frame, offline | 58,671 bytes; 64,778 with query tools | n/a | n/a |

The rule total moved from 2,263 to 2,264 on both stacks during the probes.
Another session was writing rules. Default-order paging returned duplicates
only on Hosted and only in that period. The probes do not show whether the
write or the default order caused them. The design relies on neither: it
sorts explicitly and verifies.

### 11.2 Recorded measurements M1 to M8

`cargo xtask record-compose` measured these on 2026-11-10 with marker
objects on the trial Serverless project (9.7.0) and the trial Hosted
deployment (9.5.6). Both answered alike unless a cell says otherwise. The
fixtures are in `tests/fixtures/serverless-9.7.0/` and
`tests/fixtures/ech-9.5.6/`. The lab (9.5.1) column is open.

| ID | Result on Serverless 9.7.0 and Hosted 9.5.6 |
| --- | --- |
| M1 | `GET /api/cases/alerts/{id}` answers 200 with an array of cases. Each element has `id`, `title`, `description`, `status`, `createdAt`, and `totals`; `id` and `title` are strings. An absent id answers `[]`. |
| M2 | The alert's source holds `kibana.alert.case_ids` once the alert is attached. |
| M3 | The section 4.2 body answers `hits.total.relation: "eq"`, terms buckets keyed by workflow status (`open`, `closed`), `sum_other_doc_count: 0`, and the five newest hits. |
| M4 | A successful run reports `status: "succeeded"`, `status_order: 0`, and integer metrics `total_search_duration_ms` and `total_indexing_duration_ms`. A run over a missing index reports `status: "partial failure"`, `status_order: 20`, a message of about 195 bytes, and empty `metrics`; it is not `failed`. |
| M5 | `_resolve/index` answers 200 with one index for the marker index, 200 with three empty arrays for a no-match wildcard and for a lone exclusion pattern, and 404 `not_found` for a missing concrete name. |
| M6 | `_find` sorted by `created_at` ascending returns the marker rules in creation order. The technique, subtechnique, and tactic clauses each select the one marker rule that carries them. The 500-rule page sizes are in the table above. |
| M7 | Exception item `_find` with `per_page=1` on a two-item list answers `total: 2` and one row. |
| M8 | A custom rule keeps `related_integrations` (`package`, `version`) and `threat` (tactic, technique, subtechnique) as created. Package status reads `installed` for `system` and `not_installed` for `apache`. |

### 11.1 Required measurements

Each row must be measured on all three flavors and recorded in the named
findings file before the version ships. M1 to M9 run first in 0.8.0, through
the fixture recorder and the live contract, because every decoder depends on
them. Marker-owned objects are prepared by the test harness, never through
MCP.

| ID | Measurement | Needed for | Blocks |
| --- | --- | --- | --- |
| M1 | `GET /api/cases/alerts/{id}` for a marker alert attached to a marker case: status, element keys, `id` and `title` types | `alert_context.cases` decoder | 0.8.0 |
| M2 | Whether that alert's source holds `kibana.alert.case_ids` | Decision D12 follow-up only | nothing; record the answer |
| M3 | Signals search with the section 4.2 body for a marker rule with alerts: `hits.total` relation, bucket keys and counts, five newest hits | Alert activity decoder | 0.8.0 |
| M4 | `execution_summary.last_execution` for a marker rule after a successful run and after a run over a missing index: status strings, metric keys and types | Execution projection and findings | 0.8.0 |
| M5 | `_resolve/index` for a marker index, a no-match wildcard, a missing concrete name, and an exclusion pattern, on the lab as well | `rule_readiness.patterns` | 0.8.0 |
| M6 | Sorted `_find` pages and the three threat KQL filters on the lab; a 500-rule page body size on each flavor | `find_window`, `rules_list` filters | 0.8.0 |
| M7 | Exception item `_find` with `per_page=1` on a marker list with two items: `total` is 2 | Exception coverage count | 0.8.0 |
| M8 | Custom rule created with `related_integrations` and `threat`: both fields round-trip; package status for an installed and a not-installed package | Coverage grouping, `rule_readiness.integrations` | 0.8.0 |
| M9 | Wall time of each task tool on the maximum-work objects of section 12.3; two consecutive eight-page `detection_coverage` reads of a 4,000-rule corpus on the lab; two consecutive full-corpus reads on Serverless and Hosted | Decisions D6 and D25 | 0.8.0 |
| M10 | `resources/read` text equals the matching tool text for all nine resource shapes; error codes on both protocol paths | Section 8 | 0.8.1 |
| M11 | Negotiated protocol, and whether each client sends `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, `prompts/get`, and `completion/complete` | Research evidence gaps | 0.8.2 |
| M12 | Whether each client defers the 24 tool definitions and loads the instructions | Decision D20 | 0.8.2 |

**Latency gate (M9).** The gate is 15 seconds, half the default deadline,
on every flavor.

- `alert_context`, `rule_health`, and `rule_readiness` are called on the
  maximum-work objects, whose shape makes the plan send its maximum of 19,
  14, and 29 requests. The slowest call of each must finish within the gate.
  The offline request-count proofs use the same shapes, so the live time
  belongs to the maximum plan and not to a degraded one.
- `detection_coverage` is measured at its maximum on the lab, which is
  disposable. The harness creates disabled `elasticctl-sample` marker rules
  until the lab corpus holds exactly 4,000 rules, calls `detection_coverage`
  with default arguments twice in a row, and deletes the sample rules. Each
  call reads eight pages. The two calls together stand for the two passes
  of a verification retry, which a live stack cannot be made to trigger.
- On Serverless and Hosted the corpus is not grown. The full-corpus read,
  five pages today, is timed twice in a row.
- `detection_coverage` is held to the 30-second default deadline instead of
  the 15-second gate. Take the highest per-page time among all six timed
  reads, a call's wall time divided by the pages it read. That time, times 8
  pages, one pass over the largest corpus, must fit the deadline. A second
  pass runs only when the corpus changed during the first; near the
  4,000-rule limit it can need a longer `--timeout`, up to 120 seconds, and
  the tool description says so. The owner set this rule on 2026-11-10: page
  time from the development host to the trial stacks ranged from 1.2 to 3.0
  seconds, driven by network transfer of about 4.4 MB a page, while the
  local lab read a page in 0.38 seconds.
- The retry path itself is proven offline: a recording mock makes the first
  pass fail verification and asserts 16 requests at the cap.

The findings list every timed read with its flavor, page count, and
seconds, the worst per-page time, and its products with 8 and with 16.

If a tool misses the gate, lower the cap that drives it, update section
10.1, and measure again before release. The gate is on wall time from the
test host; it is not a service-level claim.

M11 and M12 use only the local lab. A model-driven client sends tool results,
which carry `target.host`, to its model provider, so such a client never
points at a trial deployment. The 0.8.2 conformance matrix is separate from
the client runs and still covers all three flavors.
