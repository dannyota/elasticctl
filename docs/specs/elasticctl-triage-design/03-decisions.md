[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

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

