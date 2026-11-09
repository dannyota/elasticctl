[Back to elasticctl-content-design](../elasticctl-content-design.md)

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

