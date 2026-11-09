[Back to elasticctl-content-design](../elasticctl-content-design.md)

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

