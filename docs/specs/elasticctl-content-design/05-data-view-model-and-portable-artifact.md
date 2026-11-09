[Back to elasticctl-content-design](../elasticctl-content-design.md)

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
objects. Every submitted `fields` entry must contain `scripted: true`; a false
or malformed entry is local `error`, not a generated mapped-field cache.

Normalization removes:

- `version`, because it is a saved-object concurrency token;
- `namespaces`, because the active profile and URL choose the target space;
- generated mapped entries from `fields`, because they are a cache of the
  source stack's mapping and permissions.

Legacy scripted fields are globally unsupported in portable 0.5.0 artifacts.
Serverless 9.6.0 drops the marker entry from both create and immediate GET.
A valid non-empty `fields` map therefore fails `unsupported` before planning,
transport, or a write. `normalize` scans raw live fields before dropping the
generated cache and also fails `unsupported` when it finds a legacy scripted
entry. The raw scripted create request is recorder evidence only; it is never
a portable spec. Hosted 9.5.2 and self-managed 9.5.1 retain the entry in both
the create response and immediate GET, but that difference cannot relax this
global refusal.
Unsupported field names are sorted for deterministic diagnostics. Direct
partial-update input first rejects malformed entries as local `error`, then
classifies a structurally valid non-empty scripted map as `unsupported`.

Import sends explicit ids, so dashboards can keep the same reference across
environments. Create uses `POST /api/data_views/data_view` with the canonical
file spec under `data_view`. Marker probes prove that create preserves
`allowHidden: true` on Serverless 9.6.0, Hosted 9.5.2, and self-managed 9.5.1,
even though the published create schema omits that property.

Update is not full replacement. `POST /api/data_views/data_view/{id}` is a
partial route that accepts `allowNoIndex`, `fieldFormats`, `fields`, `name`,
`runtimeFieldMap`, `sourceFilters`, `timeFieldName`, `title`, `type`, and
`typeMeta`. elasticctl sends only changed properties from that set with
`refresh_fields: true`. It never sends `id`, `allowHidden`, or `fieldAttrs` to
that route.

Field attributes use a second request:
`POST /api/data_views/data_view/{id}/fields`. elasticctl builds a metadata
delta over the union of the current and desired field names and metadata
keys. The documented metadata properties include `count`, `customLabel`,
`customDescription`, and formatter data. Desired values are sent as-is. A
current key missing from the desired spec is sent as `null`, which removes it.
An empty delta causes no request. The current public operation documents an
exact `{ "acknowledged": true }` success body. All three measured flavors
instead return a full `{ "data_view": { ... } }` envelope. The client accepts only
that exact acknowledgement object or an exact top-level data-view envelope
whose open inner map has a non-empty string `id` equal to the request id.
Every other 2xx body is `http`. All three measured flavors return the full
data-view envelope.

The public update API has no documented way to clear `name`, `timeFieldName`,
`type`, or a non-empty `typeMeta`. It also has no way to change
`allowHidden`; marker requests with that property answer 400 on Serverless
9.6.0, Hosted 9.5.2, and self-managed 9.5.1. Missing and `false`
`allowHidden` values are equivalent. Any other overwrite that changes
`allowHidden`, or removes one of the optional properties without a documented
clearing value, fails as `unsupported` during planning. Import never deletes
and recreates a data view to evade that limit.

After create, or after all required update requests, import GETs and
normalizes the stored data view. It requires exact equality with the desired
canonical spec. Once a mutation route has returned a decoded success, a later
metadata failure or comparison mismatch is a failed row with `applied: true`;
elasticctl does not roll back an earlier write.

