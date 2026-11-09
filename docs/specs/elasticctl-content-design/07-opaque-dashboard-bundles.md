[Back to elasticctl-content-design](../elasticctl-content-design.md)

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

