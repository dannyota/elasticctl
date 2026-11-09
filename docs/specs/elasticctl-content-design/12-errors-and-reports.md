[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 12. Errors and reports

Existing error kinds apply:

- `not_found`: selector or referenced data-view id missing;
- `conflict`: ambiguous selector, existing import id, changed preflight
  snapshot, or unsafe referenced deletion;
- `unsupported`: Dashboards API below 9.5.1, any valid portable or live
  legacy scripted field, warning-bearing typed export, or a data-view
  overwrite the public update routes cannot express;
- `http`: malformed success response, an unexpected data-view DELETE success
  body, failed loss invariant, or transport response outside the documented
  shapes;
- `error`: malformed local artifact or invalid command combination.

List and get return ordinary typed values through `render`. Validate returns
`{valid, total}` plus per-kind bundle counts. Export with `--out` returns
`{exported, path, failed}`; without it, stdout is the artifact. Import reports
`{applied, succeeded, skipped, failed, lossy, total}`. Delete reports
`{applied, deleted, failed, total}`. A non-empty `failed` or `lossy` collection
sets exit 1 through the existing main-result policy.

No report contains saved-object attributes from an opaque bundle. Its preview
and result may name only `type`, `id`, counts, and server error text.

