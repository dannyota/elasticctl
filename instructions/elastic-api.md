# Elastic API gotchas

Read this before changing transport, an API call, or the response model. Each item is measured
against a live stack; spec section 7 holds the evidence. Record a newly verified quirk there and,
if it is easy to get wrong, here.

- `kbn-xsrf: true` is required on every non-GET Kibana request or it is rejected.
- `elastic-api-version: 2023-10-31` is required on versioned public APIs.
- **Two error envelope shapes exist.** The Cloud edge proxy returns
  `{"ok":false,"message":"Unknown resource."}`; Kibana returns
  `{"statusCode":...,"error":...,"message":...}`. The classifier must handle both. The edge
  shape also appears for a hostname that no longer resolves after a project rename.
- `rules/_export` ends with a `{"exported_count":N,...}` summary object. It is a trailer, not a
  rule. With zero rules it is the entire body.
- `_bulk_action` targets rules by stable `rule_id` through
  `alert.attributes.params.ruleId: "<rule_id>"`, so no server-id lookup is needed. It also accepts
  `?dry_run=true` for a server-computed preview. Enable, disable, and delete are idempotent: acting
  on a rule already in the target state reports `succeeded`, and a missing rule is just absent
  from `total`. So `skipped` stays `0` for every action elasticctl sends, and the
  `total == succeeded + failed + skipped` invariant's `skipped > 0` branch is defensive only.
- Rule export includes volatile `id`, `created_at`, `created_by`, `updated_at`, `updated_by`,
  `version`, `revision`, and `execution_summary`. Normalize them away on `pull` or every diff is
  false drift.
- A real self-managed stack reports `version.build_flavor: "traditional"`, not `"default"`. Only
  `"serverless"` is matched exactly; everything else falls through to hostname detection.
- `rules/preview` returns `{preview_id, invocations, errors, warnings}` and **no hit count**.
  Four hits and zero hits are byte-identical responses. Query the preview alerts index separately
  with `preview_id`. The only in-band hit signal is the `max_signals` warning at 100+.
- Re-importing existing rules without overwrite is a per-rule 409 storm, not a skip: N "already
  exists" errors and exit 1.
- ES|QL `POST /_query/async` rejects `format`: a `format: csv` body is a 400 "unknown field".
  `columnar: true` is accepted, so CSV export transposes the columnar response client-side.
