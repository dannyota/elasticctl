[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 14. Measured behavior

The Task 6 read and marker-scoped mutation probe ran on 2026-09-02 against
Serverless 9.6.0, Elastic Cloud Hosted 9.5.2, and self-managed 9.5.1. Every
leg restored its default and removed all marker data views and indices. The
Serverless prebuilt baseline was unchanged; the lab teardown left zero services
and volumes.

| Fact | Measured result |
|---|---|
| Data-view lifecycle | All three flavors create with an explicit id, list, get, update, and delete the marker view. |
| Legacy scripted fields | Serverless 9.6.0 drops the marker scripted entry from raw create and immediate GET. Hosted 9.5.2 and traditional 9.5.1 retain it in both. Portable legacy scripted fields remain globally unsupported. |
| Direct delete body | All three flavors succeed with a 200 empty body. elasticctl accepts only an empty body or exact `{ "acknowledged": true }`. |
| Data-view response | Carries `id`, `title`, the configured optional values, formats, runtime fields, field attributes, generated `fields`, `namespaces`, and `version`; absent and false `allowHidden` normalize to false |
| Hidden-index create | `allowHidden: true` is accepted and survives GET on all three flavors. |
| Hidden-index update | Sending `allowHidden: false` to the partial update route answers 400 and leaves the stored true value unchanged on all three flavors. |
| Field metadata | `/fields` returns a one-key full data-view envelope on all three flavors. It preserves `count` and `customDescription` and omits a `customLabel` sent as `null`. |
| Reference preview | A fresh self-swap (`fromId == toId`) decodes to an empty result on all three flavors before replacement creation. |
| Unsafe direct delete | Direct DELETE of a referenced marker data view answers 200; the dependent dashboard remains readable and broken |
| Swap default | All three flavors retain the deleted source id as the current default after successful marker swap/delete, with zero references. |
| Default restoration | Serverless and Hosted preserve and restore a preexisting nonmarker default, scrubbed to the public placeholder. Fresh traditional 9.5.1 claims raw `""`, first create implicitly makes source default, restores with a null POST, and returns exact raw `""`. |
| Dashboard create/update | `PUT /api/dashboards/{id}` answers 201 on create and 200 on replacement; replacement is full, not patch semantics |
| Dashboard response | Top level is `{id, data, meta}` for the measured supported dashboard |
| Dashboard search | All three scoped marker responses use paginated `{data, meta}`, with each row shaped as `{id, data: {title, description?, tags?, ...}, meta: {...}}`. elasticctl derives its flat `DashboardSummary` only for rendering. |
| Dashboard delete | Answers 204 with an empty body on all three flavors, despite documentation that still lists 200 |
| Deep export | Marker dashboard export with `includeReferencesDeep` contains one `dashboard`, one `index-pattern`, and one export-details trailer |
| Accepted loss | All three flavors accept the marker loss copy but omit root `time_range.mode`; the recorder reports exactly `$.time_range.mode` and deletes that copy immediately. |
| Saved Objects import | All three flavors return the strict success envelope for overwrite import and the strict conflict envelope without overwrite. |
| Transport empty body | Existing response handling maps a successful empty body to `Value::Null`; no dashboard-specific 204 exception is needed |
| Preview-hit fixtures | The production preview query decodes after response-only timing, shard metadata, hit `_index`, score, and response sort values are removed. |
| Close-by-query fixture | Marker cleanup requires a conflict-free, non-noop successful outcome, persists canonical typed counters, and removes untyped runtime envelope fields. |

The 0.5.2 conformance matrix ran on 2026-09-03. All nine contracts passed on
each measured flavor:

| Flavor | Version | Result | Report |
|---|---|---|---|
| Serverless | 9.6.0 | 9 pass | [report](../../conformance/v0.5.2/serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 9 pass | [report](../../conformance/v0.5.2/ech-9.5.2.json) |
| Self-managed | 9.5.1 | 9 pass | [report](../../conformance/v0.5.2/traditional-9.5.1.json) |

Every leg finished with zero marker dashboards, data views, and indices. The
persistent cloud targets restored their exact captured defaults, every
prebuilt-rule count matched its captured baseline, and the self-managed lab
removed its containers and volumes. The public
[findings](../../conformance/v0.5.2/findings.md) record no new cross-flavor
deviation.

The 0.5 content evidence is complete:

- 0.5.1: the accepted-but-lossy root `time_range.mode` payload and Saved
  Objects import success/conflict are recorded and production-decoded on
  Serverless 9.6.0, Hosted 9.5.2, and traditional 9.5.1.
- 0.5.2: the ninth contract and three-flavor matrix prove transfer, exact
  default restoration, unchanged prebuilt counts, and zero content residue.

