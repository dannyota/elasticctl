[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 13. Fixtures and conformance

Fixtures are recorded from real traffic for Serverless, Hosted, and
self-managed deployments. The recorder creates only unique
`elasticctl-sample-*` data-view and dashboard ids and an
`*elasticctl-sample*` index. Marker mutations, gets, and exports use their
fixed ids. Dashboard list recording uses the exact marker title as its query,
then requires one nested row with the fixed marker id and title before it can
enter a public fixture. An unscoped dashboard list or Saved Objects export
must never enter public fixtures.

When `ELASTICCTL_FIXTURE_FLAVOR=traditional` exactly, `cargo xtask record`
activates the headless lab's profile through the existing login-and-verify
helper before it builds its recording session. The command requires generic
`ELASTICCTL_USERNAME` and `ELASTICCTL_PASSWORD` for this one flavor; either
missing input fails by its variable name before a marker mutation. Serverless
and Hosted recording do not activate a profile. The helper discovers the
deployment's Basic provider, logs in, and verifies a nonempty activated-profile
response without exposing its contents.

The 0.5.0 fixture set covers:

- data-view list, raw scripted create/get evidence with explicit id and
  `allowHidden: true`, partial update, field-metadata merge and null deletion,
  its closed acknowledgement-or-data-view response union, and a post-metadata
  GET that proves persisted `count`, `customDescription`, and label removal,
  default get/set/unset, self-swap preview, replacement swap, direct delete,
  post-restore default GET, and post-delete 404;
- generated-field normalization, the scripted-field refusal in section 5, and
  the closed direct-delete union of an empty body or exact
  `{ "acknowledged": true }`;
- default restoration and zero marker residue.

The recorder proves marker-index absence and deletion with the root index
route, not just a marker document. After the marker source direct-404 and
backing-index proof, it reads, strictly decodes, rejects marker or
whitespace-only defaults, and resolves any nonmarker default read-only. It
rereads the exact raw envelope immediately before source create. That second
response is the `data_view_default_get` fixture and becomes one pending restore
lease before the source-create POST, with no intervening remote I/O. The lease
holds the raw envelope, its canonical id or no-default state, and a
`CreateMayImplicitlySetSource` or `ExplicitDefaultMutationMayHaveChanged`
phase. It clears only after an exact restore acknowledgement and raw GET
equality.

The unrecorded GET immediately after source create accepts only the exact
original raw envelope, or, when the original default was absent, the marker
source id. Before the first explicit default POST it repeats that same audit,
then moves the lease to the explicit-mutation phase immediately before the
POST. A preexisting default displaced by source create fails the main flow but
remains recoverable by cleanup because the source is owned. While the lease is
pending, cleanup and normal success accept only the original raw envelope,
the source id, and, in the explicit phase, canonical no-default (`null` or
empty string); replacement or arbitrary nonmarker defaults are unsafe. They
restore before every marker delete. Restore failure, timeout, raw mismatch, or
an unexpected current default retains the lease and all data-view/index
ownership and skips those deletes. Fixtures replace any real original default
id with a fixed placeholder. Self-preview and swap responses must be empty;
source and replacement ownership clear only after their respective
marker-scoped GET-404 exchanges.

The fresh traditional 9.5.1 lab returns `{ "data_view_id": "" }` before any
data view is created. The recorder canonicalizes that raw state to no default,
does not resolve an empty id, claims that exact empty envelope before source
create, restores with `null`, and requires the post-restore GET to be the same
empty envelope. Every flavor requires exact raw initial and restored envelope
equality before clearing the pending lease. A cloud recording keeps a non-empty
original id redacted to the fixed placeholder.

The 0.5.1 fixture set covers:

- dashboard search, PUT create (201), GET, PUT update (200), DELETE (204), and
  404;
- a typed metric panel using
  `{type: "data_view_reference", ref_id: "elasticctl-sample-data-view"}`;
- strict typed round trip and one measured accepted-but-lossy payload;
- Saved Objects deep export containing exactly the marker dashboard, its
  marker data view, and the export-details trailer;
- Saved Objects import success and conflict response shapes;
- zero dashboard and data-view marker residue.

Dashboard fixture scrubbing preserves the caller-selected root dashboard and
data-view ids. It deterministically normalizes generated panel tokens in
direct panels and Saved Objects `panelsJSON` (`panelIndex` and `gridData.i`),
including reference names, to `elasticctl-fixture-dashboard-panel-N`.

Preview-hit fixtures retain the production query and decoder-required search
shape, but remove response-only runtime fields: `took`, `timed_out`, shard
metadata, and each hit's concrete `_index`, score, and response sort values.
The recorder decodes a close-by-query outcome before persistence, requires `updated > 0` and
zero `version_conflicts`, `noops`, and failures, then persists the typed
successful outcome as `total: 1`, `updated: 1`, `version_conflicts: 0`, and
`noops: 0`. It removes the untyped update-by-query runtime envelope
(`took`, shard metadata, batches, retries, throttling, request rate, and
deleted counter). This keeps the response production-decodable without making
a repeated marker cleanup run a fixture diff.

The implemented ninth matrix contract is
`content_transfers_data_views_and_dashboards_without_residue`. It:

1. refuses a dirty target containing any `elasticctl-live-*` data view or
   dashboard;
2. creates a marker index and explicit-id data view;
3. captures the current default, sets the marker default, then restores it;
4. creates a typed dashboard with one metric panel referring to the marker
   data-view id;
5. gets, lists, exports, updates, and strictly round-trips that dashboard;
6. deep-exports the dashboard and proves the bundle contains its data view;
7. deletes both objects, imports the opaque bundle, and proves the same ids and
   reference are restored;
8. creates a second marker data view, replaces the dashboard reference while
   deleting the first, and verifies the dashboard and default now resolve to
   the second id;
9. deletes the dashboard and second data view;
10. deletes the marker index and proves the original default is restored;
11. concludes with zero marker dashboards, data views, or indices and the
    unchanged prebuilt-rule baseline.

Cleanup registers ids before each mutation. Baseline capture rejects a marker
or whitespace-only default and resolves any nonempty default before mutation.
Cleanup reads the current default and restores the captured value only from an
owned marker state; it does not overwrite an unexpected nonmarker default. It
deletes data views only after every dashboard delete and the verified default
restore succeed, and deletes the marker index only after every data-view delete
succeeds. A failed prerequisite retains its dependents for the Drop retry. The
recorder derives each phase gate from the ownership that remains after the prior
phase. Any dashboard ownership blocks all data-view and backing-index cleanup;
any data-view ownership blocks backing-index cleanup. The content contract
tolerates no residue.

`xtask::CONTRACTS` contains nine entries, ending with `name: "content"` and
`features: &[DASHBOARDS]`, where `DASHBOARDS` wraps `Feature::Dashboards`.
`scripts/check-conformance-reports.sh`
recognizes the nine-contract `v0.5` family. The measured reports are under
`docs/conformance/v0.5.2/`.

