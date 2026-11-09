[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 10. Reference-safe data-view deletion

Kibana's direct data-view DELETE succeeds even while dashboards still refer to
the id. The dashboard remains but is broken. elasticctl therefore treats
reference discovery as part of the deletion plan.

For each source id, the client calls
`POST /api/data_views/swap_references/_preview` with `fromId` and `toId` both
equal to the source. Live measurement proves this self-swap is accepted and
returns every referring saved object's `id` and `type` without changing it.

Without `--replace-with`:

- any returned reference refuses the deletion and lists all dependents;
- a source that is the current default also refuses and directs the operator
  to `default unset` or `--replace-with`;
- an unreferenced, non-default source previews a direct DELETE.

With `--replace-with TARGET`:

- the target resolves before the guard and must differ from every source;
- one source may be replaced per command, so multiple source selectors with
  `--replace-with` are rejected;
- the preview lists every affected saved object and a default change when
  applicable;
- apply calls `POST /api/data_views/swap_references` with
  `{fromId, toId, delete: true}`;
- success requires `deleteStatus.deletePerformed == true` and
  `deleteStatus.remainingRefs == 0`;
- marker probes on 2026-09-02 found that Serverless 9.6.0, Hosted 9.5.2, and
  self-managed 9.5.1 retain the deleted source id as the default after a
  successful swap/delete. Every probe restored the prior default and left no
  marker views.
- if the guarded source was default, apply GETs the default again after the
  strict swap and before any forceful default POST. A current default equal to
  the deleted source is updated to the replacement. A current default already
  equal to the replacement is success with no POST. A null or other default
  produces the partial error `references moved and source deleted; default
  changed before update` with no POST. A post-swap default GET error produces
  `references moved and source deleted; default recheck failed: {message}`
  with no POST. A replacement POST error remains `references moved and source
  deleted; default update failed: {message}`.

The guard retains the normalized reference list for each source and the full
default-data-view id snapshot. Immediately before each source mutation, apply
must call the self-swap preview, then GET the default, and only then DELETE or
swap. Both reads must exactly equal the guarded snapshots. A changed reference
list fails that source with `references changed since preview`; a changed
default fails it with `default data view changed since preview`. Neither case
may send DELETE, swap, or default POST for that source. A direct-source read,
preview, or snapshot failure is a failed row and apply continues to independent
sources. Replacement permits one source, so its check failure is its one failed
row and stops. Kibana exposes no conditional mutation token. The final
post-swap default GET-to-POST interval is therefore the unavoidable
conditional-write window.

`data-views default set` resolves the selector and sends its id with
`force: true`. `default unset` sends `data_view_id: null` with `force: true`.
The client validates ids because Kibana's endpoint does not. `GET
/api/data_views/default` accepts only the exact `{ "data_view_id": null }` or
`{ "data_view_id": "" }` envelope as no default, and preserves every
non-empty string exactly, including whitespace. Missing, non-string, or
extra-member envelopes are `http`. Writes remain stricter: unset is `null`,
and an empty or whitespace-only set id is local `error` before I/O.

