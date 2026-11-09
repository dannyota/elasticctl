[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 9. Mutation guard, imports, and races

Every remote mutation uses `guard::check`. Preview and apply print profile,
host, and space. The guarded paths are:

```text
data-views import
data-views delete
data-views default set
data-views default unset
dashboards import
dashboards delete
dashboards bundle import
```

Portable import fully reads and validates the file before any server call.
With neither conflict flag, any existing id makes the plan fail before the
guard. `--skip-existing` reads the server, removes existing ids from the
pending set, and reports them as skipped. `--overwrite` classifies each object
as create, replace, or no-op and previews that exact action.

The resolved file body and preflight snapshots travel in the plan. Apply does
not re-read the path after the guard. Immediately before each write, it re-GETs
that object:

- a planned create refuses if the id appeared since preview;
- a planned replace or no-op refuses if the current canonical value differs
  from the preview snapshot;
- a missing planned replacement is a conflict, not a create.

The public APIs expose no conditional-write token for these operations. A
change can still race the final GET and write. Reports call this out as the
smallest unavoidable window. Multi-object imports are not transactions: they
continue after per-object failures and report every succeeded, skipped,
failed, and lossy object. They do not roll back successful earlier writes.
Each failed row in a portable JSON/YAML import carries `applied: false` until
a mutation route for that object has returned a decoded success, and
`applied: true` after that point. This flag confirms a known earlier write; it
does not claim that a timed-out or malformed response made no remote change.
Opaque bundle errors retain the server's object shape instead.

Dashboard PUT can answer 2xx after discarding submitted content. After every
successful PUT, elasticctl recursively checks that the submitted body is a
subset of `response.data`. A missing or changed submitted value produces a
report row with `applied: true`, `lossy: true`, and a field path. elasticctl
then GETs the dashboard once and appends any `warnings[].message`. Lossy is a
failure and exits non-zero. It is not rolled back because restoring the prior
snapshot could overwrite a concurrent change and still cannot recreate a
panel the public API cannot express.

