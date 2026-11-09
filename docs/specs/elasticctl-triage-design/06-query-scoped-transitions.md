[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 6. Query-scoped transitions

An implicit-set mutation must be as safe as an explicit-ids one. The design
makes the set visible before it is mutated and honest about the race window:

1. **Preview (default).** The client runs the operator's query through
   `signals/search` (`size` = sample size, `track_total_hits: true`) and
   prints the matched count plus a sample — `_id`, rule name, severity,
   `@timestamp` — capped at 10 rows:

   ```
   $ elasticctl alerts close --query '{"term":{"kibana.alert.rule.rule_id":"…"}}' --reason false_positive
   [DRY RUN] Close alerts matching query (profile: dev @ <host>, space: default)
     matched now: 1,214   showing 10 of 1,214
     9f2a…  Suspicious PowerShell  high    2026-08-30T21:14:02Z
     …
     The set is resolved again at apply time; this count is advisory.
   Pass --yes to apply.
   ```

2. **Apply (`--yes`).** The client POSTs `signals/status` with
   `{status, query, conflicts, reason?}`. The server resolves the set and
   mutates it in one update-by-query — no client-side id round-trip, so
   there is no window where the client acts on a stale id list.

3. **Report.** The response is a raw Elasticsearch update-by-query envelope
   (measured, section 10): `total`, `updated`, `version_conflicts`, `noops`,
   `failures`. The report renders these counts verbatim and exits non-zero if
   `failures` is non-empty or `version_conflicts > 0` under `--conflicts
   abort`.

`--conflicts` defaults to `abort`, the server default: a document whose
version moved between resolution and write stops the run rather than being
silently skipped. `--conflicts proceed` opts into best-effort, and the report
still prints the conflict count. `--query` takes inline JSON or `@file`, the
`search dsl` convention. `--query` and positional ids are mutually exclusive;
an empty query (`{}` or match-all) is rejected — a mass close of *everything*
must at least say what it matches, e.g. an explicit `match_all`. The preview
count and the apply count can legitimately differ; the report shows both so
the operator sees the drift.

