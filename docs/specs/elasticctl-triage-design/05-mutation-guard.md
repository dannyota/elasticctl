[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 5. Mutation guard

Every mutation previews by default and applies with `--yes`, printing profile,
host, and space, per section 6.1 of the main spec. For an explicit id list the
preview resolves each `_id` first and shows what would change:

```
$ elasticctl alerts close 9f2a... 41c7...
[DRY RUN] Close 2 alerts (profile: dev @ <host>, space: default)
  9f2a...  Suspicious PowerShell   open -> closed
  41c7...  Rare DNS Tunnel         acknowledged -> closed
Pass --yes to apply.
```

An `_id` that resolves to nothing is reported before anything applies; the
command refuses to proceed on a partial resolution rather than closing the
subset (fail-closed, section 6.3). The status route is idempotent per the
update-by-query semantics: a no-op transition counts as processed, so previews
mark `already closed` rows and the apply still succeeds.

Case mutations carry the same guard. `cases delete` is the only destructive
verb in the area and its preview names each case title.

