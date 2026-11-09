[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 16. Decisions log

1. **Product boundary:** transfer and administration, not `state`
   reconciliation.
2. **Format:** typed JSON/YAML by default; separate opaque NDJSON bundles for
   dependency-inclusive migration.
3. **Cut line:** 0.5.0 data views, 0.5.1 dashboards, 0.5.2 proof and review.
4. **Loss:** warning-bearing export refuses; accepted-but-dropped import is an
   applied, lossy failure.
5. **Delete:** referenced data views require explicit replacement; direct
   broken-reference deletion is never exposed.
6. **Floor:** typed dashboards require measured Kibana 9.5.1 or newer.

