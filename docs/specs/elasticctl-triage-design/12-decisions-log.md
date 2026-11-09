[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 12. Decisions log

All four design questions are resolved:

1. **Cut line** — 0.4.0 alerts only, 0.4.1 the complete cases surface,
   0.4.2 conformance and review. Section 11.
2. **Username assignment** — required; resolved per flavor with a `uid:`
   bypass. Section 7.
3. **Alert residue** — residual closed marker alerts are accepted; no
   deletion API exists and none will be built. Section 9.
4. **Query-scoped transitions** — allowed and shipped in 0.4.0 with the
   count-and-sample dry-run guard. Section 6.

