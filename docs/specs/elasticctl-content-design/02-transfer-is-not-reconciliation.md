[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 2. Transfer is not reconciliation

Rules and exception lists have a desired-state mirror because their local
files are deployment intent. Dashboard and data-view files in 0.5 are explicit
export/import artifacts. Their absence never means delete, and importing one
file never scans for or removes remote content that the file omits.

Consequences:

- `state` remains rule and exception-list state only.
- `export` reads a selected set and writes a portable artifact.
- `import` acts only on object ids present in its file.
- `delete` is the only deletion instruction.
- No background dependency remapping occurs. Typed dashboards keep their
  referenced ids; the operator creates matching ids or uses an opaque bundle.

