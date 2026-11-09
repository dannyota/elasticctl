[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 2. Transfer is not reconciliation

Agent- and integration-policy files are explicit export/import artifacts.
Their absence never means delete, and importing one file never scans for or
removes remote policies that the file omits.

- `state` remains rule and exception-list state only.
- `export` reads a selected set and writes a portable artifact.
- `import` acts only on stable ids present in its file.
- `delete` is the only deletion instruction.
- Agent and integration policies remain separate artifacts.
- A complete transfer imports agent policies first, then integrations.
- No environment reference is remapped by name or guessed from a default.

