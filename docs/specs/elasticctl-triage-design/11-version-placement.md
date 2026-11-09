[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 11. Version placement

| Version | Content |
|---|---|
| 0.4.0 | The complete alerts vertical: `alerts list|get|ack|open|close|tag|assign` including `--query` transitions and username resolution; no version floor — the only flavor divergence is the suggest route, switched at runtime; fixtures for all of it |
| 0.4.1 | The complete cases surface: `cases list|get|create|close|open|delete|attach|comment`, case assignees; the `elkctl` alias binary |
| 0.4.2 | Triage conformance contract, cross-flavor matrix run, bounded review patch |

Each version is one meaningful story — alerts, then cases, then proven.
0.4.0 is the first independently usable release; a cases read stub beside a
complete alerts vertical would dilute both. Query-scoped transitions sit in
0.4.0 (rev 1 had them in 0.4.2) because the endpoint shape is measured on
both cloud flavors and the guard design in section 6 is the same preview
machinery the id form needs anyway.

