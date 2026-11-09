[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 6. Dashboard model and portable artifact

The typed Dashboards API returns `{id, data, meta}`. `meta` is server-owned
creation, update, ownership, and warning context. The portable artifact keeps
only identity and the API-compatible body:

```json
[
  {
    "id": "security-overview",
    "data": {
      "title": "Security overview",
      "description": "Detection activity",
      "panels": []
    }
  }
]
```

`DashboardSpec.id` is a required non-empty string. `DashboardSpec.data` is a
JSON object with a required non-empty string `title`. The dashboard body stays
as an ordered `serde_json::Map`: elasticctl must preserve new GA fields it does
not yet know instead of down-converting the public schema. The wrapper is typed
and validated; the evolving panel union remains the server's typed contract.

Export fetches every selected dashboard individually after list resolution,
sorts by id, removes `meta`, and writes stable JSON or YAML. If the GET response
contains any `warnings[].message`, export refuses the typed artifact and names
the dashboard plus every warning. The error directs the operator to
`dashboards bundle export`, because the public transformation has already
removed the unsupported content.

Portable import rejects `time_range.mode` before mutation. Kibana accepts that
field for validation but does not persist it, so accepting it would guarantee
a false round trip. Other submitted values must survive the server response as
a recursive subset; extra derived response fields are allowed.

