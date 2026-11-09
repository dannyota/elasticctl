[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 11. Architecture

Dependency direction remains:

```text
elasticctl-cli  ->  elasticctl-api  ->  elasticctl-core
```

`elasticctl-api` owns the verticals:

- `content_codec` encodes and decodes portable JSON/YAML without CLI types;
- `data_views` owns route wrappers and response models;
- `data_views_ops` owns selection, normalization, import, default, and delete
  orchestration;
- `dashboards` owns typed dashboard route wrappers and strict decoders;
- `dashboards_ops` owns selection, portable transfer, race checks, loss
  detection, and delete orchestration;
- `saved_objects` owns opaque export/import wrappers and the read-only bundle
  scan.

`elasticctl-cli::cmd::{data_views,dashboards}` resolve context, invoke API
plans, apply the guard, serialize typed results, and hand values to `render`.
They do not orchestrate stacks or parse server response bodies.

`elasticctl-core` gains only a named-filename multipart helper needed by the
Saved Objects import. The existing rules and exceptions wrapper continues to
send the same body and headers through that helper. No content model enters
`-core`.

The `DashboardSpec.data` and extensible nested data-view maps are JSON values,
but command outcomes and route envelopes are typed structs. No orchestration
function returns a pre-rendered string except an artifact body whose verbatim
bytes are the command's product.

