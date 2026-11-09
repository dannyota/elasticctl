[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 2. Architecture and alternatives

Add a published `elasticctl-mcp` library. The existing `elasticctl` package
calls it from `elkctl mcp serve`; both existing binaries support the same
command. The MCP library owns schemas, projections, protocol routing, and
call limits. Existing API orchestration owns Elastic operations.

```text
elasticctl CLI ──> elasticctl-mcp ──> elasticctl-api ──> elasticctl-core
       └─────────────────────────> elasticctl-api
```

Both frontend crates can depend directly on core configuration and transport.
Neither `-api` nor `-core` depends on a frontend. No `clap` type enters the MCP
library, API, or core. MCP never calls the CLI renderer or captures a CLI
subprocess. `xtask` may use the MCP library for test tooling but never depends
on the CLI crate.

| Approach | Benefit | Cost | Decision |
| --- | --- | --- | --- |
| Separate library, existing binaries | Follows the planned crate boundary; same install command and binary names | Fourth published crate and packaging updates | Recommended |
| MCP modules or a third binary inside the CLI package | Preserves three published crates | Places another frontend inside the CLI crate; third binary changes archive contents if chosen | Viable, less aligned with the planned boundary |
| Reflect or subprocess the CLI | Less initial routing code | Reintroduces parsing, file flags, mutation paths, and output capture | Rejected |

There is no new generic transport trait or rewrite of existing verticals.
Core gains opt-in response limits, redirect control, and retry suppression. Explicit tool
registration and fixed adapter calls enforce the MCP operation allowlist;
the general API library still contains mutation functions for CLI callers.

