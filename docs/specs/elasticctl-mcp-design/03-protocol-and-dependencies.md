[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 3. Protocol and dependencies

Use `rmcp = "=3.9.0"`, `default-features = false`, with `server`, `macros`,
and `transport-io`. Use the SDK's re-exported `schemars` for schemas. Keep
the locked dependency graph and Rust 2024 / Rust 1.97.1 workspace floor.

The target protocol is 2026-07-28. Support its optional `server/discover`
and direct metadata-bearing requests without an initialization handshake.
Also test legacy 2025-11-25 initialization through the SDK compatibility path.
Override `ServerHandler::supported_protocol_versions` with exactly these two
revisions; the SDK default advertises more. Unsupported current request
metadata produces a protocol error. Legacy initialization follows version
negotiation: echo a supported requested revision; otherwise offer 2025-11-25
as the configured legacy fallback. A client that cannot use that version
disconnects. Do not claim support for the original unsupported revision or
hand-write a parallel protocol implementation.

Select the lifecycle from the first bounded SDK-decoded message. A complete
current request enters the SDK concurrent service loop before its handler
runs, so the first tool call supports cancellation and admission limits.
Current connections require 2026-07-28 metadata on every request and reject
a later initialization handshake. The 2025-11-25 revision uses initialization.
An initial ping without complete current metadata selects legacy startup;
a later current request without initialization is rejected before tool work.
Such a client must initialize or reconnect. The SDK still owns parsing,
legacy negotiation, cancellation routing, and protocol result fields.

Current protocol result objects include `resultType: "complete"`. Legacy
results omit that field. Live validation checks the selected protocol
before checking the tool result; the discriminator is not part of
`structuredContent`.
Current tools/list results include `ttlMs: 0` and `cacheScope: "private"`;
legacy tools/list results omit these hints. Protocol fields stay outside
`structuredContent`.

Advertise tools only. Return the fixed catalog in lexical name order, in one
page, with no next cursor. Catalog discovery makes no Elastic requests and
does not require a credential. The catalog is fixed for a process and its
startup query setting; no tool changes it. Descriptions are static project
text, never server-supplied rule names or descriptions.

Every registered tool sets `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, and `openWorldHint: true`. These describe the data-read
contract, not deterministic results or absence of compute/inference costs.
The registration and request tests enforce scope; annotations do not.
From 0.9 the opt-in mutation tools are the exception; see
[mutation design section 3](../elasticctl-mcp-mutation-design/03-startup-opt-in-and-catalog.md).

Use object-shaped structured results and the same compact JSON as one text
content item. Each tool has an input and output schema. Input objects reject
unknown fields. Inputs are validated before network access. Protocol envelope
and unknown-tool errors use SDK JSON-RPC errors. Tool argument validation and
Elastic failures use `isError: true` with the error envelope in section 6.

Every output schema declares root `type: "object"` alongside its success and
failure alternatives. Current MCP permits broader output schemas, but the
[2025-11-25 tool schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-11-25/schema.ts#L1193-L1205)
requires an object root. Both lifecycle paths use the same compatible catalog;
this declaration does not wrap or change the result envelope.

The SDK owns protocol-specific fields, including the current `resultType`,
`ttlMs`, and `cacheScope`.
An application must not assume that the current and legacy wire envelopes
are byte-identical. Their tool data and catalog must agree.

Each public MCP session runs on a dedicated OS thread with a current-thread
Tokio runtime and a thread-local no-op tracing subscriber. This suppresses SDK
request, result, error, and notification logs even when the embedding process
enables tracing. It leaves the process-wide subscriber and ordinary CLI
logging unchanged. Approved MCP diagnostics use explicit static messages.
The four active calls remain concurrent as asynchronous work on that thread.
Caller cancellation reaches the session through the shared root token.

Await SDK and bounded transport cleanup before ending the session runtime.
Use background runtime shutdown only after that cleanup; Tokio's blocking
stdin read cannot be cancelled and must not extend the five-second grace.
The public stream bounds remain unchanged. The supported stdio and duplex
streams can move to this runtime; runtime-affine stream support would need a
separate design.

