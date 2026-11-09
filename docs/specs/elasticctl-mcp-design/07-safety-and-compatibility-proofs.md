[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 7. Safety and compatibility proofs

Tests must drive the public MCP router and real stdio process, not only call
private adapter functions. Compare exact catalog names and schemas. Assert
that mutation names, arbitrary commands, target changes, file inputs,
query tools without opt-in, and internal Kibana assignee/profile lookup never
reach Elastic. Doctor's public Elasticsearch `/_security/_authenticate`
read remains allowed.

Use a recording mock to compare every emitted method/path with the routes
needed by the chosen tool. Read POST paths include signals search and,
only with query opt-in, synchronous `_query` and index `_search`. Assert zero
PUT/PATCH/DELETE, Fleet setup, preview, import, async query, and PIT requests.
Inspect actual requests on error paths as well as successful results.

Inject credential-shaped sentinels into errors and excluded response fields;
prove absence from both output channels. Check changed config/environment
between calls, redirects to another authority, malformed success bodies,
capability failures, oversized chunked bodies, Unicode/escaping, cancellation,
and the fifth concurrent call. Existing CLI snapshots remain byte-identical
apart from the new command-tree/help entries and release version snapshot.

Existing fixture files remain recorded evidence and are never hand-edited.
New synthetic responses belong in adversarial tests, not fixture directories.
Reuse existing fixture sets through the production MCP adapter before adding
recordings. Need for a new request shape triggers the existing scoped recorder
workflow and independent review.

