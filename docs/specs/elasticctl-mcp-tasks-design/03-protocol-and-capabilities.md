[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 3. Protocol and capabilities

The protocol contract of [0.7 section 3](../elasticctl-mcp-design/03-protocol-and-dependencies.md#3-protocol-and-dependencies)
is unchanged: target revision 2026-07-28, legacy 2025-11-25 initialization,
exactly those two advertised revisions, stdio only, one dedicated session
thread, and SDK-owned protocol fields.

### Dependency

Keep `rmcp = "=3.9.0"` with `default-features = false` and features
`server`, `macros`, and `transport-io`. No feature is added. In 3.9.0 the
`server` feature already provides every handler 0.8 implements:
`list_resources`, `list_resource_templates`, `read_resource`, `list_prompts`,
`get_prompt`, and `complete`. The features `elicitation` and `request-state`
stay off. The locked dependency graph does not change.

### Advertised capabilities

| Version | `capabilities` | `instructions` |
| --- | --- | --- |
| 0.7.x | `{"tools": {}}` | absent |
| 0.8.0 | `{"tools": {}}` | static text, section 7.2 |
| 0.8.1 and later | `{"prompts": {}, "resources": {}, "tools": {}}` | same static text |

`prompts` and `resources` are empty objects. The server never sets
`listChanged` or `subscribe`, and it declares no `completions`, `logging`,
`experimental`, or `extensions` entry. The same capability object is returned
by `server/discover` on the current path and by `initialize` on the legacy
path.

### Methods

| Method | 0.8.0 | 0.8.1 |
| --- | --- | --- |
| `tools/list`, `tools/call` | 24 or 26 tools | unchanged |
| `resources/list`, `resources/templates/list`, `resources/read` | static method-not-found error, as in 0.7 | implemented, section 8 |
| `prompts/list`, `prompts/get` | static method-not-found error, as in 0.7 | implemented, section 9 |
| `completion/complete` | SDK default | static method-not-found error, code `-32601` |
| `subscriptions/listen`, `resources/subscribe`, `resources/unsubscribe` | not implemented | not implemented |
| `tasks/get`, `tasks/update`, `tasks/cancel`, `skills/list`, `skills/get`, `resources/directory/read`, `logging/setLevel` | not implemented | not implemented |

The SDK default for `completion/complete` returns an empty result even when
the capability is absent. 0.8.1 overrides it so an unadvertised method is
refused. `accepted_subscription_filter` keeps its default of `None`, which
leaves `subscriptions/listen` unimplemented.

### Result fields

On the current path the SDK writes `resultType: "complete"` on every result
and `ttlMs: 0` with `cacheScope: "private"` on `tools/list`,
`resources/list`, `resources/templates/list`, `resources/read`, and
`prompts/list`. The server does not override these values. Zero means a
client may refetch whenever it needs the data; private is correct because a
resource body is read under one credential. On the legacy path the SDK omits
all three fields.

Every list returns one page with no `nextCursor`. `resources/list`,
`resources/templates/list`, and `prompts/list` reject a request that carries
a `cursor` with JSON-RPC `-32602` and the static message `Invalid cursor`.
`tools/list` keeps its 0.7 behavior.

List order is lexical: tools by name, resources by URI, templates by
`uriTemplate`, prompts by name. No list depends on the connection, on an
earlier request, or on Elastic. The tool list depends only on the startup
query flag.

### Tool annotations

The four new tools carry the 0.7 annotation set: `readOnlyHint: true`,
`destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`. Each
has an input schema that rejects unknown fields and an output schema with
root `type: "object"` and the success and failure alternatives.
