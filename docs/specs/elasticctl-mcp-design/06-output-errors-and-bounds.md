[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 6. Output, errors, and bounds

Successful structured content has this shape:

```json
{
  "target": {"profile": "analyst", "host": "kibana.example.test", "space": "default"},
  "data": {},
  "page": null
}
```

Output schemas describe serialization. Always-written nullable fields are required;
fields omitted when absent stay optional. Input schemas keep their existing requirements.
The following lists the required fields for the shared envelopes and supporting
objects, plus the two tool projections whose required fields changed. Other tool
projections retain their own required sets.

- Success envelope: `data`, `page`, `target`.
- PageInfo: `limit`, `returned`, `total`, `has_more`, `truncated`.
- ToolError: `kind`, `http_status`, `code`, `message`.
- Failure envelope: `target`, `error`; target: `profile`, `host`, `space`.
- `stack_info.data`: `version`, `flavor`, `license`, `spaces`.
- `search_dsl.data.hits[]`: `id`, `index`, `score`, `source`.

Each tool defines its own typed `data` schema. List results, exception items,
and query rows carry `page` with `limit`, `returned`, nullable exact `total`,
nullable `has_more`, and boolean `truncated`. Other gets have `page: null`.
Set `truncated` when the adapter omits fetched rows, or, for `rules_list`'s
server page, when the server total exceeds `returned`; set `has_more` only when
known, otherwise null. Do not turn a lower-bound server count into an exact
total. In particular, DSL totals are null because the existing decoder drops
the total relation. Fleet list operations currently count before their local
search filter. Call them with `limit: None`, derive the filtered total from
the complete returned vector, then apply MCP row/byte limits. Keep CLI totals
unchanged. There is no domain result cursor in 0.7; narrow filters
or use exact gets after a capped list. MCP catalog pagination is separate.

Errors use the same target plus an error object:

```json
{
  "target": {"profile": "analyst", "host": "kibana.example.test", "space": "default"},
  "error": {"kind": "permission", "http_status": 403,
    "code": "elastic_permission", "message": "The selected credential cannot read this data."}
}
```

Declare the success and error alternatives in each output schema. The error
object retains the existing error-kind vocabulary. Local failures use stable
codes `invalid_argument`, `busy`, `deadline_exceeded`, and `result_too_large`,
with `kind` respectively `error`, `error`, `timeout`, and `unsupported`.
An oversized input line ends the connection before a request can be decoded;
it has no tool error envelope. An upstream body-limit failure retains core's
`unsupported` kind and maps to `elastic_unsupported`. Do not parse core error
messages to invent a more specific code.
Map Elastic errors to `elastic_<kind>` and a static message per kind. Do not
copy `Error.message`, request text, raw bodies, URLs, credentials, or arbitrary
SDK error data into tool errors or startup diagnostics. Safe validation errors
may name a static field and its permitted range, never its supplied value.

Doctor failing checks remain a successful diagnostic report with `ok: false`;
they are not an exception. A failure to construct its transport is a tool
error. MCP does not reuse the CLI's rendered-field exit-status inference.

| Limit | Value | Enforcement |
| --- | --- | --- |
| Input line | 262,144 bytes, excluding newline | Before the SDK buffers/parses the full line; oversize terminates the connection with a static stderr diagnostic |
| Structured content | 262,144 serialized UTF-8 bytes | Before building the text copy |
| Complete outbound JSON-RPC frame | 1,048,576 serialized bytes, excluding newline | Includes JSON escaping, text duplication, SDK metadata, and request id |
| Upstream body | 16,777,216 decoded bytes per response | Optional core transport setting; check declared size and count streamed chunks |
| Rows | Default 50, maximum 200 | Validate before I/O; preserve explicit cap metadata |
| Active tool calls | Four | Try-acquire a semaphore; fifth call returns `busy`, with no queue or Elastic request |
| Whole call | Default 30 seconds, allowed 1-120 | Includes capability probe, retries, paging, projection, and serialization |
| Shutdown grace | Five seconds | Cancel active calls on stdin EOF or process signal, then stop |

Limits are product choices, not MCP defaults. Count UTF-8 bytes, not string
characters. Stop list output between complete rows to meet the structured and
frame caps. Mark omitted rows as truncated. If no row or a single-object result
fits, return `result_too_large`; do not split fields, emit invalid JSON, or
claim success with empty data. The error response itself must fit the frame.

Core's existing constructors preserve their behavior. Add an opt-in constructor
or options structure for response-body limits, disabled redirects, and
disabled retries; apply
the body limit to success and error responses on every transport path.
The MCP transport always has debug off. This is bounded request memory, not
a claim that a full API collector only performs one bounded read. Existing
rule, exception, and Fleet collectors may scan more than the displayed rows;
the outer deadline stops them and returns a failure, never a partial success
disguised as a complete collection. Avoid an unrelated paging rewrite in 0.7.

Observe the SDK request cancellation token while awaiting API operations.
Drop the API future and release its permit on cancellation. Send no later
result for that request. A client disconnect cancels all active work.
Synchronous queries may continue briefly inside Elastic after disconnect;
the server promises to stop client work, not to prove backend cancellation.
There are no client-owned PIT or async result objects needing cleanup.

