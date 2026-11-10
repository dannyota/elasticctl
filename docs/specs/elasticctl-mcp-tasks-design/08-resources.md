[Back to elasticctl-mcp-tasks-design](../elasticctl-mcp-tasks-design.md)

## 8. Resources

Resources ship in 0.8.1. A resource is a URI form of one existing tool call
with fixed arguments. It adds no new read path, projection, or limit.

### 8.1 URI scheme

```text
elasticctl://stack/<path>
```

- The scheme is `elasticctl`, lowercase. The authority is a namespace, not a
  host. 0.8 defines one namespace, `stack`: objects on the deployment bound
  at startup. `plans` is reserved for mutation plans and unused.
- A URI never holds a host, profile, space, credential, port, query,
  fragment, or local path. Target identity is inside the body, as in every
  tool result.
- Identifiers are path segments, percent-encoded per RFC 3986.

Parsing, in this order. Any failure is "resource not found":

1. The URI is at most 4,096 bytes and starts with `elasticctl://stack/`.
2. It holds no `?`, `#`, or `@`, and no empty segment.
3. Each segment is percent-decoded once. An invalid escape or a result that
   is not UTF-8 fails.
4. A decoded identifier segment is 1 to 1,024 bytes, not whitespace-only,
   holds no character in U+0000 to U+001F or U+007F, and is not `.` or `..`.
5. The decoded segments match exactly one row of the tables below. Literal
   segments compare byte for byte. `namespace_type` is `single` or
   `agnostic`.

The server never normalizes, lowercases, or trims an identifier, and never
fetches a URI. Only the tables below reach Elastic.

### 8.2 Listed resources

`resources/list` returns exactly these five, in this order, with
`mimeType: "application/json"`. It sends no Elastic request and needs no
credential.

| URI | `name` | `title` | Tool and fixed arguments |
| --- | --- | --- | --- |
| `elasticctl://stack/coverage/tactic` | `coverage-tactic` | Detection coverage by ATT&CK tactic | `detection_coverage` `{"group_by":"tactic","limit":200}` |
| `elasticctl://stack/coverage/technique` | `coverage-technique` | Detection coverage by ATT&CK technique | `detection_coverage` `{"group_by":"technique","limit":200}` |
| `elasticctl://stack/doctor` | `doctor` | Stack diagnostics | `stack_doctor` `{}` |
| `elasticctl://stack/info` | `info` | Stack version and flavor | `stack_info` `{}` |
| `elasticctl://stack/prebuilt-rules/status` | `prebuilt-rules-status` | Prebuilt rule status | `rules_prebuilt_status` `{}` |

Each `description` is the matching tool's description. No resource has
`size`, `icons`, or `annotations`.

### 8.3 Resource templates

`resources/templates/list` returns exactly these four, in this order, with
`mimeType: "application/json"`.

| `uriTemplate` | `name` | `title` | Tool and arguments |
| --- | --- | --- | --- |
| `elasticctl://stack/alerts/{alert_id}` | `alert` | Alert by id | `alerts_get` `{"alert_id": alert_id}` |
| `elasticctl://stack/cases/{case_id}` | `case` | Case by id | `cases_get` `{"id": case_id}` |
| `elasticctl://stack/exception-lists/{namespace_type}/{list_id}` | `exception-list` | Exception list by namespace and id | `exceptions_get` `{"list_id": list_id, "namespace": namespace_type, "limit": 50}` |
| `elasticctl://stack/rules/{rule_id}` | `rule` | Rule by rule_id | `rules_get` `{"selector": rule_id}` |

The rule template is exact-id only. `rules_get` also accepts a display
name, so after the read the server compares the returned `rule_id` with the
decoded segment. A mismatch is "resource not found". Identity stays
`rule_id`, never a name.

Each template `description` is the matching tool's description, except the
rule template's, which is `Inspect one rule by its exact rule_id.` because
the `rules_get` text also offers a display name.

Dashboards, data views, and Fleet policies have no template in 0.8. Their
get tools remain. Adding a template later is additive.

### 8.4 Reading

`resources/read` resolves the URI, then runs the tool adapter through the
same admission, deadline, and cancellation path as `tools/call`. A resource
read holds one of the four call permits.

The result has one content item:

```json
{"contents": [{"uri": "<the request URI, unchanged>", "mimeType": "application/json", "text": "<json>"}]}
```

`text` is the compact JSON success envelope `{target, data, page}`. It is
byte-identical to the text content the matching `tools/call` returns for the
same arguments at the same moment. The 262,144-byte structured cap applies
to `text`, and the 1,048,576-byte cap applies to the frame. The two coverage
resources trim rows exactly as the tool does and say so in `page`.

There is no binary content and no embedded or linked resource. Tool results
in 0.8 do not carry `resource_link` blocks or URI fields; the ids they return
fill the templates above. What the two evidence clients do with resource
links is unmeasured.

### 8.5 Errors

A failed read is a JSON-RPC error, because the protocol has no error result
for resources.

| Cause | Current path | Legacy path | `message` | `data` |
| --- | --- | --- | --- | --- |
| URI fails section 8.1, the matching tool refuses the decoded id, Elastic answers `not_found`, or the rule id mismatches | `-32602` | `-32002` | `Resource not found` | absent |
| A `cursor` on a list request | `-32602` | `-32602` | `Invalid cursor` | absent |
| Fifth active call | `-32603` | `-32603` | `Resource read failed` | `{"kind":"error","http_status":null,"code":"busy"}` |
| Deadline | `-32603` | `-32603` | `Resource read failed` | `{"kind":"timeout","http_status":null,"code":"deadline_exceeded"}` |
| Body above the cap | `-32603` | `-32603` | `Resource read failed` | `{"kind":"unsupported","http_status":null,"code":"result_too_large"}` |
| Any other Elastic or core failure | `-32603` | `-32603` | `Resource read failed` | `{"kind": kind, "http_status": status or null, "code": "elastic_<kind>"}` |

The SDK helper for "resource not found" emits `-32002` and upgrades it to
`-32602` for a 2026-07-28 peer. `data` never holds the URI, a remote message,
or any request text. A cancelled read sends no response, as in 0.7.

A read never returns an empty `contents` array.

### 8.6 What is left out

- **Subscriptions.** `subscribe` is not declared and `subscriptions/listen`
  is not implemented. A resource update signal would need the server to poll
  Elastic with no call in progress.
- **List changes.** Both lists are compile-time constants.
- **Completion.** Suggesting ids would need Elastic reads driven by
  keystrokes, and neither evidence client is verified to send
  `completion/complete`.
- **Dynamic listing.** See decision D14 and its alternative.
