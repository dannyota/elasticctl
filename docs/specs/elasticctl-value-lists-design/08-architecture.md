[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 8. Architecture

The layering of shared design 3 holds: the CLI parses and guards, `-api`
owns the model and the orchestration and returns typed values, and `-core`
owns the transport. `-mcp` does not change (D9).

### 8.1 `elasticctl-core`

Three send-once transport calls are added beside the existing `post_once`,
`put_once`, and `delete_once`:

- `patch_once(path, body)`: the container update (section 6.3). The existing
  `patch` retries.
- `post_multipart_once_named(path, filename, content_type, body)`: the value
  import. The existing `post_multipart_ndjson_named` deliberately replays its
  POST on a retryable answer, which for `_import` would duplicate values (V5).
- `delete_once_response(path)`: returns the status and the decoded JSON body
  instead of turning a 4xx into an error, so `value-lists delete` can read
  `references` from a 409 (section 6.5). The shared error kinds and statuses
  are built from it as usual.

`patch_once_response` and `post_multipart_once_named_response` return the
status and body of a 2xx or 4xx in the same way, so the fixture recorder can
store Kibana's own 409, 413, and 415 bodies and tests can serve them.

All five use the one-shot client with an attempt limit of 1, like the other
`_once` calls. `post_text` already reads a non-JSON body and serves
`_export`. No other transport behavior changes.

### 8.2 `elasticctl-api`

A `value_lists` module replaces `exceptions/value_lists.rs` and owns:

- the model: the container, the four types, and canonical values by type
  (section 3);
- the codec for the container and values files, and their validation
  (section 5);
- the reads: the bootstrap state, `_find` with `cursor`, the container read,
  `_export` decoded into the stored values and the set (section 3.6), and
  the scan of installed references (D26), which reuses the exception list
  and item reads of `exceptions`;
- the plan: container action and value adds and removes per list, computed
  from a local pair and a remote read;
- the apply: create, update, the two phases, and their read-backs (section
  6), returning the evidence of section 7.5 for every list, whatever the
  outcome;
- `delete` and `init`, with their outcomes.

The state engine (`state` module) gains the closure, the `value-lists/` root
in the mirror reader and writer, the `value_lists` diff block, the push
refusals and order (section 7), and the report entries. The existing
reference check in `state/push/references.rs` extends to read `list.type`
beside `list.id`.

`doctor`'s `value_list_index` check keeps its name. Its message names
`elasticctl value-lists init` and the initialize API instead of the
deprecated `POST /api/lists/index`. That is a change to `doctor` output text,
recorded in the 0.10.0 CHANGELOG.

### 8.3 `elasticctl` CLI

`value-lists` joins the command tree with the commands of section 4. The
adapters build a context, call `-api`, guard mutations, and render. The
`commands` tree and the shell completions gain the group. The `state`
commands change only through `-api`.

The guard today previews a list of strings. The value preview of section 4.1
needs a structured preview, rendered as text for the table output and as one
JSON object under `--json`. The push report path publishes the evidence that
`-api` returns before the command turns a stopped list into its exit code.

### 8.4 Spec changes that land with the code

Each lands in the same commit as the behavior it describes:

- shared design 1: value-list content leaves "out of scope";
- shared design 4: the `value-lists` lines in the command table;
- shared design 5.4: the closure and order gain value lists;
- shared design 7.7: the sentence that value-list content "is not managed
  here" is replaced by a pointer to this design, and the `push` paragraph
  states the D4 refusal;
- shared design 11: the 0.10 entry in the release ladder.
