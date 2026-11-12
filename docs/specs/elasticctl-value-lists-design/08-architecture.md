[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 8. Architecture

The layering of shared design 3 holds: the CLI parses and guards, `-api`
owns the model and the orchestration and returns typed values, and `-core`
owns the transport. `-mcp` does not change (D9).

### 8.1 `elasticctl-core`

Two send-once transport calls are added beside the existing `post_once`,
`put_once`, and `delete_once`:

- `patch_once(path, body)`: the container update (section 6.3). The existing
  `patch` retries.
- `post_multipart_once_named(path, filename, content_type, body)`: the value
  import. The existing `post_multipart_ndjson_named` deliberately replays its
  POST on a retryable answer, which for `_import` would duplicate values (V5).

Both use the one-shot client with an attempt limit of 1, like the other
`_once` calls. `post_text` already reads a non-JSON body and serves
`_export`. No other transport behavior changes.

### 8.2 `elasticctl-api`

A `value_lists` module replaces `exceptions/value_lists.rs` and owns:

- the model: the container, the four types, and canonical values by type
  (section 3);
- the codec for the container and values files, and their validation
  (section 5);
- the reads: the bootstrap state, `_find` with `cursor`, the container read,
  and `_export` decoded into distinct values and a duplicate count;
- the plan: container action and value adds and removes per list, computed
  from a local pair and a remote read;
- the apply: create, update, reconcile, and read-back (section 6), returning
  a typed outcome per list: applied, failed, or unknown, with counts;
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

### 8.4 Spec changes that land with the code

Each lands in the same commit as the behavior it describes:

- shared design 1: value-list content leaves "out of scope";
- shared design 4: the `value-lists` lines in the command table;
- shared design 5.4: the closure and order gain value lists;
- shared design 7.7: the sentence that value-list content "is not managed
  here" is replaced by a pointer to this design, and the `push` paragraph
  states the D4 refusal;
- shared design 11: the 0.10 entry in the release ladder.
