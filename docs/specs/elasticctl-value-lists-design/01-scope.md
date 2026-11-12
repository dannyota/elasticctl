[Back to elasticctl-value-lists-design](../elasticctl-value-lists-design.md)

## 1. Scope

In scope:

- value-list containers of four types, `keyword`, `ip`, `ip_range`, and
  `text`, in the profile's space;
- their values, read, validated, written, and reconciled exactly;
- a `value-lists` command group: `list`, `get`, `validate`, `export`,
  `import`, `delete`, and `init`;
- the state mirror: `state pull` writes every value list a mirrored exception
  item references, `state diff` reports value-list drift, and `state push`
  writes value lists before the exceptions that use them;
- a `doctor` message and a `state push` refusal that name the supported
  bootstrap.

Out of scope:

- the other 19 API types (`binary`, `date`, `long`, and the rest). They are
  refused by name, never mirrored;
- item `meta`, and the `serializer` and `deserializer` parameters, which
  Kibana removed in 9.2.7, 9.3.2, and 9.4.0 and now ignores;
- `deleteReferences=true`, `ignoreReferences=true`, and
  `DELETE /api/lists/index`. Each widens suppression or removes every list in
  the space ([research](../../plans/v0.10-research.md#recommendation));
- value lists that no mirrored exception references. `value-lists export`
  covers them, as `exceptions export` covers unreferenced exception lists;
- copying a list between spaces in one command. Every command acts on the
  profile's space, as for every other object;
- MCP tools. 0.10.0 adds none (owner decision 9). Read-only tools may follow
  in a later 0.10 patch; mutation would need a new class under the 0.9
  mutation design;
- endpoint exceptions, which Kibana does not allow to use value lists.

What does not change:

- `state push` never deletes a remote rule, exception container, or value-list
  container. Items and values inside a mirrored container are reconciled
  exactly, as shared design 5.4 already does for exception items.
- Rule identity is `rule_id`; exception list identity is `list_id` plus
  `namespace_type`; value-list identity is its `id` within the space (section
  3).
- Every remote mutation is a dry run by default, applies with `--yes`, and
  names the profile, host, and space.
