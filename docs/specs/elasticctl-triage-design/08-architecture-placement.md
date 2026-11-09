[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 8. Architecture placement

Per the standing rule, orchestration returns typed values from `-api` and the
CLI adapter guards and renders:

- `elasticctl-api::alerts` — typed wrappers over `signals/search`,
  `signals/status`, `signals/tags`, `signals/assignees`; sibling of `rules`.
- `elasticctl-api::alerts_ops` — filter construction, id resolution, preview
  plan and outcome types, the query-scoped preview/apply pair.
- `elasticctl-api::profiles` — username-to-uid resolution behind one function;
  owns the flavor switch between the public and internal suggest routes.
- `elasticctl-api::cases` / `cases_ops` — same split for the cases routes.
- `elasticctl-cli::cmd::alerts` / `cmd::cases` — clap parsing, guard, render.
- `elasticctl-core` — keeps its existing `kbn-xsrf` and `elastic-api-version`
  handling and gains only internal-origin request support
  (`Transport::get_internal` and `post_internal`, which send
  `x-elastic-internal-origin` and omit `elastic-api-version`) plus the
  `Transport::has_es_url` accessor that lets `-api` name a missing `es_url`
  in a suggest failure. No version floor: the only flavor divergence in the
  whole triage area is the profile-suggest route, switched at runtime on the
  probed `Flavor` (section 7), not gated behind a `Feature` variant. Every
  supported stack at the 9.5.1 evidence floor (section 10) serves every
  triage route.

No new crate. The MCP-readiness rule holds: every command returns a struct.

