[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 3. Startup opt-in and catalog

The operator runs:

```bash
elkctl --profile analyst --space default mcp serve
elkctl --profile analyst --space default mcp serve --allow-mutations rules-toggle
elkctl --profile analyst --space default mcp serve --allow-mutations rules-toggle,cases
```

The first form is unchanged from 0.8: no mutation tool is listed, and a call
to a mutation tool name is the static unknown-tool protocol error.

`--allow-mutations` rules:

- The value is a comma-separated list of class names. The flag may repeat.
  Repeats and duplicates fold into one set.
- Class names are `rules-toggle` (0.9.0), `alerts-triage`, `cases`, and
  `rules-create` (0.9.1). A version rejects names it does not ship.
- There is no `all` value and no wildcard. A class added later is never
  granted by an old command line.
- An empty value, an unknown name, or surrounding whitespace is a usage
  error: exit 2, the existing static `Invalid MCP serve arguments.` line, no
  echo of the value.
- The flag combines freely with `--allow-query-tools`.
- The setting cannot be read or changed through MCP. Changing the environment
  or config after startup does not change it.

The CLI passes the raw strings to `elasticctl_mcp::MutationClasses::parse`.
`ServerOptions` gains `allow_mutations: MutationClasses`, default empty. No
`clap` type crosses into the library. The library validates the set again in
`serve_io` before protocol startup.

When the set is not empty, startup writes one more static line to stderr
before the protocol starts:

```json
{"warning":{"kind":"mutations_enabled","message":"MCP mutation tools are enabled.","classes":["rules-toggle"]}}
```

Startup still makes no Elastic request and needs no credential. A credential
that cannot perform a class is found when a plan is made
([section 5.2](05-plans.md#52-binding)).

One more startup check needs no network. Every plan binds the credential
through Elasticsearch, so a non-empty class set requires the resolved profile
to have `es_url`. Without it the server exits 1 before the protocol starts,
with this static line and no other detail:

```json
{"error":{"kind":"error","message":"MCP mutation tools need an Elasticsearch URL. Set es_url in the profile or ELASTICCTL_ES_URL."}}
```

The library makes the same check in `serve_io`. A profile without `es_url`
still serves the read-only catalog when the flag is absent.

`mcp serve` stays `mutates: false` in the command tree and stays out of
`guard::MUTATING`. The command itself changes nothing; the `--allow-mutations`
help text says what it enables. The `mcp` command description drops the word
"read-only".

### Catalog

Mutation tools are added to the fixed catalog by class. The catalog stays in
lexical name order, in one page, fixed for the process.

| Since | Class | Tool | Purpose |
| --- | --- | --- | --- |
| 0.9.0 | any class | `plan_apply` | Ask for confirmation, then apply one plan |
| 0.9.0 | any class | `plan_discard` | Close an open plan |
| 0.9.0 | any class | `plan_get` | Return one plan and its outcome |
| 0.9.0 | any class | `plan_list` | Return open and recent plans |
| 0.9.0 | `rules-toggle` | `rules_set_enabled_plan` | Plan enabling or disabling rules |
| 0.9.1 | `alerts-triage` | `alerts_set_status_plan` | Plan a status change for alerts by id |
| 0.9.1 | `alerts-triage` | `alerts_set_tags_plan` | Plan adding and removing alert tags by id |
| 0.9.1 | `cases` | `cases_comment_plan` | Plan one comment on a case |
| 0.9.1 | `cases` | `cases_create_plan` | Plan one new case |
| 0.9.1 | `cases` | `cases_set_status_plan` | Plan closing or reopening cases |
| 0.9.1 | `rules-create` | `rules_create_plan` | Plan one new rule, created disabled |

The four plan tools are listed when at least one class is enabled. A planner
is listed only when its class is enabled. A tool that is not listed is
unknown to the router: the name is resolved against the enabled set before
arguments are decoded.

| Startup | 0.8 | 0.9.0 with `rules-toggle` | 0.9.1 with all four classes |
| --- | --- | --- | --- |
| Default | 24 tools | 29 | 35 |
| `--allow-query-tools` | 26 tools | 31 | 37 |

Without `--allow-mutations` the counts and every definition equal 0.8.

Names ending in `_plan` are planners. Names starting with `plan_` act on
stored plans. 0.9 reserves both patterns.

### Annotations

The 0.7 rule that every tool is read-only applies to every tool outside this
table.

| Tool | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` | `_meta` |
| --- | --- | --- | --- | --- | --- |
| every `*_plan` | true | false | true | true | none |
| `plan_get`, `plan_list` | true | false | true | false | none |
| `plan_discard` | false | false | true | false | none |
| `plan_apply` | false | true | true | true | `anthropic/requiresUserInteraction: true` |

Reasons:

- A planner changes nothing outside the server process. It may be called in
  parallel and repeated; each call makes a separate plan.
- `plan_apply` is marked destructive because a toggle is an update, not an
  addition, and because that is the value clients prompt on.
- `plan_apply` is idempotent by construction: a second call with the same
  plan id returns the stored outcome ([section 5.5](05-plans.md#55-replay)).
- `plan_get`, `plan_list`, and `plan_discard` touch only process memory.

Annotations describe behavior. Registration, the class gate, and the
confirmation step enforce it.

### Server instructions

0.8 returns static `instructions` whose second sentence is "It never changes
Elastic or local files." That stays true and unchanged when no class is
enabled. When at least one class is enabled, the server returns the same
text with that sentence replaced by:

```text
It changes Elastic only through a stored plan that a person confirms in the client; no tool argument confirms a change. It never changes local files. To change something, call a tool whose name ends in _plan, then plan_apply with the plan id.
```

The result stays one line of ASCII under the 4,096 character limit. It names
no class, host, or object. Which of the two texts a process returns depends
only on whether the startup set is empty.

### Descriptions

Tool descriptions are static project text. Each planner description states,
in this order: what it plans; that it changes nothing; that a plan lasts 15
minutes, lives in this server process only, and is applied with `plan_apply`
after a person confirms in the client. The `plan_apply` description states
that it needs a person's confirmation, that arguments cannot confirm, and that
a client without form elicitation cannot apply. No description repeats target
data, plan data, or text from the stack.
