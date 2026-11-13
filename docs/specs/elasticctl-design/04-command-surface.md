[Back to elasticctl-design](../elasticctl-design.md)

## 4. Command surface

Lines marked `0.2` or `0.10` are added in that release; everything else ships
in v0.1.

```
elasticctl config init --from-env            Create a profile from ELASTICCTL_* vars
elasticctl config list | show | test         Inspect profiles; secrets always redacted
elasticctl doctor                            Configuration, connectivity, flavor, auth, key scope, rule access
elasticctl info                              Stack version, flavor, license tier, spaces

elasticctl rules list                        --enabled/--disabled --type --severity --tag --filter --search --source
elasticctl rules get <name|rule_id>
elasticctl rules validate --path FILE        Local schema check, no server contact
elasticctl rules enable  <name|rule_id>...   [guarded]
elasticctl rules disable <name|rule_id>...   [guarded]
elasticctl rules delete  <name|rule_id>...   [guarded]
elasticctl rules export [<name|rule_id>...] [--tag TAG] [--source S] [--out FILE] [--format-file ndjson|yaml]
elasticctl rules import --path FILE [--overwrite | --skip-existing]  [guarded]
elasticctl rules preview <file|name|rule_id> [--invocations N] [--sample N]
elasticctl rules prebuilt status             Installed, missing, outdated, customized             0.2
elasticctl rules prebuilt install            Install missing and update outdated  [guarded]       0.2

elasticctl exceptions list                   --type --tag --namespace --search                    0.2
elasticctl exceptions get <list_id> [--namespace single|agnostic]                                 0.2
elasticctl exceptions validate --path FILE   Local schema check, no server contact                0.2
elasticctl exceptions export [<list_id>...] [--tag TAG] [--namespace NS] [--format-file ndjson]   0.2
elasticctl exceptions import --path FILE [--overwrite | --skip-existing]  [guarded]               0.2
elasticctl exceptions delete <list_id>... [--namespace single|agnostic]   [guarded]               0.2

elasticctl value-lists list [--type T] [--search TEXT]                                            0.10
elasticctl value-lists get <id> [--values]                                                        0.10
elasticctl value-lists validate --path FILE  Local check, no server contact                       0.10
elasticctl value-lists export <id>... [--dir DIR]                                                 0.10
elasticctl value-lists import --path FILE [--overwrite]   [guarded]                               0.10
elasticctl value-lists delete <id>...        [guarded]                                            0.10
elasticctl value-lists init                  Bootstrap the space's list data streams  [guarded]   0.10

elasticctl state pull [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/ [--format-file ndjson|yaml]
elasticctl state diff [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/  Field-level structured drift
elasticctl state push [<name|rule_id>...] [--tag TAG] [--search TEXT] [--source S] --dir config/ [--report FILE]  [guarded]

elasticctl completion bash|elvish|fish|powershell|zsh
elasticctl commands                          Machine-readable command tree
```

`exceptions` has no `create` verb: authoring is `import --path` or `state
push`, and a flag surface for arbitrary nested `entries` would be worse than a
file. It has no `attach`/`detach` either, because attaching a list to a rule is
a rule mutation and `state push` is how rule mutations are made.

`value-lists` has no `create` or `add` verb either: authoring is a container
file and a values file, written by `import` or `state push`. The
[value lists design](../elasticctl-value-lists-design/04-command-surface.md#4-command-surface)
gives each command's reads, preview, and output.

`doctor` is most useful when the configuration is broken, so it never stops
at `Context::build`: it reports the failure as a `config` check with status
`fail` and skips the checks that need a resolved, credentialed target. A
failed transport is a `connectivity` failure, and reporting continues. A
permissive config file mode is a `config_permissions` check with status
`warn` in the report, not a stderr warning. Each check is `ok`, `warn`, or
`fail`; only `fail` makes the report's `ok` false.

### 4.1 Rule identity

Engineers think in names; the API has `rule_id` (a stable UUID) and `id` (a
volatile saved-object id). Commands accept either a name or a `rule_id`. A
`rule_id` is tried first. A name lookup occurs only when it misses with a 404;
any other failure, such as a 401, is returned unchanged. The lookup
is a **single `_find` filtered server-side on `alert.attributes.name`**, never
a walk of the whole space. Walking took 8.8 seconds against 2,066 rules just
to report no match.

Candidates are matched exactly client-side. A name never resolves by prefix or
substring. A non-unique name returns a typed `conflict` error listing the
candidates instead of silently picking the first match. The candidate page is
capped at 100. If a name has more candidates than that and no exact match, the
command reports that the search was capped. It does not claim that the name is
absent. A selector matching neither an id nor a name is reported as `No rule
with rule_id or name '...'`, because reporting a missed `rule_id` as a missed
*name* misdirects the operator.

State matching is **always** by `rule_id` — never by name, never by `id`.

### 4.2 Global flags

Accepted before or after the subcommand: `--profile`, `--config`, `--space`,
`--json`, `--format`, `--fields`, `--out`, `--yes`/`-y`, `--timeout`,
`--debug`.

### 4.3 Export selection

`rules export` takes the same positional selectors as `enable`, `disable`, and
`delete` — a name or a `rule_id`, resolved the same way — and a `--tag` filter.
Given both, the union is exported. Given neither, the whole space is exported.
This historical behavior remains the default.

Selection is turned into the scoped export body `{"objects": [{"rule_id": ...}]}`
rather than filtered client-side, so a subset export transfers only the subset.

A selection resolving to no rules is refused with `not_found` naming the
selector. It is never widened to "export everything." Treating an empty
selection as "all" has the same failure mode as an unscoped bulk action. A
`--tag` that matches no rules is refused the same way, naming the tag, even
when a selector resolves. Otherwise, a mistyped tag disappears into the union
and the command reports a short export as a success.

A rule deleted between selection and export comes back in the export trailer's
`missing_rules`. Those ids are reported as failures, so the command exits 1
rather than reporting a short export as a success.

### 4.4 Import conflict handling

Re-importing an existing rule returns a per-rule 409 and exit 1. It does not
skip the rule. Two mutually exclusive flags resolve the conflict because they
give opposite answers to the same question:

- `--overwrite` replaces the existing rule.
- `--skip-existing` leaves it alone and reports it as skipped.

`--skip-existing` asks the server which of the file's `rule_id`s already exist,
in chunks, before the guard runs. That is what makes the dry run honest: the
preview names what would be created and what would be skipped, instead of
listing every rule in the file as if it would import. Skipped rules are removed
from the uploaded NDJSON and never affect the exit code — a rule the server was
never asked to change is not a failure.

The default is unchanged: without either flag, a conflict is a reported failure.

A dry run of `rules import` or `exceptions import` without `--skip-existing`
reads only the file, so it needs no credential. A missing file is reported
before a missing credential.

`rules export` writes the rules with the exception containers and items they
reference in one NDJSON bundle, and `rules import` keeps all three so Kibana
can recreate the containers. The upload carries only the containers and items
that a rule scheduled for upload references: `rules import` is guarded as a
rule mutation, so an exception-only or unreferenced object never becomes an
unpreviewed write. Each readable reference gets a placeholder `id`, because
Kibana validates the pointer as a string before it re-resolves it against the
target. Both `rules import` and `exceptions import` re-encode the planned
objects without the export trailer, so trailer counts never describe a skipped
object.

### 4.5 Exception list identity

Identity is `list_id` plus `namespace_type`, never the saved-object `id`. The
rule that governs rules governs lists, and here the API forces the point by
disagreeing with itself. Measured 2026-08-14 against Serverless 9.6.0:

| Path | Matches a list by |
|---|---|
| `POST /api/detection_engine/rules` | `id` — required, and any UUID is accepted unvalidated |
| `POST .../rules/_export` | `list_id` — exported the correct list despite a zeroed `id` |
| `POST .../rules/_import` | `list_id` — recreated the list and rewrote the rule's `id` to match |

A rule's `exceptions_list[].id` is therefore a required pointer that two of the
three paths ignore and nothing validates. A rule created with
`"id": "00000000-0000-0000-0000-000000000000"` alongside a live `list_id` is
accepted with a 200 and stores the dangling pointer.

`normalize` strips it, so it can never surface as drift, and `push` resolves
`list_id` against the target stack and injects the current `id`. Nothing else
is safe: omitting the field is a 400, and carrying a pulled stack's `id` to
another stack writes a pointer to an object that does not exist there. That is
the dev-to-prod promotion this tool exists for.

Because the server does not catch a dangling pointer, `diff` does. A rule whose
stored `id` does not match the live container for its `list_id` is reported,
and `push` repairs it.

`namespace_type` is part of identity because `single` and `agnostic` are
separate namespaces in which the same `list_id` may exist independently.

That independence has a consequence for the command surface. A bare `list_id`
is not a selector when the same one exists in both namespaces, so `get`,
`export`, and `delete` each take `--namespace` to qualify it. Without the flag
they refuse such a `list_id` with `conflict` rather than picking a side, and the
error names `--namespace` as the remedy. Read commands default to enumerating
both namespaces and merging, ordered by `(namespace_type, list_id)`: the route's
own default is `single`, so a client that simply omits the parameter would show
an operator a partial list and call it complete.

### 4.6 Prebuilt rules

`rules prebuilt status` reports installed, missing, outdated, and customized
counts. The first three come from
`GET /api/detection_engine/rules/prepackaged/_status`. The fourth costs one
extra `_find` and is the reason the command earns its place: a prebuilt rule
edited in the Kibana UI is invisible to a custom-scoped mirror, and an
unrecorded edit to a detection is exactly what a detection engineer needs to
see.

`rules prebuilt install` installs every missing prebuilt rule and updates every
outdated one. It is one verb because the route is one call:
`PUT /api/detection_engine/rules/prepackaged` does both indivisibly and takes
no selection. There is no per-rule prebuilt upgrade in this tool. The route
offering one is `access: 'internal'`, and its sibling `status` route answers
400 on Serverless 9.6.0 — the same ground on which section 5.2 rejects the
internal search route.

The preview is computed from `_status` rather than from a server dry run,
because this route takes no `dry_run` parameter. It is the only guarded path in
the tool whose preview is client-computed, and the banner names both counts.

### 4.7 Object search

`rules list` gains `--search`, a friendly query over the public `_find` filter
fields. Measured 2026-08-16, that filter reaches `name`, `tags`, `type`,
`enabled`, `ruleId`, `severity`, and the source fields, but **not** `description`
or `query`: either returns 400 (`This key 'alert.attributes.description' … does
NOT exist in alert saved object index patterns`). `--search <text>` therefore
narrows to name substring plus tags:

```
(alert.attributes.name: "*<text>*" OR alert.attributes.tags: "<text>")
```

The parenthesized clause is ANDed with the structured filters, so `--search`
never widens a scoped `_find` past its other clauses. Name is substring-matched
by a quoted wildcard term and matches case-insensitively (measured 2026-08-16
against Serverless 9.6.0: `--search "PowerShell"` and `--search "powershell"`
return the same rules); tags are exact, as in `--tag`, and case-sensitive. The
quotes are
load-bearing: measured 2026-08-16, an unquoted `name: *a b*` matches names
containing both words in any order (a token AND), while the quoted `name: "*a
b*"` matches only the contiguous substring. It is sugar over the same filter as
`--filter` (raw KQL, unchanged); the two are mutually exclusive. `exceptions
list` gains name-substring search through the same flag, over
`exception-list.attributes.name` (or its `-agnostic` counterpart). `--search`
widens list discovery only. Selector resolution stays exact (§4.1), and `state`
gains the flag through §5.3. The internal `_search` route is not used (§5.2).

