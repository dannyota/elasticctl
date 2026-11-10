# Limitations

Elastic behaviors `elkctl` cannot change, each with what the tool does about
it.

## Some features need Kibana 9.5.1 or newer

Dashboards, exception lists, Fleet policies, prebuilt rules, and rule source
scoping need Kibana 9.5.1 or newer, the oldest version with complete recorded
evidence. Rule source scoping is any `--source` other than `all`, which
includes the `state` default, `custom`.

Against an older stack, these commands answer `unsupported` before the
feature's first request. The message names the feature, the flavor, the
reported version, and the 9.5.1 floor. Rule commands that read every source
work, and local commands such as `validate` never check the version. In
[MCP](MCP.md), `stack_info` and `stack_doctor` stay usable for diagnosing an
older stack.

## An organization-level Cloud key cannot enable a rule

Enabling a rule makes the alerting framework create a rule API key on behalf of
the caller, and it refuses to do that for an organization-level Elastic Cloud
API key. Such a key can still read, create disabled rules, and delete. The
`essu_` prefix does not tell the key types apart.

`elkctl doctor` reports which realm the key authenticates through:
`_cloud_api_key` means enabling will fail, and `_es_api_key` means it will
work. Use an Elasticsearch API key created inside Kibana; see
[which key to use](Configuration.md#which-api-key-to-use).

## Serverless tags a rule enabled by a project-scoped key

On Serverless 9.7.0, enabling a rule with a project-scoped key appends the tag
`Missing Elastic Cloud API Key` to the rule. The rule still runs. `elkctl`
treats the tag as server-applied state: `state pull` never writes it, `state
diff` does not report it, and `state push` never sends it. A rule cannot keep
this exact tag through the mirror; a rule file that carries it reads as if it
did not. `rules get` and `rules export` omit it as well; `rules list` shows it.

## Rule search cannot reach description or query

The public rules API cannot filter on a rule's description or query; a filter
on either answers 400. `rules list --search` therefore matches a name substring,
ignoring case, or an exact tag. To find text inside a rule's query or
description, pull or export the rules and search the files. See
[Rules](Rules.md#list-and-get).

## Reading more than 10,000 rules

A single rule search returns at most 10,000 results, however it pages.
`rules list` and `state` read a larger corpus as one search per rule type,
split again by enabled state when one type passes the limit, and refuse the
read when the parts do not add up to the total. A part still above the limit
answers `unsupported`; narrow the selection with a filter or a tag.

The server's rule export is capped at 10,000 rules and refuses a larger export
with a 400. Narrow `rules export` with selectors, `--tag`, or `--source`.

## Prebuilt rule install takes no selection

The public install route installs every missing prebuilt rule and updates every
outdated one in one call. It accepts no selection and has no dry-run option.
`rules prebuilt install` computes its preview from the prebuilt status counts
and, with `--yes`, applies the whole pack. There is no per-rule upgrade.

## Rule preview returns no hit count

The preview route reports errors and warnings but not how many events matched.
`rules preview` reads the matches back from the preview alerts index with the
preview's id, and retries once after one second when the first read finds
none. If that read fails, the preview still reports its errors and warnings,
with `hits` null and the failure in `hits_error`.

## Alerts cannot be deleted

The public API has no alert delete. Close alerts with `alerts close` instead.
Cases can be deleted with `cases delete`.

## A Kibana space does not restrict Elasticsearch

Spaces scope Kibana objects: rules, exception lists, data views, dashboards,
alerts, and cases. Elasticsearch index access follows the credential. `search`
and the MCP query tools read every index the API key can read, whatever
`--space` says. Limit access with the key's privileges. See
[Search](Search.md#access).

## Assigning a user needs a Kibana user profile

Alert and case assignees are user profile ids, and a profile exists only after
the user has logged in to Kibana once. An API key identity never has one.

`elkctl` resolves a username to its profile and matches it exactly. No match is
`not_found`, and several matches are `conflict`. On Hosted and self-managed
stacks the lookup uses the Elasticsearch user profile API, which needs the
`read_security` privilege and, on Hosted, the Elasticsearch URL in the profile.
Serverless answers that API with 410, so `elkctl` uses the Security solution's
own route there. When the lookup route is unavailable the command answers
`unsupported`; pass `uid:<profile_uid>` to skip the lookup.

## Kibana deletes a referenced data view

Kibana deletes a data view even while dashboards refer to it, and leaves those
dashboards broken. `data-views delete` refuses a referenced data view unless
`--replace-with` moves its references first. See
[Data Views and Dashboards](Data-Views-and-Dashboards.md#data-views).

## Legacy scripted fields

Serverless drops a data view's legacy scripted fields, while Hosted and
self-managed stacks keep them. Because they do not survive every stack, a
portable data-view file carrying them is rejected before any request.

## Some dashboard content does not round-trip

The typed Dashboards API leaves out content it cannot represent and returns a
warning instead. `dashboards export` refuses a dashboard whose response
carries warnings, names each one, and points to `dashboards bundle export`,
which moves the dashboard as an opaque Saved Objects bundle.

Kibana also accepts a root `time_range.mode` on write but does not store it.
`dashboards import` rejects a file carrying that field before any change.
