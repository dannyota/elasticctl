[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 9. Selection and listing

Both list routes are paginated and reject `sortField=id` with 400 `Unknown
sort field id` (measured on Serverless 9.6.0 and Hosted 9.5.2). elasticctl
requests `sortField=created_at&sortOrder=asc` in pages of 1000, collects until
the reported `total`, then sorts by id locally. It fails `http` when page
metadata disagrees with the request, `total` changes between pages, an id
repeats, or a page is short before `total`. This mirrors the dashboard list.
Package-policy lists add `format=simplified`.

`--search` is a local case-insensitive substring match over id and name after
collection. KQL over `id` is not a usable server contract: the package-policy
route answers 400 because `id` is not a saved-object attribute, and the
agent-policy route silently ignores the clause and returns every policy. Name
KQL works but would give `--search` two different semantics, so neither is
used. `--limit` truncates after sorting and the list reports `truncated`.

Resolution tries the exact id with the single-object endpoint first. On
`not_found` it collects the list and keeps exact name matches. Zero matches is
`not_found`; more than one is `conflict`. A name never becomes stored identity.
For read-only integration-policy selection, an exact-id read must return that
requested id. A read selected from an integration-policy list, including exact
name fallback and `--all-custom` export, must return the same id, name,
namespace, parent-id membership, package coordinate, and description as its
selected list row. Parent ids compare as sorted, duplicate-preserving
sequences, so reordering is consistent but a multiplicity change is not hidden.
A mismatch is a malformed `http` response; its error does not include response
values.

Selectors are deduplicated by id. Every selector resolves before export or
delete. The single-object agent-policy read carries populated
`package_policies`, and carries `agents` only when the caller holds the Fleet
agents read privilege, because Kibana populates the count behind that check.
Mutation planning uses both for blast radius and attached integrations. A read
with no `agents` field is `permission` and names the missing privilege; a read
without `package_policies`, or with either field malformed, is `http`.
Ordinary list output does not request compiled full policies.

Integration parent snapshots keep only id, name, namespace, agents, sorted
attached integration ids, platform ownership, and protection. They ignore
agent-policy-only environment and portability fields, but require an existing
integration to appear in every parent named by its `policy_ids`; disagreement
is a malformed `http` response and the attachment list remains a race snapshot.

Agent-policy get returns a sanitized `AgentPolicyDetail`, never the raw Fleet
item. It contains `id`, `name`, `namespace`, `description`, `agents`, `status`,
sorted `attached_integrations` ids, and sorted `blocked_by` field names. The
last list explains why the live policy cannot be exported or mutated without
exposing environment ids, the `agentless` configuration, usernames, or
populated integration objects.

Integration-policy get returns a sanitized `IntegrationPolicyDetail`, never
the raw Fleet item. It contains `id`, `name`, `namespace`, `description`,
sorted `policy_ids`, the exact package coordinate, `affected_agents`, and
sorted `blocked_by`; it never exposes inputs, variable values, secret
references, audit identities, environment ids, or compiled content.

