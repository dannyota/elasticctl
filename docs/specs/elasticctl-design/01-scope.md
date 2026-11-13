[Back to elasticctl-design](../elasticctl-design.md)

## 1. Scope

v0.1 delivers the foundation layer and one vertical: **detection rules as
code**.

v0.2 completes that vertical. It adds exception lists as managed objects,
prebuilt rule status and installation, and `--source` scoping for `rules list`,
`rules export`, and the state commands. It also closes section 3's layering
debt by moving all command orchestration into `-api`.

Out of scope (additive later): alert triage, cases, Fleet and agent policies,
ad hoc search, and the MCP server. These are the original 0.1 boundaries;
section 11 lists later capability areas. 0.1 also deferred value-list content.
0.10 manages it as the
[value lists design](../elasticctl-value-lists-design.md) describes.

