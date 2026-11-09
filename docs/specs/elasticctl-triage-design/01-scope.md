[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 1. Scope

0.4.0 is the complete alerts vertical and nothing else:
`alerts list | get | ack | open | close | tag | assign`, including
query-scoped transitions and username-based assignment.

0.4.1 is the complete cases surface in one release:
`cases list | get | create | attach | comment | close | open | delete` and
case assignees. 0.4.2 is the triage conformance contract, the cross-flavor
matrix run, and the bounded review patch.

Each version tells one meaningful story — alerts, then cases, then proven.
0.4.0 is the first independently usable release, and a cases read stub beside
a complete alerts vertical would dilute both.

Out of scope for 0.4 entirely: dashboards and data views (0.5), rule-side
changes of any kind (attaching an exception to a rule stays a `state push`
concern), alert deletion (no public API path worth wrapping), and Timeline or
investigation-guide content.

