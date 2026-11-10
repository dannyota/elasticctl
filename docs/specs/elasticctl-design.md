# elasticctl — design

`elasticctl` is a Rust CLI for operating Elastic Security from a security
engineer's laptop. It manages detection rules as code against self-managed
stacks, Elastic Cloud Hosted deployments, and Elastic Cloud Serverless
projects.

It is modelled on [splunkctl](https://github.com/dannyota/splunkctl) and
reuses its operating contracts: named profiles, dry-run-by-default mutations,
structured output, and a stable error taxonomy. The 0.7 read-only MCP server
calls the existing API layer through a separate frontend library. 0.8 adds
cross-vertical task tools, resources, and prompts
([design](elasticctl-mcp-tasks-design.md)). From 0.9 the server can apply a
bounded set of changes after a person confirms each stored plan in the client
([design](elasticctl-mcp-mutation-design.md)).

## Contents

| Section | Page |
|---|---|
| 1. Scope | [Read](elasticctl-design/01-scope.md#1-scope) |
| 2. Decisions | [Read](elasticctl-design/02-decisions.md#2-decisions) |
| 2.1 Why not the alternatives | [Read](elasticctl-design/02-decisions.md#21-why-not-the-alternatives) |
| 3. Architecture | [Read](elasticctl-design/03-architecture.md#3-architecture) |
| 3.1 elasticctl-core | [Read](elasticctl-design/03-architecture.md#31-elasticctl-core) |
| 3.2 elasticctl-api | [Read](elasticctl-design/03-architecture.md#32-elasticctl-api) |
| 3.3 elasticctl-cli | [Read](elasticctl-design/03-architecture.md#33-elasticctl-cli) |
| 3.4 elasticctl-mcp | [Read](elasticctl-design/03-architecture.md#34-elasticctl-mcp) |
| 4. Command surface | [Read](elasticctl-design/04-command-surface.md#4-command-surface) |
| 4.1 Rule identity | [Read](elasticctl-design/04-command-surface.md#41-rule-identity) |
| 4.2 Global flags | [Read](elasticctl-design/04-command-surface.md#42-global-flags) |
| 4.3 Export selection | [Read](elasticctl-design/04-command-surface.md#43-export-selection) |
| 4.4 Import conflict handling | [Read](elasticctl-design/04-command-surface.md#44-import-conflict-handling) |
| 4.5 Exception list identity | [Read](elasticctl-design/04-command-surface.md#45-exception-list-identity) |
| 4.6 Prebuilt rules | [Read](elasticctl-design/04-command-surface.md#46-prebuilt-rules) |
| 4.7 Object search | [Read](elasticctl-design/04-command-surface.md#47-object-search) |
| 5. State engine | [Read](elasticctl-design/05-state-engine.md#5-state-engine) |
| 5.0 Pull path identity and locking | [Read](elasticctl-design/05-state-engine.md#50-pull-path-identity-and-locking) |
| 5.0.1 Report path identity and locking | [Read](elasticctl-design/05-state-engine.md#501-report-path-identity-and-locking) |
| 5.1 Server-applied defaults | [Read](elasticctl-design/05-state-engine.md#51-server-applied-defaults) |
| 5.2 Reading the corpus | [Read](elasticctl-design/05-state-engine.md#52-reading-the-corpus) |
| Partitioned reads above the window | [Read](elasticctl-design/05-state-engine.md#partitioned-reads-above-the-window) |
| 5.3 Scoped state operations | [Read](elasticctl-design/05-state-engine.md#53-scoped-state-operations) |
| 5.4 Exceptions in the mirror | [Read](elasticctl-design/05-state-engine.md#54-exceptions-in-the-mirror) |
| 5.5 Scoping by rule source | [Read](elasticctl-design/05-state-engine.md#55-scoping-by-rule-source) |
| 6. Contracts | [Read](elasticctl-design/06-contracts.md#6-contracts) |
| 6.1 Safety | [Read](elasticctl-design/06-contracts.md#61-safety) |
| 6.2 Output and errors | [Read](elasticctl-design/06-contracts.md#62-output-and-errors) |
| 6.3 Fail-closed boundaries | [Read](elasticctl-design/06-contracts.md#63-fail-closed-boundaries) |
| 7. Verified API facts | [Read](elasticctl-design/07-verified-api-facts.md#7-verified-api-facts) |
| 7.1 Rule schema, measured | [Read](elasticctl-design/07-verified-api-facts.md#71-rule-schema-measured) |
| 7.2 Rule mutation requires a project-scoped API key | [Read](elasticctl-design/07-verified-api-facts.md#72-rule-mutation-requires-a-project-scoped-api-key) |
| 7.3 Targeting rules by rule_id in bulk actions | [Read](elasticctl-design/07-verified-api-facts.md#73-targeting-rules-by-rule_id-in-bulk-actions) |
| 7.4 Two error body shapes | [Read](elasticctl-design/07-verified-api-facts.md#74-two-error-body-shapes) |
| 7.5 Preview results | [Read](elasticctl-design/07-verified-api-facts.md#75-preview-results) |
| 7.6 Elastic Cloud Hosted, measured | [Read](elasticctl-design/07-verified-api-facts.md#76-elastic-cloud-hosted-measured) |
| 7.7 Exceptions, measured | [Read](elasticctl-design/07-verified-api-facts.md#77-exceptions-measured) |
| 7.8 Prebuilt rules, measured | [Read](elasticctl-design/07-verified-api-facts.md#78-prebuilt-rules-measured) |
| 7.9 ES\|QL async query, measured | [Read](elasticctl-design/07-verified-api-facts.md#79-esql-async-query-measured) |
| 8. Testing | [Read](elasticctl-design/08-testing.md#8-testing) |
| 8.1 Sample corpora | [Read](elasticctl-design/08-testing.md#81-sample-corpora) |
| 8.2 CI and release preflight | [Read](elasticctl-design/08-testing.md#82-ci-and-release-preflight) |
| 8.3 Cross-flavor live conformance | [Read](elasticctl-design/08-testing.md#83-cross-flavor-live-conformance) |
| 9. Local lab | [Read](elasticctl-design/09-local-lab.md#9-local-lab) |
| 10. Distribution | [Read](elasticctl-design/10-distribution.md#10-distribution) |
| 11. Versioning | [Read](elasticctl-design/11-versioning.md#11-versioning) |
| 11.1 What counts as breaking | [Read](elasticctl-design/11-versioning.md#111-what-counts-as-breaking) |
| 11.2 Publishing | [Read](elasticctl-design/11-versioning.md#112-publishing) |
| 12. Credentials in this repository | [Read](elasticctl-design/12-credentials-in-this-repository.md#12-credentials-in-this-repository) |
| 13. Risks | [Read](elasticctl-design/13-risks.md#13-risks) |
