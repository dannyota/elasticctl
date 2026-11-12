# elasticctl value lists design

Status: designed for 0.10 and approved after review. Not implemented.
Plans: 0.9.4 (on `dev-0.9.4`) and [0.10.0](../plans/v0.10.0.md). The
[research](../plans/v0.10-research.md) records the sources, the live
measurements V1 to V11 on Serverless 9.7.0, Hosted 9.5.6, and the 9.5.1 lab,
and the owner's ten decisions of 2026-11-12.

Value lists are the 0.10 capability area: the content of Elastic Security
value lists, managed as code. An exception entry of type `list` matches an
event field against a value list, so the list's values decide what a rule
suppresses. 0.1 deferred that content as "data rather than configuration"
(shared design 7.7). The content is in fact suppression policy: removing an
address from a list is how a detection is un-suppressed. 0.10 manages it the
way 0.2 manages exception items: a command group and a closure in the state
mirror, reconciled exactly.

This design defers to [`elasticctl-design.md`](elasticctl-design.md) for
architecture, transport, rendering, errors, the guard, fixtures, and release
contracts, and changes none of them except where a section says so.

## Contents

| Section | Page |
|---|---|
| 1. Scope | [Read](elasticctl-value-lists-design/01-scope.md#1-scope) |
| 2. Decisions | [Read](elasticctl-value-lists-design/02-decisions.md#2-decisions) |
| 3. Model, identity, and canonical values | [Read](elasticctl-value-lists-design/03-model-identity-and-values.md#3-model-identity-and-canonical-values) |
| 4. Command surface | [Read](elasticctl-value-lists-design/04-command-surface.md#4-command-surface) |
| 5. Validation | [Read](elasticctl-value-lists-design/05-validation.md#5-validation) |
| 6. Writes, read-back, and outcomes | [Read](elasticctl-value-lists-design/06-writes-and-read-back.md#6-writes-read-back-and-outcomes) |
| 7. State engine | [Read](elasticctl-value-lists-design/07-state-engine.md#7-state-engine) |
| 8. Architecture | [Read](elasticctl-value-lists-design/08-architecture.md#8-architecture) |
| 9. Testing and conformance | [Read](elasticctl-value-lists-design/09-testing-and-conformance.md#9-testing-and-conformance) |
| 10. Version placement | [Read](elasticctl-value-lists-design/10-version-placement.md#10-version-placement) |
