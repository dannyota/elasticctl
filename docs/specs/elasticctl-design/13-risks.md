[Back to elasticctl-design](../elasticctl-design.md)

## 13. Risks

**Serverless-first bias — resolved.** Serverless is the most divergent of the
three flavors — no license tiers (features gate on project tier instead),
different auth, and some endpoints versioned differently. Developing only
against it risks baking Serverless assumptions into code that claims to support
self-managed. The mitigation is fixture tagging by flavor and version,
capability-gated divergent behavior, and recordings for each flavor.

All three flavors now have 29 fixtures: `serverless-9.6.0`,
`traditional-9.5.1`, and `ech-9.5.1`. Coverage is even, so no flavor is least
tested. Each set records custom and prebuilt `immutable` filters against the
same probe rule and proves their totals sum to the unscoped total. The two
9.5.1 sets therefore establish the rule-source compatibility floor; older
versions remain unsupported until an equally complete recording lowers it.

Both halves of the Hosted signal are now measured, not inferred. Every set
records response headers: `traditional-9.5.1` has headers but lacks
`x-found-handling-cluster`, and the other two include it. The self-managed
recording also closed the last open question about `rules preview`, which had
previously been exercised only against Serverless.

**`rules preview` stability — resolved.** The concern was that the preview
endpoint has moved between public and internal paths across Elastic versions.
Measured on Serverless 9.6.0: `POST /api/detection_engine/rules/preview` is
public and returns 200 with a `previewId` and a `logs` array carrying per
execution `errors` and `warnings`. The internal path returns 404.

`elastic-api-version` must be a date string. `1` and `2` are both rejected
with "Invalid version. Received \"1\", expected a valid date string". Internal
Kibana routes are versioned numerically, which is a second reason they are
unreachable here. `2023-10-31` is the only version this client needs.

The command stays in 0.1.0 and off the trim line. It is now also confirmed on a
self-managed stack: `traditional-9.5.1` carries recorded `rules_preview` and
`rules_preview_hits` fixtures.

**Empty project — resolved.** The serverless development project now holds
2,066 prebuilt Elastic rules covering all seven rule types, seeded for scale
testing. Measured against them, `state pull` writes 2,066 files in ~8.4 s, a
second pull is byte-identical, `state diff` reports zero drift, and export
round-trips every type exactly. They are read-only ground truth. A live test
never mutates an untagged rule; every object it creates carries the
`elasticctl-sample` marker, and a run ends by verifying that the project is
back to that baseline.

**A large retrofit shipped beside two new capability areas — mitigated by
ordering.** 0.2 moves 1,528 lines of orchestration into `-api` in the same
release that adds exceptions and prebuilt rules. The mitigation is sequence and
evidence rather than care: the retrofit lands first as its own wave, and
snapshot tests prove every existing command renders byte-identically before any
0.2 feature is written. If the rest of 0.2 runs long, the retrofit ships alone.

**Fact G — runtime exception identity — resolved.** Measured on Serverless
9.6.0 on 2026-08-15: a matching exception suppressed the test event with both
the live pointer and a zero UUID pointer, producing zero preview hits in each
case. Runtime exception lookup therefore follows `list_id` on the measured
stack; the stored `exceptions_list[].id` is not its runtime discriminator.

`diff` still reports the stale pointer and `push` repairs it, so a mirror
converges on the target stack's current saved-object id. The same serialized
live test deletes the exception container, imports the exported rule bundle,
and proves that import rewrites the upload placeholder to the recreated
container's live id. This behavior needs a rule that fires against a real
stack, so it remains live conformance rather than a recorded response fixture.
