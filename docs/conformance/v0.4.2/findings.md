# elasticctl 0.4.2 Conformance Findings

All eight contracts passed on all three targets. 0.4.2 adds the `triage`
contract (alert status by id and by query, tag and untag, assignee resolve
and assign/unassign, and a full case create-attach-comment-close-delete round
trip) to the seven 0.3 contracts, and the matrix proves the triage vertical
behaves identically across Serverless, Hosted, and the self-managed 9.5.1
compatibility floor.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.6.0 | 8 pass | [serverless-9.6.0.json](serverless-9.6.0.json) |
| Elastic Cloud Hosted | 9.5.2 | 8 pass | [ech-9.5.2.json](ech-9.5.2.json) |
| Self-managed | 9.5.1 | 8 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

No contract failed or skipped. Cleanup audits passed after every contract and
the final rule partitions matched each target's captured baseline. Each leg
took roughly four to five minutes of wall clock, the self-managed leg
including its own lab boot, prebuilt install, teardown, and everything in
between; the documented twenty-minute lab boot is a cold-image figure, and
these runs had the container images already pulled.

## Contract residue

The `triage` contract's accepted deviation is closed alert residue: the
public API has no alert delete, so the contract closes every alert its marker
rule produced and baseline verification counts only *open* marker alerts.
After the matrix, Serverless held 9 closed marker alerts and Hosted held 3,
with zero open on either and zero marker rules, marker indices, or marker
cases anywhere. Both cloud targets' prebuilt packs were unchanged at 2,069
rules. The self-managed lab is destroyed with its volumes, so it retains
nothing.

## Two boot-step defects, both fixed before the passing run

Neither failure was in a contract; both were in a leg's own setup, and both
were found by the first live run of code that until then had only been
exercised offline.

**Login provider name.** `POST /internal/security/login` takes a provider's
*configured name*, not its type. Profile activation sent `"basic"`, which a
self-managed stack configures but an Elastic Cloud Hosted deployment does
not — Hosted names its HTTP Basic provider `cloud-basic`. With identical
credentials, `basic` answered `401 Unauthorized` and `cloud-basic` answered
`200`, so the wrong name was indistinguishable from a wrong password.
Activation now reads `GET /internal/security/login_state` and takes the name
of the first `basic`-type provider that uses the login form. That probe also
settled a shape question: the lab reports `selector.enabled: false` while
still listing the provider, so enablement is ignored.

**Prebuilt install convergence.** One
`PUT /api/detection_engine/rules/prepackaged` does not install the whole pack
on a fresh lab. The first call reported `rules_installed: 1963` and left
`rules_not_installed: 106`; a second call installed exactly those 106 in six
seconds and the status then reported the pack current. The self-managed leg
now repeats install-then-status until the status is current, bounded at five
attempts. The earlier symptom would have been a `source_scoping` failure
against an incomplete partition.

Both fixes are pure setup-path changes. No contract, baseline rule,
classifier, or cleanup behavior was touched to make this matrix pass.
