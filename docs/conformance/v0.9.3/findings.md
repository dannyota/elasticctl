# elasticctl 0.9.3 conformance findings

All thirteen contracts passed on all three targets. This was the first live
run with the API key passed to each contract child only through its
environment (0.9.3 Task 3), and with the test-only plan-life seam in the
server (Task 2). No contract changed.

| Flavor | Version | Result | Report |
| --- | --- | --- | --- |
| Serverless | 9.7.0 | 13 pass | [serverless-9.7.0.json](serverless-9.7.0.json) |
| Elastic Cloud Hosted | 9.5.6 | 13 pass | [ech-9.5.6.json](ech-9.5.6.json) |
| Self-managed | 9.5.1 | 13 pass | [traditional-9.5.1.json](traditional-9.5.1.json) |

Every leg ran at source commit `ced578fce122a8c66932c3d2d782dcb5cbcdd18a`.
The two Cloud legs ran in one matrix process from `2026-11-12T08:47:14Z` to
`09:13:06Z`. The read-only preflight just before found both answering
`doctor`, with 2,263 prebuilt rules and no marker rule. The self-managed leg
is the `traditional` job of Live lab run 43185388154 on `dev-0.9.3` (mutation
design D35). Its matrix step ran from `08:46:31Z` to `08:57:30Z`, 659 seconds
of the job's 22-minute budget, and the teardown step succeeded. The published
report is byte-identical to the run's `live-lab-public` artifact.

## Offline tests

- `mutation_conformance` passed fourteen tests three runs in a row, including
  the new end-to-end expiry case: a one-second plan ends, `plan_apply` is
  `plan_expired`, nothing is written, and the audit sink gets exactly
  `plan_created` then `plan_closed` with `state: "expired"`.
- `detection_coverage_tool` passed thirteen tests ten runs in a row with the
  gated permit check. A temporary change that held a fourth call made the
  check fail with `busy`, so it cannot pass on a leaked permit.
- The live harness's offline tests show that the written config has no
  `api_key`, and that each live child carries the key in its environment and
  in no argument.

## Cleanup and evidence limits

Every contract and end-of-leg audit passed, and no marker object remained
apart from closed marker alerts. The CI lab was destroyed with its runner.

- No live request capture is claimed; raw results stay in private ignored
  logs.
- The harness answer in the mutation contract is test consent.
