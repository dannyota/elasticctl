[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 8. Evidence and release contract

Before 0.7.0 and 0.7.1, run direct MCP reads for every tool shipped in that
version against Serverless, Hosted, and self-managed targets. Use marker-owned
objects prepared by the external test harness; never prepare them through MCP.
Read results stay in ignored private logs. A per-version findings document
records the protocol, client, tool coverage, aggregate outcomes, and cleanup.
Empty results alone do not prove a get/projection path works.

0.7.2 adds the eleventh conformance contract, `mcp_reads_existing_verticals`,
to the existing matrix. The test controller prepares marker rules, exceptions,
alerts/cases, data views, dashboards, and Fleet policies using existing guarded
test patterns, then runs the MCP reads. Any new fixture provisioning or
cleanup code receives adversarial ownership review before live use. It never
mutates prebuilt or unmarked objects. The harness verifies existing baselines,
marker cleanup, exact default data view, and package inventory.

The existing conformance JSON keys stay unchanged. Detailed MCP client and
tool coverage belongs in scrubbed narrative findings. Extend the report
validator for eleven contracts while retaining historical formats. Never
report a skipped or unavailable target as a pass.

The first release publishing all four crates was 0.7.0. They share one version.
Package-content checks and workspace version validation cover all four.
The normal publisher checks that all four
names exist and remain owned by `dannyota` before obtaining a publish token.
Crate ownership does not prove Trusted Publisher configuration; the owner
checks each entry before dispatch. The owner approved a one-time local
exception for the first publication. Future publication follows the normal
workflow and needs explicit approval for that version. Workspace verification
precedes uploads, but registry uploads are not atomic. These publication
prerequisites do not block implementation or nonpublishing gates.
`cargo install elasticctl` still installs `elasticctl` and `elkctl`; no third
binary or new build target is proposed.
Each version runs the exact-commit CI and nonpublishing preflight in
[releasing.md](../../releasing.md). Packaging changes follow that guide's
published-candidate rule if crates.io publishing is requested.
No release, registration, or publishing action is authorized by this plan.

