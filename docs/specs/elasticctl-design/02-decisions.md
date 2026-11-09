[Back to elasticctl-design](../elasticctl-design.md)

## 2. Decisions

| Decision | Choice | Reason |
|---|---|---|
| Language | Rust 2024, stable toolchain | Single static binary per platform, no runtime for the user to install |
| Deployment targets | Self-managed, Elastic Cloud Hosted, Serverless | Security engineers use all three |
| Flavor handling | Runtime capability probe | ~90% of the detection-rules API is identical across flavors; auth, headers, and feature availability differ |
| First vertical | Detection rules as code | Highest daily value for detection engineers; the API is stable across all three flavors |
| On-disk rule format | NDJSON **and** YAML | NDJSON round-trips Kibana's export/import exactly; YAML is what a human reviews |
| Credentials | Config file at `0600` | Portable across Linux, macOS, WSL, headless, and CI; no keyring dependency |
| Testing | Recorded fixtures plus opt-in live suite | Fixtures record Elastic's actual exchanges |
| Primary dev target | Serverless project | No local stack is needed; the local lab is an occasional recording environment |

### 2.1 Why not the alternatives

**Trait-per-flavor** (`SelfManaged` / `Ech` / `Serverless` behind a trait) was
rejected. The flavors barely diverge on the detection-rules API, which would
create three near-identical implementations to maintain.

**A single flat crate** mirroring splunkctl's layout was rejected because
nothing structurally prevents `clap` types leaking into command logic. That
leak makes a later MCP addition expensive.

**TOML one-file-per-rule** (Elastic's own `detection-rules` convention) was
considered and set aside in favor of NDJSON for round-trip fidelity, with
YAML covering human review.

