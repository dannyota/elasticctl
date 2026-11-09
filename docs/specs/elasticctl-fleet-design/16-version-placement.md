[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 16. Version placement

| Version | Fleet content |
|---|---|
| 0.6.0 | Complete agent-policy administration and transfer |
| 0.6.1 | Complete integration-policy administration and exact package checks |
| 0.6.2 | Fleet conformance matrix and bounded review patch |

The release target list is unchanged from 0.5.2, whose asset set is complete.
0.6.x needs no release candidate unless packaging or targets change. A release
does not publish to crates.io without explicit approval for that exact version.

