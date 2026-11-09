[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 1. Scope

0.6.0 is the complete agent-policy surface:

```text
fleet agent-policies list | get | validate | export | import | delete
```

0.6.1 is the complete integration-policy surface:

```text
fleet integration-policies list | get | validate | export | import | delete
```

0.6.2 adds the Fleet conformance contract, runs the cross-flavor matrix, and
ships the bounded review patch. Each release tells one complete story: agent
configuration, attached integrations, then proof.

The 0.6 area administers and transfers policy definitions. It does not:

- extend `state pull | diff | push`;
- reconcile a directory or delete policies omitted from a file;
- assign, enroll, unenroll, upgrade, migrate, or diagnose agents;
- create or revoke enrollment API keys, service tokens, or uninstall tokens;
- manage Fleet outputs, Fleet Server hosts, proxies, download sources, cloud
  connectors, or agentless deployments;
- upgrade, downgrade, or uninstall integration packages;
- expose the compiled policy sent to an agent; or
- manage package assets independently of an integration-policy import.

Enrollment-key creation is deferred because its response carries an enrollment
secret. Outputs and hosts are environment infrastructure rather than portable
policy content.

