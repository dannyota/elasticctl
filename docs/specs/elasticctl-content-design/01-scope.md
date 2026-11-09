[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 1. Scope

0.5.0 is the complete data-view surface:

```text
data-views list | get | validate | export | import | delete
data-views default get | set | unset
```

0.5.1 is the complete dashboard surface:

```text
dashboards list | get | validate | export | import | delete
dashboards bundle export | import
```

0.5.2 adds the content conformance contract, runs the cross-flavor matrix, and
ships the bounded review patch. Each release tells one complete story: data
sources, then dashboards, then proof.

The 0.5 area is transfer and administration, not another mirror. It does not
extend `state pull | diff | push`, reconcile a directory, manage Kibana tags or
library visualizations as independent resources, generate dashboards, manage
PDF/PNG reporting, or expose legacy internal dashboard routes.

