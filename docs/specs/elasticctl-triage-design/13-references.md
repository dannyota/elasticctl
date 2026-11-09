[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 13. References

Consulted 2026-09-01:

- Set detection alert status — request one-of (`signal_ids` | `query`),
  `conflicts`, `reason` enum:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertsstatus
- Assign/unassign detection alerts — uids, activation requirement,
  update-by-query response:
  https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertassignees
- Suggest user profiles — paths, schema, `read_security` privilege, GA 8.2,
  "designed only for use by Kibana and Elastic solutions" caveat:
  https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-suggest-user-profiles
- User profiles concept and activation:
  https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/user-profiles
