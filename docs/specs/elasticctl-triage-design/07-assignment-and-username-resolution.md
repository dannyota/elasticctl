[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 7. Assignment and username resolution

The assignees routes take user profile uids, not usernames, and a uid only
exists after its user has *activated* a profile by logging into Kibana at
least once. Usernames are required on the CLI, so elasticctl resolves them.

Resolution is flavor-dependent (measured, section 10):

- **Hosted and self-managed** — the public Elasticsearch suggest API,
  `POST /_security/profile/_suggest` with `{name, size}`, GA since 8.2,
  requiring the `read_security` cluster privilege. Response:
  `{total, took, profiles: [{uid, user: {username, realm_name, roles, …}}]}`.
  Measured working on Hosted 9.5.1.
- **Serverless** — the public route answers 410 `api_not_available_exception`.
  The working path is the Security solution's own suggestion route,
  `GET /internal/detection_engine/users/_find?searchTerm=…`, which requires
  the `x-elastic-internal-origin: Kibana` header (400 "exists but is not
  available" without it) and returns `[{uid, user, data, enabled}]`. This is
  the route the Security UI itself uses for the assignee picker.

The capability probe already knows the flavor; `alerts assign` and `--assignee`
pick the route accordingly. The internal-route dependency is recorded in the
risks section of the spec: it is outside Elastic's compatibility contract, so
the conformance contract exercises it every release and a breakage downgrades
cleanly (below) rather than corrupting anything.

Client-side matching, mirroring rule-name resolution (section 4.1 of the main
spec): the suggestion list is matched **exactly** on `user.username`.

Failure modes, each a typed error:

- **No profile.** Username yields no exact match → `not_found`, with the
  remediation in the message: the user must have logged into Kibana at least
  once to activate a profile, and an API-key identity never has one.
- **Ambiguous.** Two or more profiles match exactly (multi-realm) →
  `conflict`, listing username and realm of each candidate, never picking one.
- **Suggest route unavailable.** 410/404/permission failure on the resolution
  route, or a 400 whose message says "is not available" (the internal
  route's own refusal shape described above, message-scoped so an unrelated
  400 still surfaces as `http`) → `unsupported`, naming the flavor and the
  remedy: pass `uid:<profile_uid>` to bypass resolution. On the public
  route, a profile with no `es_url` configured also names that as the likely
  cause — without it, the request silently went to the Kibana host instead
  of Elasticsearch. The `uid:` prefix always works and is the escape hatch,
  not the primary interface.

Case assignees (0.4.1) take the same uids in `assignees: [{uid}]` and reuse
the same resolver.

