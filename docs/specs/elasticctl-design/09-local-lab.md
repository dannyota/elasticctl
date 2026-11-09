[Back to elasticctl-design](../elasticctl-design.md)

## 9. Local lab

The on-demand `lab/` Docker Compose v2 (or Podman Compose) stack runs
Elasticsearch and Kibana 9.5.1 for self-managed recording and traditional
conformance. Ports 9200 and 5601 bind only to 127.0.0.1; Elasticsearch keeps
its 2-GiB heap. Images are tag-pinned, not digest-pinned.

Compose requires `ELASTIC_PASSWORD` and `KIBANA_SYSTEM_PASSWORD` without
fallbacks. `lab/up.sh` generates missing passwords randomly and atomically
writes gitignored `lab/.env` at mode 0600. Existing values are reused;
caller environment values take precedence. Passwords must match
`^[A-Za-z0-9._~-]{16,128}$`; invalid values fail before writing or invoking
Compose. Values are written unquoted. Compose config and startup diagnostics
are captured and replaced with fixed errors. An exclusive `mkdir lab/.up.lock`
covers preparation through key persistence and fails fast if held; EXIT, INT,
and TERM release it. Treat `lab/.env` as Compose data; never print or source it.

`lab/up.sh` waits for readiness, resets the `kibana_system` password, starts
a 30-day trial when needed, bootstraps the signals index, and mints an API key.
An active trial, platinum, or enterprise license skips trial activation. A 403
from activation triggers a license re-read and succeeds only if it now qualifies.
Other trial and signals failures are fatal. It writes `ELASTICCTL_API_KEY`,
`ELASTICCTL_KIBANA_URL`, and `ELASTICCTL_ES_URL` to `lab/.env`, printing only
`wrote lab/.env` instead of credentials. Kibana uses the `UPPER_SNAKE`
encryption settings so the alerting framework can persist rule API keys.

`lab/seed.sh` installs the prebuilt pack. It and the matrix read
`ELASTIC_PASSWORD` from the environment, then `lab/.env`, and fail naming the
variable if absent. The matrix mints its own key and activates a user profile.
Recording uses `ELASTICCTL_USERNAME=elastic` and
`ELASTICCTL_PASSWORD="$ELASTIC_PASSWORD"` after loading the lab password.
`lab/down.sh` removes containers, volumes, and orphans using
`--env-file /dev/null` and harmless interpolation placeholders only for teardown.

`.github/workflows/live-lab.yml` runs only the traditional conformance matrix
on a disposable Ubuntu runner without repository secrets. Concurrency groups use
workflow and ref; only pull requests cancel earlier runs. Two per-run random
passwords are masked before export. Tracing and target-cache saving are off.
The job has a 25-minute timeout; work receives SIGINT by minute 22, followed
by bounded escalation. An independent always-run step tears down Compose with
`--env-file /dev/null` and harmless interpolation placeholders.
Hard termination cannot guarantee teardown. The artifact contains only the
schema-allowlisted public JSON report; exactly eleven named contracts must
pass. Private logs, configs, captures, and environment files are never uploaded.
Cold pulls, package downloads, and alert polling make runner timing unverified;
measure the workflow before making it required CI.

