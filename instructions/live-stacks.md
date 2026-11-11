# Live stacks, credentials, and the lab

## Credentials

`.env` holds live credentials for the development stacks. It is gitignored and mode `0600`;
`.env.example` is the placeholder-only template and lists every variable the tools read.

- Never commit `.env`, copy its contents into tracked files, or echo a key into output, logs, or
  commits. Write a new key straight into `.env`; never print it to read it back.
- A worktree has no `.env`. Source the main checkout's file instead of copying it.
- An **organization-level** Cloud API key is not enough. Every key type carries the `essu_`
  prefix, so the prefix does not indicate scope. Only `GET /_security/_authenticate` (or
  `elasticctl doctor`) reports the realm. An organization key can read and create *disabled*
  rules, but **cannot enable a rule**: the alerting framework refuses to mint a rule API key on
  its behalf. Enable, disable-apply, and `state push` need a **project-scoped Elasticsearch API
  key** created inside Kibana.
- Recording reads the generic `ELASTICCTL_*` target and `ELASTICCTL_FIXTURE_FLAVOR`. Map the
  `ELASTICCTL_ECH_*` target to those generic names for the recorder; `.env.example` shows how.
  `cargo xtask conformance-matrix` reads the `ELASTICCTL_ECH_*` names itself.

## Trial stacks

Live systems are trial Serverless and Hosted test deployments. Never expose their URLs, IDs,
credentials, or identifying data. Trial end dates live with the owner, not in this repo.

- If `.env` is missing, a host does not resolve, or the Cloud edge answers `Unknown resource.`,
  the project is suspended or the trial ended. Stop and tell the owner. Provision a replacement
  only when the owner asks.
- Keep the Hosted deployment running. Do not stop, suspend, or tear it down: a stopped deployment
  changes its endpoints on restart and invalidates `.env`.

## Live testing

Serverless is the primary target; nothing needs to run locally day to day. Live testing against the trial stacks is always permitted:
probe them read-only or run a marker-scoped mutation without asking first. The marker and
baseline rules still apply.

- The Serverless project holds Elastic prebuilt rules for scale testing. `cargo xtask seed`
  installs or updates the prebuilt pack until its status reports current. They are read-only ground truth: never mutate an
  untagged rule.
- Every object a live contract creates carries the live marker: the `elasticctl-live-` prefix on `rule_id`s, ids, and index names, and the `elasticctl-live-marker` tag. The baseline audit checks for that marker. The fixture recorder, the corpus fill, and sample data use the `elasticctl-sample` marker instead. Every remote mutation targets explicit ids, and a cleanup deletes a rule by its exact `rule_id`, never by name.
- A run ends by verifying the project is back to baseline: unchanged prebuilt-rule count, no
  sample rules, and no sample indices.
- Fleet packages are the exception: a package a test installs (for example `system` or
  `elastic_agent`) may stay installed. Marker objects are still removed.

## Lab

The on-demand `lab/` stack supports Docker Compose v2 first, then Podman Compose.
It records self-managed fixtures and runs traditional conformance; do not assume it is running.
`live-lab.yml` runs the self-managed matrix in CI, so a release does not start the lab on a
workstation for it. Model-driven clients run against the Hosted test deployment, not the lab
([design 9.3](../docs/specs/elasticctl-mcp-mutation-design/09-testing-and-evidence.md#93-real-clients)).
Start it locally only to record self-managed fixtures, or for a contract that `live-lab.yml`
does not run yet, such as the 0.9 mutation contract.

- `lab/up.sh` generates missing `ELASTIC_PASSWORD` and `KIBANA_SYSTEM_PASSWORD`
  and atomically stores them in gitignored `lab/.env` at mode 0600. Existing
  values are reused; caller environment values win. Keep values single-line.
- `lab/up.sh` writes its API key and localhost URLs to `lab/.env`; it prints only
  `wrote lab/.env`. Treat it as Compose data; never print or source it.
- `lab/seed.sh` and the matrix read `ELASTIC_PASSWORD` from the environment first,
  then `lab/.env`. Recording needs `ELASTICCTL_USERNAME=elastic` and
  `ELASTICCTL_PASSWORD="$ELASTIC_PASSWORD"` after loading the lab password.
- Trial-license and signals-index bootstrap failures stop startup. Kibana needs
  the `UPPER_SNAKE` encryption settings; dotted names are ignored by its entrypoint.
- Ports bind to 127.0.0.1. `lab/down.sh` removes volumes and orphans.
- `live-lab.yml` runs the traditional matrix with per-run masked passwords, no
  repository secrets, and only a validated public report artifact. Private logs
  and `lab/.env` stay on the disposable runner. Runner timings remain unverified.
