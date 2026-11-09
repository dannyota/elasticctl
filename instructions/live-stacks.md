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
- Every object a live test creates carries the `elasticctl-sample` marker: a `rule_id` prefix and
  tag for rules, and `*elasticctl-sample*` in index names. Every remote mutation targets explicit
  ids.
- A run ends by verifying the project is back to baseline: unchanged prebuilt-rule count, no
  sample rules, and no sample indices.
- Fleet packages are the exception: a package a test installs (for example `system` or
  `elastic_agent`) may stay installed. Marker objects are still removed.

## Lab

The `lab/` podman stack is an on-demand session (~3 GB, ~20 minutes) used only to record
self-managed fixtures and run the traditional conformance leg. Do not assume it is running.

- `podman compose` delegates to `docker-compose`; `podman-compose` is not installed.
- Kibana's entrypoint maps only `UPPER_SNAKE` environment variable names. The dotted
  `xpack.encryptedSavedObjects.encryptionKey` form is silently ignored, so every rule creation
  fails.
- `lab/up.sh` prints a disposable API key. Pass it only to the process that needs it.
