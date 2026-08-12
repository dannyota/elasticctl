# elasticctl

**Operate Elastic Security as code with a safety-first CLI for security engineers.**

`elasticctl` is a Rust CLI for managing Elastic Security detection rules as
code, across self-managed stacks, Elastic Cloud Hosted deployments, and Elastic
Cloud Serverless projects.

> **Status: design.** No code yet. The design is in
> [`docs/specs/elasticctl-design.md`](docs/specs/elasticctl-design.md).

It is a sibling to [splunkctl](https://github.com/dannyota/splunkctl) and shares
its operating contracts:

- **Every mutation is a dry run by default.** Nothing changes until you pass
  `--yes`, and every preview names the profile, host, and space it would touch.
- **Configuration as code.** Pull live rules, review structured drift, push
  approved changes with a change-evidence report. Push never deletes remote
  rules.
- **Stable machine output.** Table by default, `--json` on request, typed error
  envelopes on stderr.
- **Named profiles** for separate development, UAT, and production instances.

An MCP server is planned once the CLI surface is stable.

## Planned surface (v0.1)

```
elasticctl config init | list | show | test
elasticctl doctor
elasticctl info

elasticctl rules list | get | validate | enable | disable | delete
elasticctl rules export | import | preview

elasticctl state pull | diff | push

elasticctl completion bash|zsh|fish
```

## Development

Requires a stable Rust toolchain.

```bash
git clone https://github.com/dannyota/elasticctl
cd elasticctl
cp .env.example .env    # fill in your Elastic endpoints and API key
cargo test
```

`.env` is gitignored. Never commit credentials.

## License

Apache-2.0
