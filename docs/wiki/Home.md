# elasticctl

Documentation for `elasticctl`, a command-line tool and Model Context Protocol
(MCP) server for operating Elastic Security as code. It works against
self-managed stacks, Elastic Cloud Hosted deployments, and Elastic Cloud
Serverless projects. This is a personal project under the Apache 2.0 license,
not affiliated with Elastic.

Examples run `elkctl`, a short alias for the same binary as `elasticctl`. Every
install method puts both names on `PATH`.

## Start here

- [Getting Started](Getting-Started.md): install, create a profile, and run the
  first commands.
- [Configuration](Configuration.md): profiles, environment variables, spaces,
  and which API key to use.
- [CLI](CLI.md): the command tree, global flags, output formats, errors, and
  exit codes.

## Guides

- [Rules as Code](Rules-as-Code.md): pull rules to a directory, review drift,
  and push approved changes.
- [Rules](Rules.md): list, inspect, validate, enable, export, import, and
  preview detection rules, and manage the prebuilt pack.
- [Exceptions](Exceptions.md): exception lists and their items.
- [Search](Search.md): ES|QL and Query DSL from the terminal.
- [Alerts and Cases](Alerts-and-Cases.md): triage alerts and track
  investigations.
- [Data Views and Dashboards](Data-Views-and-Dashboards.md): portable files and
  Saved Objects bundles.
- [Fleet](Fleet.md): agent policies and integration policies.
- [MCP](MCP.md): serve read-only tools to an MCP client.
- [MCP Mutations](MCP-Mutations.md): let an MCP client change rules, alerts,
  and cases after a person confirms each change.
- [MCP Mutation Kinds](MCP-Mutation-Kinds.md): each mutation class, its tools
  and inputs, and what a second call does not restore.

## Reference

- [Security](Security.md): the dry-run guard, credential handling, and what the
  MCP server can reach.
- [Limitations](Limitations.md): server behaviors the tool cannot change and
  what it does about each.
- [Changelog](https://github.com/dannyota/elasticctl/blob/master/CHANGELOG.md):
  changes by version.
- [Design](https://github.com/dannyota/elasticctl/blob/master/docs/specs/elasticctl-design.md):
  scope, architecture, and measured API behavior.
