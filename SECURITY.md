# Security policy

## Supported versions

Only the latest release receives security fixes. Upgrade before reporting a
problem you found in an older version.

## Reporting a vulnerability

Report privately through GitHub: open the repository's
[Security tab](https://github.com/dannyota/elasticctl/security) and choose
**Report a vulnerability**, or go straight to the
[private report form](https://github.com/dannyota/elasticctl/security/advisories/new).
Do not open a public issue for a vulnerability.

Include:

- the `elasticctl --version` output and your operating system;
- the deployment flavor and Elastic version, such as Serverless or
  self-managed 9.5.1;
- the command or MCP tool call, and what happened compared with what you
  expected;
- steps to reproduce, with credentials, hostnames, and ids replaced by
  placeholders.

Never post an API key, a password, a stack URL, or a deployment id in a public
issue, pull request, or discussion. If one was exposed, revoke the key first.

The [Security](https://github.com/dannyota/elasticctl/wiki/Security) wiki page
describes the protections the tool provides.
