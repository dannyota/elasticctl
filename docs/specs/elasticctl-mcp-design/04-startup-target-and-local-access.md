[Back to elasticctl-mcp-design](../elasticctl-mcp-design.md)

## 4. Startup target and local access

The operator runs:

```bash
elkctl --profile analyst --space default mcp serve
elkctl --profile analyst --space default mcp serve --allow-query-tools
```

The second form is available from 0.7.1. It permits synchronous queries
against the data accessible to that credential, including possible downstream
inference calls. This setting cannot be changed through MCP. Query tools
remain absent and unknown to the router when it is false.

Resolve core config once, using the existing flags/environment/profile
precedence and paired Kibana/Elasticsearch target rules. Credentials come
from the existing profile or process environment. No tool accepts a profile,
space, host, URL, credential, config path, debug option, timeout, or file path.
Changing the process environment or config after startup does not retarget it.

Startup accepts `--config`, `--profile`, `--space`, and `--timeout` through
the normal CLI flags. Timeout defaults to 30 seconds and must be 1-120 seconds
after resolution; reject an out-of-range value. Reject `--yes`, `--out`,
`--fields`, `--json`, explicitly selected `--format`, and `--debug` for serve.
Check explicit flag provenance where a default renderer value is present.

The library validates the resolved target before starting either `serve_io`
or `serve_stdio`; CLI-only validation is insufficient. Validation requires
no credential, transport construction, or network access. Validate both
resolved URL schemes and authorities at startup. Accept only HTTP
or HTTPS with no query or fragment; reject malformed doubled schemes. Preserve
a configured base path. Disable redirects on the MCP transport. Core's
userinfo scrubbing remains in force. The resolved target never comes from
tool data or returned content.

Startup reads only operator-selected configuration and normal TLS trust
material. Tool calls have no local path inputs and create no files. There is
no client-config installer in this release. Documentation shows a placeholder
stdio launch stanza; users register it through their client.

Return target context as `{profile, host, space}` on every tool outcome.
`host` is the scrubbed Kibana authority without path, query, or credentials.
This is operator-visible runtime context, never data for public fixtures or
release reports. Return flavor and version from `stack_info`; other calls
reuse the cached capability probe where needed.

