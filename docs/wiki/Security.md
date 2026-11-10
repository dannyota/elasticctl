# Security

`elkctl` changes nothing without `--yes`, keeps credentials out of URLs and
logs, and refuses a response it cannot trust. None of these can be turned off.

## Changes

- Every command that changes a stack prints a preview and changes nothing.
  `--yes` applies it. The preview and the apply both print a banner naming the
  profile, host, and space, so neither a person nor a script can mistake which
  stack is about to change. See [Dry run and apply](CLI.md#dry-run-and-apply).
- `state push` never deletes a remote rule or an exception list. A rule
  missing from the directory is not a delete instruction; delete with
  `rules delete` or `exceptions delete`. Items inside a mirrored exception list
  reconcile exactly, including deletes, because a list's item set is written
  in full. See [Rules as Code](Rules-as-Code.md#push).
- The MCP server has no tool that changes the stack; see
  [MCP server](#mcp-server).

## Credentials

- Profiles live in `~/.elasticctl/config.toml`. On Unix-like systems the file
  is written with mode `0600`, and a read warns when group or other can read
  it. Each save writes a temporary file in the same directory and renames it
  over the old one, so a save never truncates the file in place or writes
  through a symlink.
- `config show` prints a profile with its secrets redacted.
- Credentials never go in URLs. A `user:password@` prefix in the Kibana or
  Elasticsearch URL is removed when the URL is resolved, before a profile is
  saved, and before any output names the host. Credentials come only from the
  API key, or from a username and password on a local lab.
- Overriding the Kibana URL alone clears the profile's Elasticsearch URL, so a
  credential is never sent to a host from another deployment. See
  [Resolution order](Configuration.md#resolution-order).
- `--debug` logs each request's method, complete URL, and status, including on
  a timeout or connection error. It never logs a header or a body, so the
  authorization header never appears. Keep credentials out of query strings.
- `doctor` truncates an API key id longer than twelve characters. The secret
  half of a key is never printed.

## Fail-closed decoding

A success-shaped response or a readable local file is not trusted on its shape
alone. Where a value is missing, contradictory, or malformed, `elkctl` fails
instead of treating it as zero, unknown, or empty:

- A bulk action, import, or case status change must return complete,
  consistent counts or ids. Anything else is an `http` error, never "nothing
  happened".
- Export trailers, rule preview hits, and the `doctor` identity check decode
  against their required fields.
- A state directory whose `rules` or `exceptions` root, or a file in either,
  is a symlink is refused, and a lost directory entry fails the read. An
  incomplete mirror cannot start a `state push`.
- An interrupted `state pull` recovers its journal one phase at a time; a
  corrupt record fails without touching the target directory.

The design gives the full rules:
[fail-closed boundaries](https://github.com/dannyota/elasticctl/blob/master/docs/specs/elasticctl-design/06-contracts.md#63-fail-closed-boundaries).

## MCP server

The server reaches only the stack, profile, and space chosen at startup.

It can:

- Read the routes its twenty-four default tools need, including the
  Elasticsearch identity check `stack_doctor` uses and the index pattern
  resolve `rule_readiness` uses, which returns counts only.
- With `--allow-query-tools`, run synchronous ES|QL queries and index searches
  with the selected credential.

It cannot:

- Send a request that changes the stack. It sends no `PUT`, `PATCH`, or
  `DELETE`, and no Fleet setup, rule preview, import, async query, or point in
  time request.
- Change its target. No tool accepts a profile, space, host, URL, credential,
  configuration path, timeout, debug option, or file path.
- Read or write local files. Startup reads only the selected configuration and
  normal TLS trust material; tool calls create no files.
- Follow a redirect, or log requests: its transport has redirects and debug
  logging off.
- Return raw upstream errors. Error messages are fixed text per error kind and
  never include upstream bodies, URLs, or credentials.

A Kibana space does not restrict Elasticsearch index access: the query tools
read every index the credential can read. Returned content is untrusted data;
see [MCP](MCP.md#returned-data-is-untrusted).

## Reporting a vulnerability

Report a security problem privately, as described in
[SECURITY.md](https://github.com/dannyota/elasticctl/blob/master/SECURITY.md).
Never post credentials or stack URLs in a public issue.
