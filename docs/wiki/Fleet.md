# Fleet

Manage Fleet agent policies and integration policies as portable files.

## Agent policies

```bash
elkctl fleet agent-policies list --search linux
elkctl fleet agent-policies get production-linux
elkctl fleet agent-policies validate --path agent-policies.yaml
elkctl fleet agent-policies export --all-custom --format-file yaml > agent-policies.yaml

elkctl fleet agent-policies import --path agent-policies.yaml --yes
elkctl fleet agent-policies delete retired-linux --yes
```

`delete` removes only a policy that has no agents and no integrations.

## Integration policies

```bash
elkctl fleet integration-policies list --search system
elkctl fleet integration-policies get production-system
elkctl fleet integration-policies validate --path integration-policies.yaml
elkctl fleet integration-policies export --all-custom --format-file yaml > integration-policies.yaml

elkctl fleet integration-policies import --path integration-policies.yaml --yes
elkctl fleet integration-policies delete retired-system --yes
```

An exported integration policy keeps the complete simplified input map, which
an exact round trip needs. A create or replacement whose package declares
inputs rejects `inputs: {}`: export the live policy instead of replacing that
map with an empty object.

## Shared behavior

- A selector is an id or an exact name. `export` takes selectors or
  `--all-custom`, which exports every policy that is not platform-owned.
- `list --search` matches a substring of the id and name, ignoring case.
  `--limit` caps the rows after sorting by id.
- Files are JSON by default; `--format-file yaml` writes YAML.
- `import` fails on an existing policy unless you pass `--overwrite` or
  `--skip-existing`.
- `import` and `delete` preview without `--yes`.

Fleet policies need Kibana 9.5.1 or newer; see [Limitations](Limitations.md).
