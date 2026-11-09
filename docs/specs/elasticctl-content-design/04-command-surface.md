[Back to elasticctl-content-design](../elasticctl-content-design.md)

## 4. Command surface

```text
elasticctl data-views list [--search TEXT]
elasticctl data-views get <id|name>
elasticctl data-views validate --path FILE
elasticctl data-views export [<id|name>...] [--format-file json|yaml]
elasticctl data-views import --path FILE [--overwrite|--skip-existing]       [guarded]
elasticctl data-views delete <id|name>... [--replace-with <id|name>]         [guarded]
elasticctl data-views default get
elasticctl data-views default set <id|name>                                 [guarded]
elasticctl data-views default unset                                         [guarded]

elasticctl dashboards list [--search TEXT] [--tag ID] [--limit N]
elasticctl dashboards get <id|title>
elasticctl dashboards validate --path FILE
elasticctl dashboards export [<id|title>...] [--format-file json|yaml]
elasticctl dashboards import --path FILE [--overwrite|--skip-existing]      [guarded]
elasticctl dashboards delete <id|title>...                                  [guarded]
elasticctl dashboards bundle export [<id|title>...]
elasticctl dashboards bundle import --path FILE [--overwrite]               [guarded]
```

The global `--out` selects an export destination, as it does for rules and
exceptions. Without `--out`, stdout is the artifact verbatim under every
global renderer format. `--format-file` controls only the portable file and
defaults to `json`. Bundle export is always NDJSON and rejects
`--format-file`; bundle import chooses no format from the extension.

An export with no selectors means every object of that type in the active
space. Every selector must resolve. A short export is an error rather than a
successful subset.

Mutating commands reject an empty target before building a transport. Bundle
import rejects a file with no dashboard object. `default unset` is explicit;
an empty argument never means unset.

