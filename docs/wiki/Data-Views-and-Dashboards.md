# Data Views and Dashboards

Move Kibana data views and dashboards between stacks as portable files.

## Data views

```bash
elkctl data-views list --search logs
elkctl data-views get logs-default
elkctl data-views validate --path data-views.yaml
elkctl data-views export logs-default --format-file yaml > data-views.yaml

elkctl data-views import --path data-views.yaml --yes
elkctl data-views default get
elkctl data-views default set logs-default --yes
elkctl data-views default unset --yes
elkctl data-views delete old-logs --replace-with logs-default --yes
```

Data views use stable ids and JSON or YAML files. A selector is an id or an
exact name. Without selectors, `export` writes every data view.

- Legacy scripted fields are not portable. A file carrying them is rejected
  before any request.
- `import` fails on an existing data view unless you pass `--overwrite` or
  `--skip-existing`.
- `delete` refuses a data view that saved objects still reference, or that is
  the current default. `--replace-with` moves the references, and the default
  when it pointed at the deleted view, to another data view, one source view
  per command. Otherwise clear the default first with `default unset`.

## Dashboards

```bash
elkctl dashboards list --search security --tag production
elkctl dashboards get security-overview
elkctl dashboards validate --path dashboards.yaml
elkctl dashboards export security-overview --format-file yaml > dashboards.yaml

elkctl dashboards import --path dashboards.yaml --yes
elkctl dashboards delete retired-overview --yes
```

Dashboards also use stable ids and JSON or YAML files. A selector is an id or
an exact title, and `list --limit` caps the rows. The typed export omits
server metadata and refuses a dashboard that carries loss warnings, so a file
never silently drops content. The typed import checks that referenced data
views exist before it writes, and fails on an existing dashboard unless you
pass `--overwrite` or `--skip-existing`.

### Bundles

Use an opaque Saved Objects bundle when a dashboard must move together with
everything it depends on:

```bash
elkctl dashboards bundle export security-overview > dashboards.ndjson
elkctl dashboards bundle import --path dashboards.ndjson --yes
```

Bundle bytes pass through unchanged, so the server restores the dashboard and
its exported dependencies together. `bundle import --overwrite` replaces saved
objects that already exist.

Dashboards need Kibana 9.5.1 or newer; see [Limitations](Limitations.md).

`import`, `delete`, `default set`, `default unset`, and `bundle import`
preview without `--yes`.
