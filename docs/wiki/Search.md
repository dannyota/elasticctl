# Search

Run ES|QL or Query DSL against Elasticsearch from the terminal. Both commands
only read.

```bash
elkctl search esql 'FROM logs-* | STATS count = COUNT(*) BY host.name | LIMIT 20'
elkctl search dsl '{"query":{"term":{"event.category":"process"}}}' --index 'logs-*'
elkctl search dsl @query.json --data-view security-default --limit 50
```

On Elastic Cloud, `search` needs the Elasticsearch URL in the profile; see
[Configuration](Configuration.md#environment-variables).

## Choosing the source

| Order | ES\|QL | Query DSL |
| --- | --- | --- |
| 1 | `--index` replaces the query's `FROM` | `--index` |
| 2 | `--data-view` resolves a Kibana data view to its index pattern | `--data-view` |
| 3 | The query's own `FROM` | The space's default alerts index |
| 4 | The space's default alerts index | |

So a query with no source searches the detection alerts of the selected space:

```bash
elkctl search esql 'WHERE kibana.alert.severity == "critical" | LIMIT 10'
```

A `dsl` body is inline JSON or `@path` to a file.

## Peek and export

Without `--out`, a search is a peek: at most 100 rows, or `--limit`. ES|QL adds
a server-side `LIMIT` when the query has none, so a large result is not
downloaded and discarded. When rows are cut, stderr says `capped at N rows`.

With `--out`, a search is an export of every row, unless `--limit` caps it:

```bash
elkctl search esql 'FROM logs-* | WHERE event.outcome == "failure"' \
  --out failures.jsonl
elkctl search dsl @query.json --index 'logs-*' --out hits.csv --format csv
```

- ES|QL exports run through the async query API and wait up to five minutes.
- Query DSL exports page through a point in time, sorted by the body's `sort`
  or by shard document order.

`--with-meta` adds `_id`, `_index`, and `_score` to each Query DSL row.

## Access

A Kibana space does not restrict Elasticsearch. `search` reads every index the
credential can read, whatever `--space` says. Limit access with the API key's
privileges.
