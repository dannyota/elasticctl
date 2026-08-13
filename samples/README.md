# Sample corpora

Rules and events for exercising `elasticctl` against real content. The scripts
fetch them on demand into gitignored `samples/out/`; the repository commits
none of it.

Requires `curl`, `unzip`, `git`, `python3`, and — for the rule slice —
`sigma-cli` with the Elasticsearch backend:

```bash
pip install sigma-cli
sigma plugin install elasticsearch
```

## Rules: SigmaHQ/sigma

```bash
./samples/fetch-sigma.sh
python3 samples/prepare_rules.py samples/out/sigma-slice.ndjson \
    > samples/out/sample-rules.ndjson
elasticctl rules import --path samples/out/sample-rules.ndjson --yes
```

`fetch-sigma.sh` shallow-clones the repository and converts a slice with
`sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson --skip-unsupported`.
`-t lucene` targets Lucene query syntax, `-p ecs_windows` maps Sigma fields to
ECS, and `-f siem_rule_ndjson` emits one detection-engine object per line. All
40 Windows `process_creation` rules in the verified slice converted with zero
failures.

`prepare_rules.py` gives every rule the `elasticctl-sample` marker: a `rule_id`
prefix, a tag, `enabled: false`, and the sample data stream as its index. A run
can then find and remove everything it created and cannot touch an untagged
rule.

**License — Detection Rule License 1.1.** Redistributing a Sigma rule, modified
or not, must retain the rule's `author` field, a link to the rule set, and the
license text or a link to it; displaying matches must show the `author`. The
converter carries `author`, `references`, and `license: DRL` into each
generated rule, and `prepare_rules.py` leaves all three alone. Rule set:
<https://github.com/SigmaHQ/sigma>. License:
<https://github.com/SigmaHQ/Detection-Rule-License>.

**If `github.com` is blocked** — some corporate egress proxies intercept it
while allowing `raw.githubusercontent.com` — clone from the GitLab mirror:

```bash
git clone --depth 1 https://gitlab.com/SigmaHQ/sigma.git samples/out/sigma
```

Individual rules are also reachable at
`https://gitlab.com/SigmaHQ/sigma/-/raw/master/<path>`.

**If `sigma convert` fails with a `RuntimeError` and no output**, it could not
download MITRE ATT&CK STIX data while finalising `siem_rule_ndjson`. Supply it
locally:

```bash
curl -fSL -o /tmp/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
cat > /tmp/sitecustomize.py <<'PY'
import sigma.data.mitre_attack as m
m.set_url("/tmp/enterprise-attack.json")
PY
PYTHONPATH=/tmp ./samples/fetch-sigma.sh
```

## Events: OTRF/Security-Datasets

```bash
./samples/fetch-events.sh

curl -fSL -X PUT "$ELASTICCTL_ES_URL/_index_template/elasticctl-sample" \
  -H "Authorization: ApiKey $ELASTICCTL_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @samples/index-template.json

python3 samples/remap_to_ecs.py samples/out/events/*.json > samples/out/bulk.ndjson
curl -fSL -X POST "$ELASTICCTL_ES_URL/_bulk" \
  -H "Authorization: ApiKey $ELASTICCTL_API_KEY" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @samples/out/bulk.ndjson
```

Three datasets are fetched: `empire_mimikatz_extract_keys` (credential access,
44 MB unzipped), `empire_psremoting_stager` (lateral movement, 6.8 MB), and
`empire_launcher_vbs` (execution, 5.6 MB) — 18,010 events in total.

For any rule to match, `remap_to_ecs.py` must:

- Rename the legacy Winlogbeat fields to ECS: `EventID` to `event.code`,
  `CommandLine` to `process.command_line`, `Image` to `process.executable`,
  `ParentImage` to `process.parent.executable`, `SourceName` to
  `event.provider`, `Hostname` to `host.name`. Sysmon 1 and Security 4688 also
  get `event.category: ["process"]` and `event.type: ["start"]`.
- Rewrite `@timestamp` into the last ~150 seconds. The source events are years
  old, but rules look back only minutes.

It also **drops** the source `host` field. That field is a scalar string, but
ECS maps `host` as an object. Leaving it in fails every document with `object
mapping for [host] ... found a concrete value` — all 18,010 in the measured
run.

**License — MIT, © 2021 Open Threat Research Forge**, per the repository's
`LICENSE` file. Its README also carries a `GPL-3.0` line and badge; that line
is stale and points at the predecessor repository
`Cyb3rWard0g/Security-Datasets`. The `LICENSE` file is the operative one.
Source: <https://github.com/OTRF/Security-Datasets>.

## Checking it worked

```bash
elasticctl rules preview elasticctl-sample-<slug> --json --sample 3
```

Measured against this corpus: a WinRM remote-PowerShell rule matched 302
events, an Empire launcher rule matched 4, and two rules correctly matched
nothing.

A converted `process_creation` rule cannot match a PowerShell-channel dataset.
`empire_mimikatz_extract_keys` carries its mimikatz strings in EventID 800 and
4103 script-block text, not in `CommandLine`. A rule querying
`process.command_line` therefore matches zero. This is a field/source mismatch,
not a broken pipeline.

## Cleaning up

```bash
elasticctl rules list --tag elasticctl-sample --json --fields rule_id
elasticctl rules delete $(elasticctl rules list --tag elasticctl-sample --json \
    | python3 -c 'import json,sys;print(" ".join(r["rule_id"] for r in json.load(sys.stdin)))') --yes

curl -fSL -X DELETE "$ELASTICCTL_ES_URL/_data_stream/logs-elasticctl.sample-default" \
  -H "Authorization: ApiKey $ELASTICCTL_API_KEY"
curl -fSL -X DELETE "$ELASTICCTL_ES_URL/_index_template/elasticctl-sample" \
  -H "Authorization: ApiKey $ELASTICCTL_API_KEY"
```

## Sources not used

- `sbousseaden/EVTX-ATTACK-SAMPLES` — **no license file in the repository**
  (checked `LICENSE`, `LICENSE.md`, `LICENSE.txt`, `LICENCE`, `LICENCE.md`,
  `COPYING`, `COPYING.txt`; the README is silent). Third-party mirrors label it
  GPL-3.0, which the repository does not. Not fetched and not used.
- `elastic/detection-rules` — Elastic License v2. Its rule content is never
  committed here.
- `splunk/security_content` — Apache 2.0, but the detections are SPL and do not
  convert to Elasticsearch.
