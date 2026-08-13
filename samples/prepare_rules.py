#!/usr/bin/env python3
"""Make converted Sigma rules safe to import into a shared project.

Every object gets the elasticctl-sample marker so a live run can find and
remove everything it created, and so no untagged rule is ever touched:

  * rule_id becomes elasticctl-sample-<slug>
  * tags become ["elasticctl-sample"]
  * enabled is false
  * index points at the sample data stream

Server-owned fields are stripped so the import assigns its own. The DRL
attribution the converter emits — author, references, license — is kept
untouched: the licence requires it.

Reads NDJSON on argv, writes NDJSON on stdout. Standard library only.
"""

import json
import re
import sys

VOLATILE = (
    "id",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "revision",
    "version",
    "execution_summary",
)

MARKER = "elasticctl-sample"
SAMPLE_INDEX = ["logs-elasticctl.sample-*"]


def slug(rule):
    source = rule.get("name") or rule.get("rule_id") or "rule"
    return re.sub(r"[^a-z0-9]+", "_", source.lower()).strip("_")[:60]


def prepare(rule):
    for field in VOLATILE:
        rule.pop(field, None)
    rule["rule_id"] = f"{MARKER}-{slug(rule)}"
    rule["tags"] = [MARKER]
    rule["enabled"] = False
    rule["index"] = list(SAMPLE_INDEX)
    return rule


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: prepare_rules.py <converted.ndjson>...")

    seen = set()
    written = 0
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rule = prepare(json.loads(line))
                if rule["rule_id"] in seen:
                    # Two rules slugging to one id would import as one.
                    print(f"skipping duplicate id {rule['rule_id']}", file=sys.stderr)
                    continue
                seen.add(rule["rule_id"])
                print(json.dumps(rule))
                written += 1

    print(f"prepared {written} rules", file=sys.stderr)


if __name__ == "__main__":
    main()
