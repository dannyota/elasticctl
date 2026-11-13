#!/usr/bin/env python3
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
                    print(f"skipping duplicate id {rule['rule_id']}", file=sys.stderr)
                    continue
                seen.add(rule["rule_id"])
                print(json.dumps(rule))
                written += 1

    print(f"prepared {written} rules", file=sys.stderr)


if __name__ == "__main__":
    main()
