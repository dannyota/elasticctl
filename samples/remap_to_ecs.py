#!/usr/bin/env python3
"""Turn OTRF Security-Datasets events into ECS documents Elastic rules can match.

Two things have to happen or no rule will ever fire:

  * The events use legacy Winlogbeat field names (EventID, CommandLine, Image).
    Elastic rules query ECS (event.code, process.command_line,
    process.executable), so the fields are renamed.
  * Their @timestamp is years old. A rule looks back minutes, so every event is
    rewritten into the last few minutes.

One field is dropped rather than renamed: OTRF's `host` is a scalar string,
while ECS maps `host` as an object. Left in place it fails every single
document with "object mapping for [host] ... found a concrete value".

Reads one or more NDJSON files, writes an Elasticsearch _bulk body on stdout.
Standard library only.
"""

import argparse
import json
import sys
import time

# Verified against the three empire_* datasets.
RENAMES = {
    "EventID": "event.code",
    "CommandLine": "process.command_line",
    "Image": "process.executable",
    "ParentImage": "process.parent.executable",
    "SourceName": "event.provider",
    "Hostname": "host.name",
}

# Process-creation events by channel-specific ID.
PROCESS_CREATION_CODES = {"1", "4688"}


def set_dotted(doc, dotted, value):
    parts = dotted.split(".")
    node = doc
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def remap(event, timestamp):
    out = {"@timestamp": timestamp}
    for key, value in event.items():
        if key in RENAMES:
            set_dotted(out, RENAMES[key], value)
        elif key in ("@timestamp", "host"):
            # `host` is scalar here but an object in ECS.
            continue
        else:
            out[key] = value

    code = str(out.get("event", {}).get("code", ""))
    if code in PROCESS_CREATION_CODES:
        out["event"]["category"] = ["process"]
        out["event"]["type"] = ["start"]
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help="NDJSON files from fetch-events.sh")
    parser.add_argument(
        "--index",
        default="logs-elasticctl.sample-default",
        help="data stream to write into (default: %(default)s)",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=150,
        help="spread events across the last N seconds (default: %(default)s)",
    )
    args = parser.parse_args()

    now = time.time()
    events = []
    for path in args.files:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))

    if not events:
        sys.exit("no events read")

    step = args.window_seconds / len(events)
    for position, event in enumerate(events):
        moment = now - args.window_seconds + position * step
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(moment)) + ".000Z"
        # Use `create`, not `index`: data streams accept no other operation.
        print(json.dumps({"create": {"_index": args.index}}))
        print(json.dumps(remap(event, stamp)))

    print(f"remapped {len(events)} events", file=sys.stderr)


if __name__ == "__main__":
    main()
