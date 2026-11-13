#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/out}"
slice="${SIGMA_SLICE:-rules/windows/process_creation}"
count="${SIGMA_COUNT:-40}"

mkdir -p "$out"
if [ ! -d "$out/sigma" ]; then
    echo "cloning SigmaHQ/sigma (shallow)"
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$out/sigma"
fi

echo "converting $slice"
(
    cd "$out/sigma"
    sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson \
        --skip-unsupported -o "$out/sigma-converted.ndjson" "$slice"
)

head -n "$count" "$out/sigma-converted.ndjson" > "$out/sigma-slice.ndjson"
echo "wrote $(wc -l < "$out/sigma-slice.ndjson") rules to $out/sigma-slice.ndjson"
echo "next: python3 $here/prepare_rules.py $out/sigma-slice.ndjson > $out/sample-rules.ndjson"
