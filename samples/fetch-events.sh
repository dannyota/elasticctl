#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/out/events}"
base="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

mkdir -p "$out"

datasets="
empire_mimikatz_extract_keys	credential_access/host
empire_psremoting_stager	lateral_movement/host
empire_launcher_vbs	execution/host
"

printf '%s\n' "$datasets" | while IFS=$'\t' read -r name path; do
    [ -n "$name" ] || continue
    echo "fetching $name"
    curl -fSL --proto '=https' --tlsv1.2 -o "$out/$name.zip" "$base/$path/$name.zip"
    unzip -oq "$out/$name.zip" -d "$out"
done

echo
echo "unpacked into $out:"
ls -1 "$out"/*.json
