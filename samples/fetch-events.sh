#!/usr/bin/env bash
# Fetch three OTRF Security-Datasets Windows event sets (MIT).
#
# Fetch, never vendor: nothing this downloads is committed. Output lands in
# samples/out/events/, which is gitignored.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/out/events}"
base="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

mkdir -p "$out"

# name<TAB>path-under-base. A plain list, not an associative array: macOS
# still ships bash 3.2, which has none.
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
