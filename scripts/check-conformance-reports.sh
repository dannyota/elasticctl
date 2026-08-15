#!/usr/bin/env bash
# Validate every tracked v0.2.* conformance report without exposing matched data.
set -euo pipefail
cd "$(dirname "$0")/.."

CONTRACTS='["diagnostics","pull_diff","exception_round_trip","stale_pointer_repair","source_scoping","rule_round_trip"]'
FLAVORS=(serverless ech traditional)

shopt -s nullglob
dirs=(docs/conformance/v0.2.*)
# Keep only directories: the glob would otherwise match a stray regular file.
filtered=()
for candidate in "${dirs[@]}"; do
  [ -d "$candidate" ] && filtered+=("$candidate")
done
dirs=("${filtered[@]}")
[ "${#dirs[@]}" -gt 0 ] || {
  echo "FAIL: no docs/conformance/v0.2.* directories found"
  exit 1
}

all_reports=()

for dir in "${dirs[@]}"; do
  reports=("$dir"/*.json)
  [ "${#reports[@]}" -eq 3 ] || {
    echo "FAIL: expected exactly three conformance reports in $dir"
    exit 1
  }

  for flavor in "${FLAVORS[@]}"; do
    matches=("$dir/$flavor-"*.json)
    [ "${#matches[@]}" -eq 1 ] || {
      echo "FAIL: expected one $flavor conformance report in $dir"
      exit 1
    }

    report=${matches[0]}
    filename=${report##*/}
    version=${filename#"$flavor-"}
    version=${version%.json}
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo "FAIL: invalid version in $filename"
      exit 1
    }

    jq -e --arg flavor "$flavor" --arg version "$version" \
      --argjson contracts "$CONTRACTS" '
        (type == "object") and
        (keys == ["contracts", "flavor", "version"]) and
        (.flavor == $flavor) and
        (.version == $version) and
        (.contracts | type == "array") and
        (.contracts | length == 6) and
        ([.contracts[].contract] == $contracts) and
        all(.contracts[];
          (type == "object") and
          (keys == ["contract", "error_class", "result"]) and
          (.result == "pass" or .result == "fail" or .result == "skip") and
          (if .result == "pass" then
             .error_class == null
           elif .result == "fail" then
             .error_class == "contract"
           else
             (.error_class | type == "string" and
               test("^unsupported:[a-z0-9_-]+:9\\.5\\.1$"))
           end)
        )
      ' "$report" >/dev/null || {
        echo "FAIL: invalid conformance report schema in $filename"
        exit 1
      }
  done

  all_reports+=("${reports[@]}")
done

scan_for() {
  local description=$1
  local pattern=$2
  shift 2
  if grep -P -l "$pattern" "$@" >/dev/null; then
    echo "FAIL: $description in a conformance report"
    return 1
  fi
}

scan_for "credential material" \
  'essu_[A-Za-z0-9_-]{8,}|ApiKey [A-Za-z0-9+/=]{20,}|Bearer [A-Za-z0-9._-]{20,}' \
  "${all_reports[@]}"
scan_for "deployment hostname" \
  '[a-z0-9-]+\.(kb|es)\.[a-z0-9-]+\.(aws|gcp|azure)\.elastic(-cloud)?\.(cloud|com)' \
  "${all_reports[@]}"
scan_for "URL userinfo" \
  '://[^/"[:space:]]+:[^/@"[:space:]]+@' \
  "${all_reports[@]}"
scan_for "email address" \
  '[A-Za-z0-9._%+-]+@(?![A-Za-z0-9.-]*example\.(com|invalid)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
  "${all_reports[@]}"

echo "conformance reports valid: schema and public-data checks passed"
