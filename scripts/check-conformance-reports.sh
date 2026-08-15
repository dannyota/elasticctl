#!/usr/bin/env bash
# Validate the tracked 0.2.3 conformance evidence without exposing matched data.
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=docs/conformance/v0.2.3
CONTRACTS='["diagnostics","pull_diff","exception_round_trip","stale_pointer_repair","source_scoping","rule_round_trip"]'
FLAVORS=(serverless ech traditional)

[ -d "$DIR" ] || {
  echo "FAIL: missing $DIR"
  exit 1
}

shopt -s nullglob
reports=("$DIR"/*.json)
[ "${#reports[@]}" -eq 3 ] || {
  echo "FAIL: expected exactly three conformance reports"
  exit 1
}

for flavor in "${FLAVORS[@]}"; do
  matches=("$DIR/$flavor-"*.json)
  [ "${#matches[@]}" -eq 1 ] || {
    echo "FAIL: expected one $flavor conformance report"
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

scan_for() {
  local description=$1
  local pattern=$2
  shift 2
  if rg --pcre2 -l "$pattern" "$@" >/dev/null; then
    echo "FAIL: $description in a conformance report"
    return 1
  fi
}

scan_for "credential material" \
  'essu_[A-Za-z0-9_-]{8,}|ApiKey [A-Za-z0-9+/=]{20,}|Bearer [A-Za-z0-9._-]{20,}' \
  "${reports[@]}"
scan_for "deployment hostname" \
  '[a-z0-9-]+\.(kb|es)\.[a-z0-9-]+\.(aws|gcp|azure)\.elastic(-cloud)?\.(cloud|com)' \
  "${reports[@]}"
scan_for "URL userinfo" \
  '://[^/"[:space:]]+:[^/@"[:space:]]+@' \
  "${reports[@]}"
scan_for "email address" \
  '[A-Za-z0-9._%+-]+@(?![A-Za-z0-9.-]*example\.(com|invalid)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
  "${reports[@]}"

echo "conformance reports valid: schema and public-data checks passed"
