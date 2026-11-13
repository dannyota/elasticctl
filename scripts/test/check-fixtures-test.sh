#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/elasticctl-check-fixtures.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
REPO=$WORK/repo
cases=0

fail() { printf 'check-fixtures-test: %s\n' "$*" >&2; exit 1; }

run_case() {
  rm -rf -- "$REPO"
  mkdir -p "$REPO/scripts" "$REPO/tests/fixtures/sample-1.0.0"
  cp "$ROOT/scripts/check-fixtures.sh" "$REPO/scripts/"
  printf '{\n%s\n}\n' "$1" >"$REPO/tests/fixtures/sample-1.0.0/probe.json"
  status=0
  output=$(bash "$REPO/scripts/check-fixtures.sh" 2>&1) || status=$?
  cases=$((cases + 1))
}

clean() {
  run_case "$2"
  [ "$status" -eq 0 ] || fail "$1: expected a clean result, got: $output"
}

leak() {
  local name=$1 line=$2 secret=$3
  run_case "$line"
  [ "$status" -eq 1 ] || fail "$name: expected a leak, got status $status"
  case "$output" in
    *"tests/fixtures/sample-1.0.0/probe.json:2"*) ;;
    *) fail "$name: the report does not name the file and line: $output" ;;
  esac
  case "$output" in
    *"$secret"*) fail "$name: the report repeats the matched text" ;;
  esac
}

date_part=2026.01.02

clean "redacted backing index" '"_index": ".ds-logs-sample-default-REDACTED-000001"'
clean "date inside the stream name" \
  "\"_index\": \".ds-sample-$date_part-123-REDACTED-000001\""
clean "date and other stream characters before the redaction" \
  "\"_index\": \".ds-a-$date_part-123@prod-REDACTED-000001\""
clean "plain index with a date" "\"_index\": \"sample-$date_part\""

leak "dated backing index" \
  "\"_index\": \".ds-logs-sample-default-$date_part-000001\"" "$date_part"
leak "dated backing index in embedded NDJSON" \
  "\"ndjson\": \"{\\\\\"_index\\\\\":\\\\\".ds-logs-sample-default-$date_part-000003\\\\\"}\"" "$date_part"
leak "dated backing index in a list" \
  "\"indices\": \".ds-a-$date_part-000001,.ds-b-$date_part-000002\"" "$date_part"

key="essu_$(printf 'A%.0s' 1 2 3 4 5 6 7 8 9 10 11 12)"
leak "credential" "\"api_key\": \"$key\"" "$key"
address="operator@$(printf 'corp').test"
leak "email address" "\"note\": \"$address\"" "$address"

printf 'check-fixtures-test: %d cases passed\n' "$cases"
