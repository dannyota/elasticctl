#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

check_package() {
  local package=$1
  local entrypoint=$2
  local files
  files=$(cargo package --package "$package" --list --locked --allow-dirty)

  if grep -Eq '(^|/)tests/|elasticctl-api-test-support' <<<"$files"; then
    printf '%s\n' "$package package contains private integration-test files" >&2
    return 1
  fi
  for required in Cargo.toml Cargo.toml.orig Cargo.lock "$entrypoint"; do
    grep -Fxq "$required" <<<"$files" || {
      printf '%s\n' "$package package is missing $required" >&2
      return 1
    }
  done
}

check_package elasticctl-core src/lib.rs
check_package elasticctl-api src/lib.rs
check_package elasticctl src/main.rs
