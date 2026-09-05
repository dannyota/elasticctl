#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 - <<'PY'
import sys
import tomllib

with open("Cargo.toml", "rb") as f:
    root = tomllib.load(f)
want = root["workspace"]["package"]["version"]
versions = {}
for name in ("elasticctl-core", "elasticctl-api", "elasticctl-mcp"):
    versions[f"workspace dependency {name}"] = root["workspace"]["dependencies"][name]["version"]
for name, directory in (
    ("elasticctl-core", "elasticctl-core"),
    ("elasticctl-api", "elasticctl-api"),
    ("elasticctl-mcp", "elasticctl-mcp"),
    ("elasticctl", "elasticctl-cli"),
):
    with open(f"crates/{directory}/Cargo.toml", "rb") as f:
        package = tomllib.load(f)["package"]
    version = package["version"]
    versions[f"package {name}"] = want if version == {"workspace": True} else version
wrong = [name for name, version in versions.items() if version != want]
for name in wrong:
    print(f"{name} version does not match the workspace version", file=sys.stderr)
if wrong:
    sys.exit(1)
PY

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
check_package elasticctl-mcp src/lib.rs
check_package elasticctl src/main.rs
