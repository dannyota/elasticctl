#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  COMPOSE="podman compose"
fi
$COMPOSE down -v
