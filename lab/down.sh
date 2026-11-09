#!/usr/bin/env bash
set +x
set -euo pipefail
cd "$(dirname "$0")"
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  COMPOSE="podman compose"
fi
ELASTIC_PASSWORD=unused KIBANA_SYSTEM_PASSWORD=unused \
  $COMPOSE --env-file /dev/null down -v --remove-orphans
