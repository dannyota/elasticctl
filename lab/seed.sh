#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Install the prebuilt Elastic rules so pull, diff, and preview have real data.
# Requires the lab from ./up.sh to be running.
ES=http://localhost:9200
KB=http://localhost:5601
AUTH='elastic:elasticctl-lab'

KEY=$(curl -sf -u "$AUTH" -X POST "$ES/_security/api_key" \
  -H 'Content-Type: application/json' \
  -d '{"name":"elasticctl-lab-seed"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["encoded"])')

ELASTICCTL_KIBANA_URL=$KB \
ELASTICCTL_ES_URL=$ES \
ELASTICCTL_API_KEY=$KEY \
cargo xtask seed
