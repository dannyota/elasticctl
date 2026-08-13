#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Install prebuilt Elastic rules so pull, diff, and preview have real data.
# Requires a running lab from ./up.sh.
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
