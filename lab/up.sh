#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ES=http://localhost:9200
KB=http://localhost:5601
AUTH='elastic:elasticctl-lab'

# Use the first working Compose provider. Locally this is usually Podman,
# while GitHub runners use Docker even when Podman is installed.
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif podman compose version >/dev/null 2>&1; then
  COMPOSE="podman compose"
else
  echo "no working compose provider: tried 'docker compose' and 'podman compose'" >&2
  exit 1
fi
echo "compose provider: $COMPOSE"
export COMPOSE

$COMPOSE up -d

echo "Waiting for Elasticsearch..."
es_ready=0
for _ in $(seq 1 100); do
  if curl -sf -u "$AUTH" "$ES/_cluster/health" >/dev/null; then
    es_ready=1
    break
  fi
  sleep 3
done
if [ "$es_ready" -ne 1 ]; then
  echo "Elasticsearch did not become healthy after 100 attempts" >&2
  $COMPOSE logs >&2 || true
  exit 1
fi

# Set the kibana_system password before Kibana starts using it.
curl -sf -u "$AUTH" -X POST "$ES/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' \
  -d '{"password":"elasticctl-lab-kibana"}' >/dev/null

echo "Waiting for Kibana..."
kb_ready=0
for _ in $(seq 1 60); do
  if curl -sf "$KB/api/status" | grep -q available; then
    kb_ready=1
    break
  fi
  sleep 5
done
if [ "$kb_ready" -ne 1 ]; then
  echo "Kibana did not become available after 60 attempts" >&2
  $COMPOSE logs >&2 || true
  exit 1
fi

# Enable Platinum-only features for 30 days.
curl -sf -u "$AUTH" -X POST "$ES/_license/start_trial?acknowledge=true" >/dev/null || true

# Create the signals index before running detection rules.
curl -sf -u "$AUTH" -X POST "$KB/api/detection_engine/index" \
  -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' >/dev/null || true

KEY=$(curl -sf -u "$AUTH" -X POST "$ES/_security/api_key" \
  -H 'Content-Type: application/json' \
  -d '{"name":"elasticctl-lab"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["encoded"])')

cat <<EOF

Lab is up.

  ELASTICCTL_KIBANA_URL=$KB \\
  ELASTICCTL_ES_URL=$ES \\
  ELASTICCTL_API_KEY=$KEY \\
  elasticctl config init --from-env --profile lab

EOF
