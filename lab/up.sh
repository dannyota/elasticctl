#!/usr/bin/env bash
# Disable inherited tracing before handling credentials, including when sourced.
set +x

# Shared with seed.sh. Parse data without executing lab/.env as shell code.
lab_env() {
  python3 - "$@" <<'PYTHON'
import os
from pathlib import Path
import secrets
import sys
import tempfile

path = Path(".env")
values = {}
if path.exists():
    for line in path.read_text().splitlines():
        name, sep, value = line.partition("=")
        if not sep or name.startswith("#"):
            continue
        value = value.strip()
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("\\'", "'")
        values[name.strip()] = value

operation = sys.argv[1]
if operation == "read":
    name = sys.argv[2]
    value = os.environ.get(name, values.get(name, ""))
    if not value:
        sys.exit(f"{name} is required in the environment or lab/.env; run lab/up.sh")
    print(value)
    sys.exit()

names = ("ELASTIC_PASSWORD", "KIBANA_SYSTEM_PASSWORD") if operation == "prepare" else (
    "ELASTICCTL_API_KEY", "ELASTICCTL_KIBANA_URL", "ELASTICCTL_ES_URL")
for name in names:
    value = os.environ.get(name, values.get(name))
    if value is None and operation == "prepare":
        value = secrets.token_hex(32)
    if not value or "\n" in value or "\r" in value:
        sys.exit(f"{name} must be a nonempty single-line value")
    values[name] = value

# mkstemp creates mode 0600 before any bytes are written; replace is atomic.
fd, temporary = tempfile.mkstemp(prefix=".env.", dir=".")
try:
    with os.fdopen(fd, "w") as output:
        for name, value in values.items():
            output.write(name + "='" + value.replace("'", "\\'") + "'\n")
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYTHON
}

# seed.sh imports only the helper.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return
fi
set -euo pipefail
cd "$(dirname "$0")"
umask 077
lab_env prepare
ELASTIC_PASSWORD=$(lab_env read ELASTIC_PASSWORD)
KIBANA_SYSTEM_PASSWORD=$(lab_env read KIBANA_SYSTEM_PASSWORD)
export ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD
ES=http://localhost:9200
KB=http://localhost:5601
AUTH="elastic:$ELASTIC_PASSWORD"

# Select the first available Compose CLI with a version probe; this does not
# verify daemon reachability.
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
  exit 1
fi

# Reset the kibana_system password before waiting for Kibana readiness.
curl -sf -u "$AUTH" -X POST "$ES/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,os; print(json.dumps({"password":os.environ["KIBANA_SYSTEM_PASSWORD"]}))')" >/dev/null

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
  exit 1
fi

# Enable Platinum-only features for 30 days.
curl -sf -u "$AUTH" -X POST "$ES/_license/start_trial?acknowledge=true" >/dev/null

# Create the signals index before running detection rules.
curl -sf -u "$AUTH" -X POST "$KB/api/detection_engine/index" \
  -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' >/dev/null

KEY=$(curl -sf -u "$AUTH" -X POST "$ES/_security/api_key" \
  -H 'Content-Type: application/json' \
  -d '{"name":"local-lab"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["encoded"])')

export ELASTICCTL_API_KEY="$KEY" ELASTICCTL_KIBANA_URL="$KB" ELASTICCTL_ES_URL="$ES"
lab_env save
unset KEY ELASTICCTL_API_KEY
echo "wrote lab/.env"
