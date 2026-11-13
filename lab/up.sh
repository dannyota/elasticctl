#!/usr/bin/env bash
set +x

lab_env() {
  python3 - "$@" <<'PYTHON'
import os
from pathlib import Path
import re
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
    if operation == "prepare" and not re.fullmatch(r"[A-Za-z0-9._~-]{16,128}", value or ""):
        sys.exit(f"{name} must match ^[A-Za-z0-9._~-]{{16,128}}$")
    if not value or "\n" in value or "\r" in value:
        sys.exit(f"{name} must be a nonempty single-line value")
    values[name] = value

if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or
       not re.fullmatch(r"[A-Za-z0-9._~:/+=@-]+", value)
       for name, value in values.items()):
    sys.exit("lab/.env contains unsupported characters")

fd, temporary = tempfile.mkstemp(prefix=".env.", dir=".")
try:
    with os.fdopen(fd, "w") as output:
        for name, value in values.items():
            output.write(name + "=" + value + "\n")
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYTHON
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return
fi
set -euo pipefail
cd "$(dirname "$0")"
umask 077
acquire_lock() {
  if mkdir .up.lock 2>/dev/null; then
    echo "$$" > .up.lock/pid
    return 0
  fi
  local owner
  owner=$(cat .up.lock/pid 2>/dev/null || true)
  if [[ "$owner" =~ ^[0-9]+$ ]]; then
    if kill -0 "$owner" 2>/dev/null; then
      echo "lab startup lock is held by running process $owner (lab/.up.lock)" >&2
      return 1
    fi
  elif [[ -z "$(find .up.lock -maxdepth 0 -mmin +5 2>/dev/null)" ]]; then
    echo "lab startup lock is held (lab/.up.lock); another up.sh may be starting" >&2
    return 1
  fi
  echo "reclaiming stale lab startup lock (lab/.up.lock)" >&2
  rm -rf -- .up.lock
  if ! mkdir .up.lock 2>/dev/null; then
    echo "lab startup lock is held (lab/.up.lock); another up.sh may be running" >&2
    return 1
  fi
  echo "$$" > .up.lock/pid
}
acquire_lock || exit 1
cleanup() {
  rm -rf -- .up.lock
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lab_env prepare
ELASTIC_PASSWORD=$(lab_env read ELASTIC_PASSWORD)
KIBANA_SYSTEM_PASSWORD=$(lab_env read KIBANA_SYSTEM_PASSWORD)
export ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD
ES=http://localhost:9200
KB=http://localhost:5601
AUTH="elastic:$ELASTIC_PASSWORD"

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

if ! compose_diagnostics=$($COMPOSE config --quiet 2>&1); then
  echo "Compose configuration failed; diagnostics suppressed to protect credentials" >&2
  exit 1
fi
# shellcheck disable=SC2034
if ! compose_diagnostics=$($COMPOSE up -d 2>&1); then
  echo "Compose startup failed; diagnostics suppressed to protect credentials" >&2
  exit 1
fi

unset compose_diagnostics

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

qualifying_license() {
  local response
  response=$(curl -sf -u "$AUTH" "$ES/_license") || return 2
  printf '%s' "$response" | python3 -c '
import json,sys
try:
    license = json.load(sys.stdin)["license"]
    if not isinstance(license, dict):
        sys.exit(2)
except (ValueError, KeyError, TypeError):
    sys.exit(2)
sys.exit(0 if license.get("status") == "active" and
         license.get("type") in ("trial", "platinum", "enterprise") else 1)
'
}
license_status=0
qualifying_license || license_status=$?
if [ "$license_status" -ne 0 ]; then
  if [ "$license_status" -ne 1 ]; then
    echo "Could not read the lab license" >&2
    exit 1
  fi
  trial_status=$(curl -s -u "$AUTH" -X POST \
    "$ES/_license/start_trial?acknowledge=true" -o /dev/null -w '%{http_code}')
  case "$trial_status" in
    200) ;;
    403)
      if ! qualifying_license; then
        echo "Trial activation denied and no active qualifying license found" >&2
        exit 1
      fi
      ;;
    *) echo "Trial activation failed" >&2; exit 1 ;;
  esac
fi

curl -sf -u "$AUTH" -X POST "$KB/api/detection_engine/index" \
  -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' >/dev/null

KEY=$(curl -sf -u "$AUTH" -X POST "$ES/_security/api_key" \
  -H 'Content-Type: application/json' \
  -d '{"name":"local-lab"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["encoded"])')

export ELASTICCTL_API_KEY="$KEY" ELASTICCTL_KIBANA_URL="$KB" ELASTICCTL_ES_URL="$ES"
lab_env save
unset KEY ELASTICCTL_API_KEY
echo "wrote lab/.env"
