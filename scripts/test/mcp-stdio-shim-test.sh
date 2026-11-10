#!/usr/bin/env bash
# Exercise byte transparency and lifecycle handling with disposable servers.
set -euo pipefail
ROOT=$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/elasticctl-shim.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
SHIM=$ROOT/scripts/mcp-stdio-shim.sh
cases=0
fail() { printf 'mcp-stdio-shim-test: %s\n' "$*" >&2; exit 1; }
cat >"$WORK/server" <<'SERVER'
#!/usr/bin/env bash
printf 'server stderr\n' >&2
if [ "${MODE:-}" = term ]; then
  trap 'printf term >"$MARKER"; exit 143' TERM
  printf ready >"$READY"
  while :; do read -r line || break; done
elif [ "${MODE:-}" = exit ]; then
  exit "${STATUS:-0}"
else
  while IFS= read -r line; do printf '%s\n' "$line"; done
  printf '%s' "$line"
  printf eof >"$MARKER"
fi
exit "${STATUS:-0}"
SERVER
printf '{"a":1}\n{"b":2}\n雪\n' >"$WORK/input"
head -c 300000 /dev/zero | tr '\0' x >>"$WORK/input"
printf '\nlast' >>"$WORK/input"
MARKER=$WORK/eof bash "$WORK/server" <"$WORK/input" >"$WORK/expected" 2>"$WORK/expected-err"
MARKER=$WORK/eof bash "$SHIM" "$WORK/log" -- bash "$WORK/server" <"$WORK/input" >"$WORK/out" 2>"$WORK/err" || fail 'pass-through run'
cmp "$WORK/input" "$WORK/log/in.jsonl" || fail input
cmp "$WORK/expected" "$WORK/out" || fail stdout
cmp "$WORK/out" "$WORK/log/out.jsonl" || fail output
cases=$((cases+1))
cmp "$WORK/expected-err" "$WORK/err" || fail stderr
cases=$((cases+1))
for status in 0 7; do
  got=0
  STATUS=$status MODE='exit' bash "$SHIM" "$WORK/status-$status" -- bash "$WORK/server" </dev/null >"$WORK/out" 2>"$WORK/err" || got=$?
  [ "$got" -eq "$status" ] || fail status
 done
cases=$((cases+1))
[ "$(cat "$WORK/eof")" = eof ] || fail eof
cases=$((cases+1))
mkfifo "$WORK/fifo"
exec 9<>"$WORK/fifo"
MODE=term MARKER=$WORK/term READY=$WORK/ready bash "$SHIM" "$WORK/signal" -- bash "$WORK/server" <"$WORK/fifo" >"$WORK/out" 2>"$WORK/err" &
pid=$!
for _ in {1..100}; do [ -f "$WORK/ready" ] && break; sleep 0.05; done
[ -f "$WORK/ready" ] || fail readiness
kill -TERM "$pid"
got=0
wait "$pid" || got=$?
[ "$got" -eq 143 ] && [ "$(cat "$WORK/term")" = term ] || fail signal
exec 9>&-
cases=$((cases+1))
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
[ "$(mode "$WORK/log")" = 700 ] && [ "$(mode "$WORK/log/in.jsonl")" = 600 ] && [ "$(mode "$WORK/log/out.jsonl")" = 600 ] || fail modes
cases=$((cases+1))
MARKER=$WORK/eof bash "$SHIM" "$WORK/log" -- bash "$WORK/server" <"$WORK/input" >"$WORK/out" 2>"$WORK/err"
cat "$WORK/input" "$WORK/input" >"$WORK/double"
cmp "$WORK/double" "$WORK/log/in.jsonl" || fail append-input
cmp "$WORK/double" "$WORK/log/out.jsonl" || fail append-output
cases=$((cases+1))
git init -q "$WORK/repo"
mkdir "$WORK/gitfile"
touch "$WORK/gitfile/.git"
for dir in "$WORK/repo/log" "$WORK/gitfile/log"; do
  got=0
  bash "$SHIM" "$dir" -- true >"$WORK/out" 2>"$WORK/err" || got=$?
  [ "$got" -eq 2 ] && [ ! -e "$dir" ] && [ ! -s "$WORK/out" ] || fail refusal
  printf 'mcp-stdio-shim: log directory is inside a Git work tree\n' >"$WORK/refusal"
  cmp "$WORK/refusal" "$WORK/err" || fail 'refusal diagnostic'
done
got=0
bash "$SHIM" "$WORK/missing" true >"$WORK/out" 2>"$WORK/err" || got=$?
[ "$got" -eq 2 ] && [ ! -e "$WORK/missing" ] && [ ! -s "$WORK/out" ] || fail usage
printf 'mcp-stdio-shim: invalid usage\n' >"$WORK/refusal"
cmp "$WORK/refusal" "$WORK/err" || fail 'usage diagnostic'
cases=$((cases+1))
mkfifo "$WORK/held"
exec 9<>"$WORK/held"
MODE='exit' bash "$SHIM" "$WORK/unique-log" -- bash "$WORK/server" <"$WORK/held" >"$WORK/out" 2>"$WORK/err" || fail shutdown
exec 9>&-
if pgrep -f "tee -a -- $WORK/unique-log" >/dev/null; then fail 'leftover tee'; fi
cases=$((cases+1))
printf 'mcp-stdio-shim-test: passed (%d cases)\n' "$cases"
