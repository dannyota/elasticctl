#!/usr/bin/env bash
# Exercise byte transparency and lifecycle handling with disposable servers.
set -euo pipefail
ROOT=$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/elasticctl-shim.XXXXXX")
trap 'pkill -KILL -f "$WORK/" 2>/dev/null || :; rm -rf -- "$WORK"' EXIT
# The shim canonicalizes its log dir, so process patterns need the real path.
WORK=$(cd -P -- "$WORK" && pwd -P)
SHIM=$ROOT/scripts/mcp-stdio-shim.sh
cases=0
fail() { printf 'mcp-stdio-shim-test: %s\n' "$*" >&2; exit 1; }
command -v pgrep >/dev/null || fail 'pgrep is required'
# A shell started with SIGINT ignored cannot pass a default one to the shim.
[ -z "$(trap -p INT)" ] || fail 'SIGINT is ignored; run the test in the foreground'
cat >"$WORK/server" <<'SERVER'
#!/usr/bin/env bash
printf 'server stderr\n' >&2
[ "${MODE:-}" != term ] || trap 'printf term >"$MARKER"; exit "${STATUS:-143}"' TERM
[ -z "${READY:-}" ] || printf '%s' "$$" >"$READY"
case ${MODE:-} in
  term|wait) while :; do read -r line || break; done ;;
  exit) exit "${STATUS:-0}" ;;
  kill) kill -KILL "$$" ;;
  line) IFS= read -r line; printf '%s\n' "$line" >"$MARKER" ;;
  hold)
    # The grandchild holds stdout open; "<" keeps Bash from giving it /dev/null.
    READY='' MODE='wait' bash "$0" <"$HOLD" &
    printf '%s' "$!" >"$MARKER"
    trap 'printf term >"$MARKER.term"' TERM
    # A forwarded TERM interrupts the first read.
    read -r line || read -r line
    ;;
  *)
    while IFS= read -r line; do printf '%s\n' "$line"; done
    printf '%s' "$line"
    printf eof >"$MARKER"
    ;;
esac
exit "${STATUS:-0}"
SERVER
printf 'server stderr\n' >"$WORK/server-err"
mkfifo "$WORK/clock" "$WORK/fifo"
exec 8<>"$WORK/clock"
nap() { read -r -t "$1" -u 8 || :; }
# Wait up to 5 s for a file to have content.
await() {
  local _
  for _ in {1..500}; do [ ! -s "$1" ] || return 0; nap 0.01; done
  fail "$2"
}
# Start the shim in the background with SIGINT at its default, as a client
# would, the way the shim starts its command. Return once a fresh Bash has
# closed fd 7, so no signal is lost. The explicit "<&0" keeps Bash from giving
# the background shim /dev/null.
launch() {
  local gate
  exec 7> >(read -r || :)
  gate=$!
  ( trap - INT; exec bash -c 'exec 7>&-; exec bash "$@"' launch "$SHIM" "$@" ) <&0 &
  pid=$!
  exec 7>&-
  wait "$gate" || :
}
# Wait up to 5 s for a background shim and set got to its status.
reap() {
  local _
  for _ in {1..500}; do kill -0 "$1" 2>/dev/null || break; nap 0.01; done
  if kill -0 "$1" 2>/dev/null; then pkill -KILL -P "$1" || :; kill -KILL "$1"; fail "$2"; fi
  got=0
  wait "$1" 2>/dev/null || got=$?
}
# Record a running shim's relays and command.
children() {
  local p
  kids=()
  for p in $(pgrep -P "$1"); do kids+=("$p"); done
  [ "${#kids[@]}" -ge 3 ] || fail "$2"
}
gone() {
  local p
  for p in "${kids[@]}"; do ! kill -0 "$p" 2>/dev/null || fail "$1"; done
}
printf '{"a":1}\n{"b":2}\n雪\n' >"$WORK/input"
head -c 300000 /dev/zero | tr '\0' x >>"$WORK/input"
printf '\nlast' >>"$WORK/input"
MARKER=$WORK/eof-ref bash "$WORK/server" <"$WORK/input" >"$WORK/expected" 2>"$WORK/expected-err"
[ ! -e "$WORK/eof-shim" ] || fail 'stale eof marker'
MARKER=$WORK/eof-shim bash "$SHIM" "$WORK/log" -- bash "$WORK/server" <"$WORK/input" >"$WORK/out" 2>"$WORK/err" || fail 'pass-through run'
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
got=0
MODE='kill' bash "$SHIM" "$WORK/status-kill" -- bash "$WORK/server" </dev/null >"$WORK/out" 2>"$WORK/err" || got=$?
[ "$got" -eq 137 ] || fail 'signal status'
cmp -s "$WORK/server-err" "$WORK/err" || fail 'signal stderr'
cases=$((cases+1))
[ "$(cat "$WORK/eof-shim")" = eof ] || fail eof
cases=$((cases+1))
exec 9<>"$WORK/fifo"
for status in '' 42; do
  rm -f "$WORK/ready" "$WORK/term"
  STATUS=$status MODE='term' MARKER=$WORK/term READY=$WORK/ready launch "$WORK/signal" -- bash "$WORK/server" <"$WORK/fifo" >"$WORK/out" 2>"$WORK/err"
  await "$WORK/ready" readiness
  children "$pid" 'TERM children'
  [ "$(pgrep -f "tee -a -- $WORK/signal/" | grep -c .)" -eq 2 ] || fail 'relay pattern'
  kill -TERM "$pid"
  reap "$pid" 'TERM forwarding'
  [ "$got" -eq "${status:-143}" ] && [ "$(cat "$WORK/term")" = term ] || fail signal
  gone 'TERM leftover'
done
exec 9>&-
cases=$((cases+1))
exec 9<>"$WORK/fifo"
rm -f "$WORK/ready"
MODE='wait' READY=$WORK/ready launch "$WORK/int" -- bash "$WORK/server" <"$WORK/fifo" >"$WORK/out" 2>"$WORK/err"
await "$WORK/ready" 'INT readiness'
children "$pid" 'INT children'
kill -INT "$pid"
reap "$pid" 'INT forwarding'
[ "$got" -eq 130 ] || fail 'INT status'
cmp -s "$WORK/server-err" "$WORK/err" || fail 'INT stderr'
gone 'INT leftover'
exec 9>&-
cases=$((cases+1))
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
[ "$(mode "$WORK/log")" = 700 ] && [ "$(mode "$WORK/log/in.jsonl")" = 600 ] && [ "$(mode "$WORK/log/out.jsonl")" = 600 ] || fail modes
cases=$((cases+1))
mkdir "$WORK/loose"
: >"$WORK/loose/in.jsonl"
: >"$WORK/loose/out.jsonl"
chmod 755 "$WORK/loose"
chmod 644 "$WORK/loose/in.jsonl" "$WORK/loose/out.jsonl"
[ "$(mode "$WORK/loose")" = 755 ] && [ "$(mode "$WORK/loose/out.jsonl")" = 644 ] || fail 'loose setup'
MODE='exit' bash "$SHIM" "$WORK/loose" -- bash "$WORK/server" </dev/null >"$WORK/out" 2>"$WORK/err" || fail 'repair run'
[ "$(mode "$WORK/loose")" = 700 ] && [ "$(mode "$WORK/loose/in.jsonl")" = 600 ] && [ "$(mode "$WORK/loose/out.jsonl")" = 600 ] || fail 'mode repair'
cases=$((cases+1))
MARKER=$WORK/eof-append bash "$SHIM" "$WORK/log" -- bash "$WORK/server" <"$WORK/input" >"$WORK/out" 2>"$WORK/err"
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
refused() {
  got=0
  bash "$SHIM" "$1" -- true >"$WORK/out" 2>"$WORK/err" || got=$?
  printf 'mcp-stdio-shim: %s\n' "$2" >"$WORK/refusal"
  [ "$got" -eq 2 ] && [ ! -s "$WORK/out" ] && [ ! -e "$3" ] || fail "path refusal: $1"
  cmp -s "$WORK/refusal" "$WORK/err" || fail "path diagnostic: $1"
}
mkdir -p "$WORK/base/repo/.git" "$WORK/base/repo/sub" "$WORK/dash"
ln -s "$WORK/base/repo/sub" "$WORK/sub-link"
ln -s "$WORK/base/repo/new" "$WORK/dangling"
refused "$WORK/base/missing/../repo/log" 'invalid log directory' "$WORK/base/repo/log"
refused "$WORK/sub-link/new/log" 'log directory is inside a Git work tree' "$WORK/base/repo/sub/new"
refused "$WORK/dangling/log" 'invalid log directory' "$WORK/base/repo/new"
(cd "$WORK/dash" && OLDPWD=$WORK/base/repo bash "$SHIM" - -- true) >"$WORK/out" 2>"$WORK/err" || fail 'dash run'
[ -f "$WORK/dash/-/in.jsonl" ] && [ ! -e "$WORK/base/repo/in.jsonl" ] && [ ! -s "$WORK/err" ] || fail 'dash log dir'
cases=$((cases+1))
mkfifo "$WORK/held"
exec 9<>"$WORK/held"
MODE='exit' bash "$SHIM" "$WORK/unique-log" -- bash "$WORK/server" <"$WORK/held" >"$WORK/out" 2>"$WORK/err" || fail shutdown
exec 9>&-
if pgrep -f "tee -a -- $WORK/unique-log" >/dev/null; then fail 'leftover tee'; fi
cmp -s "$WORK/server-err" "$WORK/err" || fail 'shutdown stderr'
cases=$((cases+1))
{ printf 'first line\n'; head -c 1000000 /dev/zero | tr '\0' y; } >"$WORK/burst"
exec 9<>"$WORK/fifo"
rm -f "$WORK/ready"
STATUS=5 MODE='line' MARKER=$WORK/line READY=$WORK/ready launch "$WORK/burst-log" -- bash "$WORK/server" <"$WORK/fifo" >"$WORK/out" 2>"$WORK/err"
await "$WORK/ready" 'burst readiness'
children "$pid" 'burst children'
cat "$WORK/burst" >&9 &
writer=$!
reap "$pid" 'early exit'
kill "$writer" 2>/dev/null || :
wait "$writer" 2>/dev/null || :
exec 9>&-
size=$(($(wc -c <"$WORK/burst-log/in.jsonl")))
[ "$got" -eq 5 ] && [ "$(cat "$WORK/line")" = 'first line' ] && [ "$size" -ge 11 ] || fail 'early exit'
head -c "$size" "$WORK/burst" | cmp -s - "$WORK/burst-log/in.jsonl" || fail 'early exit input'
cmp -s "$WORK/server-err" "$WORK/err" || fail 'early exit stderr'
gone 'early exit leftover'
cases=$((cases+1))
# A grandchild keeps stdout open after the command exits 3. Exactly one TERM,
# sent while the command runs ("early") or while shutdown waits ("late"),
# must stop the relays.
exec 9<>"$WORK/fifo"
for when in early late; do
  rm -f "$WORK/ready" "$WORK/holder" "$WORK/holder.term"
  STATUS=3 MODE='hold' HOLD=$WORK/clock MARKER=$WORK/holder READY=$WORK/ready launch "$WORK/hold-$when" -- bash "$WORK/server" <"$WORK/fifo" >"$WORK/out" 2>"$WORK/err"
  await "$WORK/holder" "hold readiness $when"
  children "$pid" "hold children $when"
  held=$(cat "$WORK/ready")
  holder=$(cat "$WORK/holder")
  if [ "$when" = early ]; then
    kill -TERM "$pid"
    await "$WORK/holder.term" 'hold forwarding'
  fi
  printf 'go\n' >&9
  for _ in {1..500}; do kill -0 "$held" 2>/dev/null || break; nap 0.01; done
  ! kill -0 "$held" 2>/dev/null || fail "command exit $when"
  kill -0 "$holder" 2>/dev/null || fail "holder $when"
  if [ "$when" = late ]; then
    kill -0 "$pid" 2>/dev/null || fail 'shutdown did not wait'
    kill -TERM "$pid"
  fi
  reap "$pid" "shutdown signal $when"
  [ "$got" -eq 3 ] || fail "shutdown status $when"
  gone "shutdown leftover $when"
  kill -0 "$holder" 2>/dev/null || fail "holder lost $when"
  kill "$holder"
  for _ in {1..500}; do kill -0 "$holder" 2>/dev/null || break; nap 0.01; done
  ! kill -0 "$holder" 2>/dev/null || fail "holder cleanup $when"
done
exec 9>&-
cases=$((cases+1))
# A signal at any point of startup ends the shim with 128 plus its number: by
# the default action before the traps exist, by the shim before the command
# runs, and through the command, which has no traps, after. Only the server's
# stderr line may appear, and no process from the run remains.
exec 9<>"$WORK/fifo"
signals=(TERM INT HUP)
for i in {0..44}; do
  sig=${signals[i % 3]}
  MODE='wait' launch "$WORK/startup-$i" -- bash "$WORK/server" "$WORK/startup-$i/" <"$WORK/fifo" >/dev/null 2>"$WORK/err"
  printf -v delay '0.%03d' "$i"
  nap "$delay"
  kill -s "$sig" "$pid"
  reap "$pid" "startup $sig $i"
  [ "$got" -eq $((128 + $(kill -l "$sig"))) ] || fail "startup status $sig $i"
  [ ! -s "$WORK/err" ] || cmp -s "$WORK/server-err" "$WORK/err" || fail "startup stderr $sig $i"
done
if pgrep -f "$WORK/startup-" >/dev/null; then fail 'startup leftover'; fi
exec 9>&-
cases=$((cases+1))
printf 'mcp-stdio-shim-test: passed (%d cases)\n' "$cases"
