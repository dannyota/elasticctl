#!/usr/bin/env bash
# Usage: mcp-stdio-shim.sh <log-dir> -- <command> [args...]
# Append stdin and stdout bytes to in.jsonl and out.jsonl.
set -euo pipefail

refuse() { printf 'mcp-stdio-shim: %s\n' "$1" >&2; exit 2; }
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  refuse 'Bash 4.4 or newer is required'
fi
[ "$#" -ge 3 ] && [ -n "$1" ] && [ "$2" = -- ] && [ -n "$3" ] || refuse 'invalid usage'
log_dir=$1
shift 2
ancestor=$log_dir
while [ ! -d "$ancestor" ]; do
  [ ! -e "$ancestor" ] || refuse 'invalid log directory'
  parent=$(dirname -- "$ancestor")
  [ "$parent" != "$ancestor" ] || refuse 'invalid log directory'
  ancestor=$parent
done
ancestor=$(cd -P -- "$ancestor" && pwd -P) || refuse 'invalid log directory'
while :; do
  [ ! -e "$ancestor/.git" ] && [ ! -L "$ancestor/.git" ] || refuse 'log directory is inside a Git work tree'
  [ "$ancestor" != / ] || break
  ancestor=${ancestor%/*}
  [ -n "$ancestor" ] || ancestor=/
done
umask 077
mkdir -p -- "$log_dir"
# An absolute path keeps BSD chmod, which rejects "--", from reading a
# leading "-" as an option.
log_dir=$(cd -P -- "$log_dir" && pwd -P)
chmod 700 "$log_dir"
in=$log_dir/in.jsonl
out=$log_dir/out.jsonl
: >>"$in"
: >>"$out"
chmod 600 "$in" "$out"
exec 3> >(exec tee -a -- "$out")
out_pid=$!
exec 4< <(exec 3>&-; exec tee -a -- "$in")
in_pid=$!
"$@" <&4 >&3 3>&- 4<&- &
child=$!
exec 3>&- 4<&-
interrupted=0
# Invoked by signal traps.
# shellcheck disable=SC2329
forward() { interrupted=1; kill -s "$1" "$child" 2>/dev/null || :; }
trap 'forward TERM' TERM
trap 'forward INT' INT
trap 'forward HUP' HUP
while :; do
  interrupted=0
  status=0
  wait "$child" || status=$?
  [ "$interrupted" -eq 0 ] && break
done
trap '' TERM INT HUP
wait "$out_pid" || :
kill "$in_pid" 2>/dev/null || :
wait "$in_pid" 2>/dev/null || :
exit "$status"
