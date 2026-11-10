#!/usr/bin/env bash
# Usage: mcp-stdio-shim.sh <log-dir> -- <command> [args...]
# Append stdin and stdout bytes to in.jsonl and out.jsonl. TERM, INT, and HUP
# reach the command once it can receive them; earlier, they stop the relays
# and the shim. Bash cannot clean up after SIGKILL: the command and relays
# then outlive the shim. Bytes reach in.jsonl before the command can read
# them. After the command exits, the shim waits for the output relay, then
# stops the input relay; bytes the client writes after the command has exited
# may be missing from in.jsonl.
set -euo pipefail

refuse() { printf 'mcp-stdio-shim: %s\n' "$1" >&2; exit 2; }
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  refuse 'Bash 4.4 or newer is required'
fi
[ "$#" -ge 3 ] && [ -n "$1" ] && [ "$2" = -- ] && [ -n "$3" ] || refuse 'invalid usage'
log_dir=$1
shift 2
# A ".." component could leave the checked ancestor. A "./" prefix keeps cd
# from reading "-" as OLDPWD or a relative path from CDPATH.
case /$log_dir/ in */../*) refuse 'invalid log directory' ;; esac
case $log_dir in /*) ;; *) log_dir=./$log_dir ;; esac
ancestor=$log_dir
missing=''
while [ ! -d "$ancestor" ]; do
  [ ! -e "$ancestor" ] && [ ! -L "$ancestor" ] || refuse 'invalid log directory'
  parent=${ancestor%/*}
  [ "$parent" != "$ancestor" ] || refuse 'invalid log directory'
  missing=/${ancestor##*/}$missing
  ancestor=${parent:-/}
done
ancestor=$(cd -P -- "$ancestor" && pwd -P) || refuse 'invalid log directory'
# The created part holds no symlink, so this is the physical path. It is
# absolute, which keeps BSD chmod, which rejects "--", from reading a leading
# "-" as an option.
log_dir=${ancestor%/}$missing
log_dir=${log_dir:-/}
while :; do
  [ ! -e "$ancestor/.git" ] && [ ! -L "$ancestor/.git" ] || refuse 'log directory is inside a Git work tree'
  [ "$ancestor" != / ] || break
  ancestor=${ancestor%/*}
  [ -n "$ancestor" ] || ancestor=/
done
signal='' child='' ready=0 interrupted=0 pids=()
# Invoked by signal traps.
# shellcheck disable=SC2329
on_signal() {
  interrupted=1
  if [ "$ready" -eq 1 ]; then kill -s "$1" "$child" 2>/dev/null || :; else signal=$1; fi
}
# Bash drops a trapped SIGINT that arrives while it waits for a command
# substitution, so the traps start after the last one; nothing exists yet.
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP
# Before the command starts, a signal stops what has started and exits.
stop_if_signaled() {
  [ -n "$signal" ] || return 0
  exec 3>&- 4<&- 5>&-
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || :; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || :; done
  exit $((128 + $(kill -l "$signal")))
}
umask 077
mkdir -p -- "$log_dir"
chmod 700 "$log_dir"
in=$log_dir/in.jsonl
out=$log_dir/out.jsonl
: >>"$in"
: >>"$out"
chmod 600 "$in" "$out"
gnu_tee=0
if tee --version >/dev/null 2>&1; then gnu_tee=1; fi
stop_if_signaled
# Relays ignore SIGPIPE, so a closed peer leaves the log file written, and
# their own diagnostics never reach the client.
exec 3> >(trap '' PIPE; exec 2>/dev/null; exec tee -a -- "$out")
out_pid=$!
pids+=("$out_pid")
stop_if_signaled
# GNU tee writes standard output first and BSD tee last, so each branch writes
# in.jsonl before the command's pipe.
if [ "$gnu_tee" -eq 1 ]; then
  exec 4< <(trap '' PIPE; exec 3>&- 2>/dev/null 6>&1 >/dev/null; exec tee -a -- "$in" /dev/fd/6)
else
  exec 4< <(trap '' PIPE; exec 3>&- 2>/dev/null; exec tee -a -- "$in")
fi
in_pid=$!
pids+=("$in_pid")
stop_if_signaled
# An asynchronous subshell ignores SIGINT and SIGQUIT, and loses a signal that
# arrives before exec while its traps reset; "trap - INT" leaves a Bash handler
# until exec. A fresh Bash, with both at their defaults, closes fd 5 to end the
# gate and runs the command; signals wait until then.
exec 5> >(exec 3>&- 4<&-; read -r || :)
gate=$!
pids+=("$gate")
stop_if_signaled
( trap - INT QUIT; exec "$BASH" -c 'exec 5>&-; exec "$@"' mcp-stdio-shim "$@" ) <&4 >&3 3>&- 4<&- &
child=$!
exec 3>&- 4<&- 5>&-
while :; do
  interrupted=0
  wait "$gate" 2>/dev/null || :
  [ "$interrupted" -eq 1 ] || break
done
ready=1
[ -z "$signal" ] || kill -s "$signal" "$child" 2>/dev/null || :
# Redirected waits keep Bash from reporting a command killed by a signal.
while :; do
  interrupted=0
  status=0
  wait "$child" 2>/dev/null || status=$?
  [ "$interrupted" -eq 1 ] || break
done
# Once the command has exited, a signal also stops the output relay.
ready=0
while :; do
  interrupted=0
  wait "$out_pid" 2>/dev/null || :
  [ "$interrupted" -eq 1 ] || break
  kill "$out_pid" 2>/dev/null || :
done
kill "$in_pid" 2>/dev/null || :
wait "$in_pid" 2>/dev/null || :
exit "$status"
