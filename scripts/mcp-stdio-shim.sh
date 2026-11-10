#!/usr/bin/env bash
# Usage: mcp-stdio-shim.sh <log-dir> -- <command> [args...]
# Append stdin and stdout bytes to in.jsonl and out.jsonl. TERM, INT, and HUP
# reach the command once it can receive them; earlier, they stop the relays
# and the shim. Bash cannot clean up after SIGKILL: the command and relays
# then outlive the shim. Bytes reach in.jsonl before the command can read
# them. After the command exits, the shim waits for the output relay, then
# stops the input relay; bytes the client writes after the command has exited
# may be missing from in.jsonl. After any TERM, INT, or HUP, it stops both
# relays without waiting, so output still in the pipe may be missing from
# stdout and out.jsonl. The shim exits with the command's status, except when
# a signal arrives as the command exits: then it may exit with 128 plus the
# signal number instead.
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
# Resolve symlinks in the shell itself and restore PWD and OLDPWD.
here=$PWD oldpwd=${OLDPWD-} oldpwd_set=${OLDPWD+1}
cd -P -- "$ancestor" 2>/dev/null || refuse 'invalid log directory'
ancestor=$PWD
cd -- "$here" 2>/dev/null || refuse 'invalid working directory'
if [ -n "$oldpwd_set" ]; then OLDPWD=$oldpwd; else unset OLDPWD; fi
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
# Until the traps exist, a signal kills the shim, so it starts only processes
# that end with it: commands it waits for with the wait builtin (Bash ignores
# an untrapped SIGINT while it waits for a foreground command that exits
# normally), the output relay, and the gate.
umask 077
mkdir -p -- "$log_dir" & wait "$!"
chmod 700 "$log_dir" & wait "$!"
in=$log_dir/in.jsonl
out=$log_dir/out.jsonl
: >>"$in"
: >>"$out"
chmod 600 "$in" "$out" & wait "$!"
gnu_tee=0
tee --version >/dev/null 2>&1 & if wait "$!"; then gnu_tee=1; fi
# Relays ignore SIGPIPE, so a closed peer leaves the log file written, and
# their own diagnostics never reach the client. The output relay ends when the
# shim's end of its pipe closes.
exec 3> >(trap '' PIPE; exec 2>/dev/null; exec tee -a -- "$out")
out_pid=$!
# An asynchronous subshell ignores SIGINT and SIGQUIT, and loses a signal that
# arrives before exec while its traps reset; "trap - INT" leaves a Bash handler
# until exec. A fresh Bash, with both at their defaults, closes fd 5 to end the
# gate and runs the command; signals wait until then.
exec 5> >(exec 3>&-; read -r || :)
gate=$!
signal='' child='' ready=0 interrupted=0 stopped=0 vanished=0 pids=("$out_pid" "$gate")
# Invoked by signal traps. A signal is recorded before the command is ready,
# forwarded while it runs, and stops the relays once it has exited; stopped is
# never cleared, so shutdown also acts on a signal from before it began.
# shellcheck disable=SC2329
on_signal() {
  interrupted=1 stopped=1
  case $ready in
    0) signal=$1 ;;
    1) kill -s "$1" "$child" 2>/dev/null || vanished=1 ;;
    *) kill "$out_pid" "$in_pid" 2>/dev/null || : ;;
  esac
}
# From here on the shim expands no process or command substitution: Bash 5.2
# can run a pending trap inside that expansion and then fail to parse it.
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP
# Wait for a process only while it exists: Bash 5.2 can lose one that exits as
# a signal interrupts wait, and a later wait for it never returns.
reap() {
  local s
  while kill -0 "$1" 2>/dev/null; do
    s=0
    wait "$1" 2>/dev/null || s=$?
    [ "$s" -gt 128 ] || return 0
  done
}
# Before the command starts, a signal stops what has started and exits.
stop_if_signaled() {
  [ -n "$signal" ] || return 0
  exec 3>&- 4<&- 5>&-
  # SIGKILL, since a TERM can be lost while a new process resets its traps.
  for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || :; done
  for pid in "${pids[@]}"; do reap "$pid"; done
  case $signal in HUP) exit 129 ;; INT) exit 130 ;; *) exit 143 ;; esac
}
stop_if_signaled
# Bash reports a job killed by an untrapped signal on its own stderr whenever
# it reaps it, so the shim's stderr becomes /dev/null and the command gets the
# original on fd 2.
exec 7>&2 2>/dev/null
# The input relay is a coprocess, which needs no substitution. Bash closes a
# coprocess's pipes once it exits, so the relay waits for EOF on its own stdin
# until the shim holds its output. GNU tee writes standard output first and
# BSD tee last, so each branch writes in.jsonl before the command's pipe.
exec 8<&0
coproc RELAY {
  trap '' PIPE
  exec 3>&- 5>&- 7>&- 2>/dev/null
  read -r || :
  [ "$gnu_tee" -eq 0 ] || exec tee -a -- "$in" /dev/fd/6 6>&1 >/dev/null <&8 8<&-
  exec tee -a -- "$in" <&8 8<&-
}
in_pid=$RELAY_PID r=${RELAY[0]} w=${RELAY[1]}
pids+=("$in_pid")
exec 4<&"$r" {r}<&- {w}>&- 8<&-
stop_if_signaled
( trap - INT QUIT; exec "$BASH" -c 'exec 5>&-; exec "$@"' mcp-stdio-shim "$@" ) <&4 >&3 2>&7 3>&- 4<&- 7>&- &
child=$!
exec 3>&- 4<&- 5>&- 7>&-
reap "$gate"
ready=1
[ -z "$signal" ] || kill -s "$signal" "$child" 2>/dev/null || :
while :; do
  interrupted=0
  status=0
  wait "$child" 2>/dev/null || status=$?
  # If the command was gone when the handler signaled it, its status may be
  # lost; keep 128 plus the signal number instead of waiting again.
  [ "$interrupted" -eq 1 ] && [ "$vanished" -eq 0 ] || break
done
ready=2
[ "$stopped" -eq 0 ] || kill "$out_pid" "$in_pid" 2>/dev/null || :
reap "$out_pid"
kill "$in_pid" 2>/dev/null || :
reap "$in_pid"
exit "$status"
