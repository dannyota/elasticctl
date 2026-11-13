#!/usr/bin/env bash
set -euo pipefail

refuse() { printf 'mcp-stdio-shim: %s\n' "$1" >&2; exit 2; }
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  refuse 'Bash 4.4 or newer is required'
fi
[ "$#" -ge 3 ] && [ -n "$1" ] && [ "$2" = -- ] && [ -n "$3" ] || refuse 'invalid usage'
log_dir=$1
shift 2
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
here=$PWD oldpwd=${OLDPWD-} oldpwd_set=${OLDPWD+1}
cd -P -- "$ancestor" 2>/dev/null || refuse 'invalid log directory'
ancestor=$PWD
cd -- "$here" 2>/dev/null || refuse 'invalid working directory'
if [ -n "$oldpwd_set" ]; then OLDPWD=$oldpwd; else unset OLDPWD; fi
log_dir=${ancestor%/}$missing
log_dir=${log_dir:-/}
while :; do
  [ ! -e "$ancestor/.git" ] && [ ! -L "$ancestor/.git" ] || refuse 'log directory is inside a Git work tree'
  [ "$ancestor" != / ] || break
  ancestor=${ancestor%/*}
  [ -n "$ancestor" ] || ancestor=/
done
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
exec 3> >(trap '' PIPE; exec 2>/dev/null; exec tee -a -- "$out")
out_pid=$!
exec 5> >(exec 3>&-; read -r || :)
gate=$!
signal='' child='' ready=0 interrupted=0 stopped=0 vanished=0 pids=("$out_pid" "$gate")
# shellcheck disable=SC2329
on_signal() {
  interrupted=1 stopped=1
  case $ready in
    0) signal=$1 ;;
    1) kill -s "$1" "$child" 2>/dev/null || vanished=1 ;;
    *) kill "$out_pid" "$in_pid" 2>/dev/null || : ;;
  esac
}
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap 'on_signal HUP' HUP
reap() {
  local s
  while kill -0 "$1" 2>/dev/null; do
    s=0
    wait "$1" 2>/dev/null || s=$?
    [ "$s" -gt 128 ] || return 0
  done
}
stop_if_signaled() {
  [ -n "$signal" ] || return 0
  exec 3>&- 4<&- 5>&-
  for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || :; done
  for pid in "${pids[@]}"; do reap "$pid"; done
  case $signal in HUP) exit 129 ;; INT) exit 130 ;; *) exit 143 ;; esac
}
stop_if_signaled
exec 7>&2 2>/dev/null
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
  [ "$interrupted" -eq 1 ] && [ "$vanished" -eq 0 ] || break
done
ready=2
[ "$stopped" -eq 0 ] || kill "$out_pid" "$in_pid" 2>/dev/null || :
reap "$out_pid"
kill "$in_pid" 2>/dev/null || :
reap "$in_pid"
exit "$status"
