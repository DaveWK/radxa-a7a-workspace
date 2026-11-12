#!/bin/bash
# Cubie A7A UART0 logger: picocom in a detached screen session "a7a-uart",
# 115200 8N1 (A7A_BAUD overrides), logging to <repo>/serial-logs/<timestamp>-<label>.log
# (gitignored: serial logs are never committed).
#
# Usage:
#   scripts/serial-log.sh [label] [device]      start logging (default: run, /dev/ttyUSB0)
#   scripts/serial-log.sh reconcile [device]    show the running session's device, baud and
#                                               log file and compare them with what a start
#                                               would use (exit 0 match, 2 mismatch, 1 none)
#   scripts/serial-log.sh attach                attach to the running session (screen -x)
#
# In the session: detach Ctrl-A d; Ctrl-X Ctrl-Q quits picocom and ends the log.
# Adapted from yy3588-workspace/serial-log.sh.
set -euo pipefail
session=a7a-uart
baud="${A7A_BAUD:-115200}"
default_dev=/dev/ttyUSB0
dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/serial-logs"
hint="attach with: scripts/serial-log.sh attach  (or screen -x $session; detach Ctrl-A d; Ctrl-X Ctrl-Q quits picocom and ends the log)"

# PID of the screen session, empty if none.
session_pid() {
    # screen -ls exits non-zero when there are no sessions at all.
    { screen -ls 2>/dev/null || true; } | sed -n "s/^[[:space:]]*\([0-9]\+\)\.${session}[[:space:]].*/\1/p" | head -n1
}

# Sets run_pid, run_dev, run_baud, run_log from the picocom under the session.
read_running() {
    local spid="$1" pid arg prev=""
    run_pid="" run_dev="" run_baud="" run_log=""
    pid="$(pgrep -P "$spid" -x picocom | head -n1 || true)"
    [ -n "$pid" ] || return 1
    run_pid="$pid"
    while IFS= read -r -d '' arg; do
        case "$prev" in
            -b|--baud) run_baud="$arg" ;;
            --logfile|-g) run_log="$arg" ;;
        esac
        case "$arg" in
            --baud=*) run_baud="${arg#--baud=}" ;;
            --logfile=*) run_log="${arg#--logfile=}" ;;
            /dev/*) run_dev="$arg" ;;
        esac
        prev="$arg"
    done <"/proc/$pid/cmdline"
}

show_running() {
    local spid="$1"
    if ! read_running "$spid"; then
        echo "session $session (pid $spid) is running but has no picocom under it" >&2
        return 1
    fi
    local size="missing"
    [ -f "$run_log" ] && size="$(stat -c %s "$run_log") bytes"
    echo "session $session (screen pid $spid, picocom pid $run_pid)"
    echo "  device:  $run_dev$([ -c "$run_dev" ] || echo '  (NOT PRESENT)')"
    echo "  baud:    $run_baud"
    echo "  log:     $run_log ($size)"
}

case "${1:-}" in
attach)
    [ -n "$(session_pid)" ] || { echo "no $session session running; start one with: scripts/serial-log.sh <label>" >&2; exit 1; }
    exec screen -x "$session"
    ;;
reconcile)
    want_dev="${2:-$default_dev}"
    spid="$(session_pid)"
    [ -n "$spid" ] || { echo "no $session session running" >&2; exit 1; }
    show_running "$spid" || exit 1
    rc=0
    [ "$run_dev" = "$want_dev" ] || { echo "  MISMATCH device: running $run_dev, expected $want_dev"; rc=2; }
    [ "$run_baud" = "$baud" ] || { echo "  MISMATCH baud: running $run_baud, expected $baud"; rc=2; }
    [ "$rc" -eq 0 ] && echo "  matches: $want_dev at $baud"
    echo "$hint"
    exit "$rc"
    ;;
esac

label="${1:-run}"
dev="${2:-$default_dev}"
spid="$(session_pid)"
if [ -n "$spid" ]; then
    echo "already running, not starting another:" >&2
    show_running "$spid" >&2 || true
    echo "$hint" >&2
    exit 1
fi
if [ ! -c "$dev" ]; then
    echo "no serial device $dev (adapter unplugged?); found: $(find /dev -maxdepth 1 \( -name "ttyUSB*" -o -name "ttyACM*" \) -printf "%p ")" >&2
    exit 1
fi
mkdir -p "$dir"
out="$dir/$(date +%Y-%m-%d-%H%M)-$label.log"
# picocom's escape is Ctrl-X so Ctrl-A stays with screen.
screen -dmS "$session" picocom -b "$baud" -e x --logfile "$out" "$dev"
echo "logging $dev at $baud to $out"
echo "$hint"
