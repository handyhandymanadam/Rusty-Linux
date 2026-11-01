#!/usr/bin/env bash
# gate.sh <fast|full>
# The tier-2/3 gate (build + boot + crc-check) with a stopwatch.
# Appends one row per step to logs/gate-times.md: seconds for the step, and
# "gap" = seconds since the previous step of ANY gate ended (the review/rework
# time between steps). Earned by Adam's 2026-10-24 ask: find where the hours go.
# Reports each step's exit status; a failed step stops the gate.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
cfg=${1:?usage: gate.sh <fast|full>}
b="build-$cfg"
log="$root/logs/gate-times.md"
last="$root/logs/.gate-last"   # epoch of previous step end (untracked)
source "$root/kbuild-env.sh" >/dev/null
cd "$root" || exit 2
[ -f "$log" ] || printf '| date | config | step | seconds | gap before (s) | exit |\n|---|---|---|---|---|---|\n' > "$log"
step() {  # step <name> <logfile> <cmd...>
    local name=$1 lf=$2; shift 2
    local t0 prev gap t1 rc
    t0=$(date +%s); prev=$(cat "$last" 2>/dev/null || echo "$t0"); gap=$((t0 - prev))
    "$@" > "$lf" 2>&1; rc=$?
    t1=$(date +%s); echo "$t1" > "$last"
    printf '| %s | %s | %s | %d | %d | %d |\n' "$(date +%F\ %H:%M)" "$cfg" "$name" "$((t1 - t0))" "$gap" "$rc" >> "$log"
    echo "[gate] $cfg $name: $((t1 - t0)) s, exit $rc (gap before: $gap s)"
    return $rc
}
step build "$root/logs/gate-$cfg-build.log" kmake O="$root/$b" -j"$(nproc)" && \
step boot  "$root/logs/gate-$cfg-boot.log"  "$root/rig/boot.sh" "$root/$b" && \
step crc   "$root/logs/gate-$cfg-crc.log"   "$root/rig/crc-check.sh" "$root/$b"
