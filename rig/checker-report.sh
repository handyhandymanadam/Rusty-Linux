#!/usr/bin/env bash
# checker-report.sh <serial-log> [expect]
#
# Reads a serial log from a checker build (configs/chk-ka, chk-kc; logs/concurrency-tooling.md) and
# reports what it READ: counts of each kernel-checker report, the libstress and libtest lines, and
# whether userspace finished. Launches nothing; it only reads a log.
#   no 2nd arg : exit 0 only if userspace completed AND zero checker reports AND no libstress failure
#   expect     : exit 0 only if at least one checker report OR a libstress failure is present
#                (a sabotage or probe run: the harness MUST be able to fail)
set -u
L=${1:?usage: checker-report.sh <log> [expect]}
[ -s "$L" ] || { echo "empty or missing log: $L"; exit 2; }
n() { grep -cE "$1" "$L"; }
declare -A pat=(
  [lockdep]='WARNING: possible (circular|recursive) locking|possible irq lock inversion|inconsistent .* lock state|WARNING: bad unlock balance|BUG: (held lock|MAX_LOCK)|lockdep: (debug_locks|.*disabled)|INFO: trying to register non-static key'
  [atomic-sleep]='BUG: (sleeping function|scheduling while atomic)'
  [rcu]='suspicious RCU usage|WARNING: suspicious RCU|rcu_sched (detected|self-detected) stall|rcu: INFO: .* stall'
  [kasan]='BUG: KASAN'
  [kcsan]='BUG: KCSAN'
  [other]='^\[[ 0-9.]*\] (WARNING:|BUG:|Oops|Kernel panic)|general protection fault'
)
total=0
echo "checker report for $L"
for k in lockdep atomic-sleep rcu kasan kcsan other; do
  c=$(n "${pat[$k]}"); printf '  %-13s %s\n' "$k" "$c"
  # 'other' double counts the specific ones; only the specific ones sum to the total, plus other-only lines
  [ "$k" != other ] && total=$((total+c))
done
# libtest's test_bug()/warn_once_helper() trigger WARN on purpose (they test the ported WARN path): not reports.
other_only=$(grep -E "${pat[other]}" "$L" | grep -vE 'WARNING: CPU: [0-9]+ PID: [0-9]+ at lib/libtest\.c:[0-9]+ (test_bug|warn_once_helper)' | grep -vcE "BUG: (KASAN|KCSAN|sleeping function|scheduling while atomic|held lock|MAX_LOCK)")
printf '  %-13s %s\n' "other-only" "$other_only"; total=$((total+other_only))
echo "  kcsan-selftest: $(grep -oE 'kcsan: selftest:.*' "$L" | tail -1)"
grep -E 'libstress:' "$L" | sed 's/^/  /'
grep -oE 'libtest: [0-9]+ self-tests passed, [0-9]+ failed' "$L" | tail -1 | sed 's/^/  /'
done_=$(n 'RIG: done'); printf '  userspace     %s\n' "$([ "$done_" -gt 0 ] && echo completed || echo 'DID NOT COMPLETE')"
sf=$(grep -cE 'libstress: [0-9]+ passed, [1-9][0-9]* failed' "$L")
printf '  total-reports %s   libstress-failed-lines %s\n' "$total" "$sf"
if [ "${2:-}" = expect ]; then
  [ $((total+sf)) -gt 0 ] && { echo "  EXPECTED FAILURE PRESENT (the harness can fail)"; exit 0; }
  echo "  NO REPORT AND NO STRESS FAILURE -- the sabotage/probe was NOT detected"; exit 1
fi
[ "$done_" -gt 0 ] && [ "$total" -eq 0 ] && [ "$sf" -eq 0 ]
