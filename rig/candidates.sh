#!/usr/bin/env bash
# candidates.sh -- compute the port candidate set from notes/GOALS.md §8's rule.
#
# The rule: everything in lib/ that is a SELF-CONTAINED ALGORITHM OVER BUFFERS,
# at any depth. Excludes code reaching into sched/mm/fs/device/per-CPU state,
# because the acceptance loop cannot test it. Excludes tests and shims.
#
# This is a HEURISTIC applied by script, not a proof. Its value is that it is
# uniform, re-runnable, and its rule is visible here rather than living in
# somebody's head -- the previous count of 79 was hand-scoped, top-level only,
# and silently dropped every decompressor.
#
# Usage: candidates.sh [--list | --excluded]
set -u
LIB=/home/adam/Rusty-Linux/src/linux/lib
cd "$LIB" || exit 1

# Coupling markers. A file mentioning any of these is reaching outside a buffer.
COUPLED='task_struct|current->|\bsched_|\bcpu_online|get_cpu\(|put_cpu\(|\bper_cpu|\bDEFINE_PER_CPU|\bkmalloc|\bkfree|\bvmalloc|\bmempool_|\balloc_pages|\bstruct page\b|\bfile_operations|\bplatform_device|\bstruct device\b|\bdebugfs_|\bproc_create|\bsysfs_|\bmodule_init|\brequest_irq|\bmutex_lock|\bspin_lock|\bwait_event|\bschedule\(\)'

# Test modules, benchmarks, fault injection and the kunit harness itself.
is_test() {
    case "$1" in
        test_*|*/test_*|*_test.c|*-test.c|*_kunit.c|*kunit*|tests/*|test_fortify/*) return 0 ;;
    esac
    grep -qE '#include <kunit/|MODULE_LICENSE.*\bTEST\b' "$1" 2>/dev/null
}

inc=(); exc=()
while IFS= read -r f; do
    if is_test "$f"; then exc+=("$f  [test]"); continue; fi
    if grep -qE "$COUPLED" "$f"; then exc+=("$f  [coupled]"); continue; fi
    inc+=("$f")
done < <(find . -name '*.c' | sed 's|^\./||' | sort)

case "${1:---count}" in
    --list)     printf '%s\n' "${inc[@]}" ;;
    --excluded) printf '%s\n' "${exc[@]}" ;;
    *)
        echo "candidate set, per notes/GOALS.md §8, computed $(date +%Y-%m-%d)"
        echo "  tree            $(readlink -f "$LIB")"
        echo "  all lib/*.c     $(find . -name '*.c' | wc -l)  (recursive)"
        echo "  candidates      ${#inc[@]}"
        echo "  excluded        ${#exc[@]}"
        echo
        echo "  candidate lines $(printf '%s\n' "${inc[@]}" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')"
        echo
        echo "  by directory:"
        printf '%s\n' "${inc[@]}" | sed 's|/[^/]*$||;s|^[^/]*\.c$|(top level)|' | sort | uniq -c | sort -rn | sed 's/^/    /'
        ;;
esac
