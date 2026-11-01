#!/usr/bin/env bash
# port/test/rcuref/bar.sh -- the concurrency-bar campaign for lib/rcuref.c (logs/concurrency-bar.md item 4):
# N boots of the libstress "rcuref" target on the KASAN build of the Rust port, N boots on the KASAN build of the C control
# (CONFIG_RUST=n, upstream rcuref.c), and S sabotage boots (readers use an object 30 ms after a lookup with no RCU read lock)
# that MUST fail.   bar.sh [N] [S]      logs: logs/bar/rcuref-{r,c,s}-<i>.log
set -u
root=$(cd "$(dirname "$0")/../../.." && pwd); cd "$root"
N=${1:-20}; S=${2:-3}
boot() {   # boot <build> <tag> <i> <extra append>
    BZ_LOG="logs/bar/rcuref-$2-$3.log" BOOT_SMP=4 BOOT_MEM=2048 BZ_APPEND="libstress.run=10 libstress.target=rcuref $4" ./rig/boot-cmdline.sh "$1" 600 >/dev/null 2>&1
}
rpass=0; cpass=0; sfail=0
for i in $(seq 1 "$N"); do
    boot build-chk-kasan r "$i" ""; ./rig/checker-report.sh "logs/bar/rcuref-r-$i.log" >/dev/null 2>&1 && rpass=$((rpass+1))
    boot build-chk-kasan-c c "$i" ""; ./rig/checker-report.sh "logs/bar/rcuref-c-$i.log" >/dev/null 2>&1 && cpass=$((cpass+1))
    echo "after $i: rust clean $rpass/$i, control clean $cpass/$i"
done
for i in $(seq 1 "$S"); do
    boot build-chk-kasan s "$i" "libstress.sabotage=1"; ./rig/checker-report.sh "logs/bar/rcuref-s-$i.log" expect >/dev/null 2>&1 && sfail=$((sfail+1))
    echo "sabotage $i: caught $sfail/$i"
done
echo "RESULT rust $rpass/$N clean, control $cpass/$N clean, sabotage $sfail/$S failed as required"
touch logs/bar/rcuref-done
