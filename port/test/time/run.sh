#!/usr/bin/env bash
# port/test/time/run.sh -- differential for the kernel/time/time.c conversions at CONFIG_HZ = 100, 250, 300, 1000.
#   run.sh [--sabotage]   (sabotage mutates the Rust and runs it at HZ 300 and 1000, the two that take different arms)
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/time"
out="${TMPDIR:-/tmp}/timetest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${TIME_RS:-$root/port/tree/kernel/time/time_rs.rs}"
C="$root/port/pristine/kernel/time/time.c"
for f in "$RS" "$C" "$root/src/linux/kernel/time/timeconst.bc"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$root/src/linux" "$C" "$out/ref.c"
REN=""
for fn in jiffies_to_msecs jiffies_to_usecs mktime64 ns_to_kernel_old_timeval set_normalized_timespec64 ns_to_timespec64 __msecs_to_jiffies \
          __usecs_to_jiffies timespec64_to_jiffies jiffies_to_timespec64 jiffies_to_clock_t clock_t_to_jiffies jiffies64_to_nsecs jiffies64_to_msecs \
          nsecs_to_jiffies64 nsecs_to_jiffies timespec64_add_safe; do REN="$REN -D$fn=c_$fn"; done
build() {   # build <rs> <dir> <hz>
    mkdir -p "$2/gen"
    echo "$3" | bc -q "$root/src/linux/kernel/time/timeconst.bc" > "$2/gen/timeconst.h"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        --cfg "CONFIG_HZ=\"$3\"" -D unsafe_op_in_unsafe_fn -D warnings --crate-name time_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -DHZ=$3 -I "$here/shim" -I "$2/gen" -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
for hz in 100 250 300 1000; do build "$RS" "$out/hz$hz" $hz; done
echo "prove-can-fail:"
if TIME_PROVE_CAN_FAIL=1 TIME_N=200000 "$out/hz250/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        ok=1
        for hz in 300 1000 250; do
            build "$out/mut.rs" "$out/m${n}_$hz" $hz >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
            if ! TIME_N=400000 timeout 300 "$out/m${n}_$hz/t" 0 >/dev/null 2>&1; then ok=0; break; fi
        done
        if [ $ok = 1 ]; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
msec-per-sec~const MSEC_PER_SEC: i64 = 1000;~const MSEC_PER_SEC: i64 = 1001;
tick-nsec~const TICK_NSEC: i64 = (NSEC_PER_SEC + HZ / 2) / HZ;~const TICK_NSEC: i64 = (NSEC_PER_SEC + HZ / 2 + 1) / HZ;
jiff-msec-300~j.wrapping_mul(HZ_TO_MSEC_NUM).wrapping_add(HZ_TO_MSEC_DEN - 1) / HZ_TO_MSEC_DEN~j.wrapping_mul(HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN
jiff-usec-300~(j.wrapping_mul(HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN) as u32~(j.wrapping_mul(HZ_TO_USEC_NUM).wrapping_add(1) / HZ_TO_USEC_DEN) as u32
jiff-msec-direct~((MSEC_PER_SEC / HZ) as u64).wrapping_mul(j) as u32~((MSEC_PER_SEC / HZ) as u64).wrapping_mul(j).wrapping_add(1) as u32
mk-mon~mon = mon.wrapping_sub(2);~mon = mon.wrapping_sub(3);
mk-year~year = year.wrapping_sub(1);~year = year.wrapping_sub(2);
mk-cond~if 0 >= mon as i32 {~if 0 > mon as i32 {
mk-367~367u32.wrapping_mul(mon) / 12~367u32.wrapping_mul(mon) / 13
mk-719499~.wrapping_sub(719499)~.wrapping_sub(719498)
mk-hour~.wrapping_add(hour as i64)) /* now have hours~.wrapping_add(hour as i64 + 1)) /* now have hours
mk-div400~.wrapping_add(year / 400)~.wrapping_add(year / 401)
kot-div~tv_usec: ts.tv_nsec / 1000~tv_usec: ts.tv_nsec / 1001
norm-up~sec = sec.wrapping_add(1);~sec = sec.wrapping_add(2);
norm-down~sec = sec.wrapping_sub(1);~sec = sec.wrapping_sub(2);
norm-cond~while nsec >= NSEC_PER_SEC {~while nsec > NSEC_PER_SEC {
ns2ts-pos~ts.tv_nsec = ((nsec as u64) % NSEC_PER_SEC as u64) as u32 as c_long;~ts.tv_nsec = ((nsec as u64) % NSEC_PER_SEC as u64) as u32 as c_long + 1;
ns2ts-neg-sec~ts.tv_sec = q.wrapping_neg().wrapping_sub(1);~ts.tv_sec = q.wrapping_neg();
ns2ts-neg-ns~(NSEC_PER_SEC as u32).wrapping_sub(rem).wrapping_sub(1) as c_long~(NSEC_PER_SEC as u32).wrapping_sub(rem) as c_long
msec-neg~if (m as i32) < 0 {~if (m as i32) < -1 {
msec-300~(MSEC_TO_HZ_MUL32.wrapping_mul(m as u64).wrapping_add(MSEC_TO_HZ_ADJ32)) >> MSEC_TO_HZ_SHR32~(MSEC_TO_HZ_MUL32.wrapping_mul(m as u64).wrapping_add(MSEC_TO_HZ_ADJ32)) >> (MSEC_TO_HZ_SHR32 + 1)
msec-direct~((m as i64 + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ)) as u64~((m as i64 + (MSEC_PER_SEC / HZ)) / (MSEC_PER_SEC / HZ)) as u64
usec-cond~if u > jiffies_to_usecs(MAX_JIFFY_OFFSET) {~if u >= jiffies_to_usecs(MAX_JIFFY_OFFSET) {
usec-300~(USEC_TO_HZ_MUL32.wrapping_mul(u as u64).wrapping_add(USEC_TO_HZ_ADJ32)) >> USEC_TO_HZ_SHR32~(USEC_TO_HZ_MUL32.wrapping_mul(u as u64).wrapping_add(USEC_TO_HZ_ADJ32)) >> (USEC_TO_HZ_SHR32 - 1)
usec-direct~((u as i64 + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ)) as u64~((u as i64 + (USEC_PER_SEC / HZ) - 2) / (USEC_PER_SEC / HZ)) as u64
ts2j-max~if sec >= MAX_SEC_IN_JIFFIES as u64 {~if sec > MAX_SEC_IN_JIFFIES as u64 {
ts2j-nsec~let mut nsec: i64 = unsafe { (*value).tv_nsec }.wrapping_add(TICK_NSEC).wrapping_sub(1);~let mut nsec: i64 = unsafe { (*value).tv_nsec }.wrapping_add(TICK_NSEC);
ts2j-sc~>> (NSEC_JIFFIE_SC - SEC_JIFFIE_SC)))~>> (NSEC_JIFFIE_SC - SEC_JIFFIE_SC - 1)))
sc-bump~if ((((NSEC_PER_SEC << 2) / TICK_NSEC) << (sc - 2)) & 0x80000000) == 0 {~if ((((NSEC_PER_SEC << 2) / TICK_NSEC) << (sc - 2)) & 0x80000000) != 0 {
shdiv~((nom / den) << lsh) + ((((nom % den) << lsh) + den / 2) / den)~((nom / den) << lsh) + ((((nom % den) << lsh) + den / 2 + 1) / den)
max-sec~SEC_JIFFIE_SC) * TICK_NSEC, NSEC_PER_SEC, 1) - 1~SEC_JIFFIE_SC) * TICK_NSEC, NSEC_PER_SEC, 1)
j2ts~let ns = jiffies.wrapping_mul(TICK_NSEC as u64);~let ns = jiffies.wrapping_mul(TICK_NSEC as u64 + 1);
clock-300~(x.wrapping_mul(TICK_NSEC as u64) / (NSEC_PER_SEC / USER_HZ) as u64) as c_long~(x.wrapping_mul(TICK_NSEC as u64) / (NSEC_PER_SEC / USER_HZ + 1) as u64) as c_long
clock-eq~(x / (HZ / USER_HZ) as u64) as c_long~(x / (HZ / USER_HZ + 1) as u64) as c_long
c2j-limit~if x >= !0u64 / (HZ / USER_HZ) as u64 {~if x > !0u64 / (HZ / USER_HZ) as u64 {
c2j-250~if x >= !0u64 / HZ as u64 * USER_HZ as u64 {~if x >= !0u64 / HZ as u64 * USER_HZ as u64 + 1 {
c2j-div~x.wrapping_mul(HZ as u64) / USER_HZ as u64~x.wrapping_mul(HZ as u64) / (USER_HZ as u64 + 1)
j64ns~((NSEC_PER_SEC / HZ) as u64).wrapping_mul(j)~((NSEC_PER_SEC / HZ) as u64 + 1).wrapping_mul(j)
j64ns-300~j.wrapping_mul(HZ_TO_NSEC_NUM) / HZ_TO_NSEC_DEN~j.wrapping_mul(HZ_TO_NSEC_NUM) / (HZ_TO_NSEC_DEN + 1)
j64ms-300~j.wrapping_mul(HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN~j.wrapping_mul(HZ_TO_MSEC_NUM) / (HZ_TO_MSEC_DEN + 1)
n2j-div~n / (NSEC_PER_SEC / HZ) as u64~n / (NSEC_PER_SEC / HZ + 1) as u64
n2j-300~n.wrapping_mul(9) / ((9u64 * NSEC_PER_SEC as u64 + HZ as u64 / 2) / HZ as u64)~n.wrapping_mul(9) / ((9u64 * NSEC_PER_SEC as u64) / HZ as u64)
add-sat~if res.tv_sec < lhs.tv_sec || res.tv_sec < rhs.tv_sec {~if res.tv_sec < lhs.tv_sec {
add-nsec~lhs.tv_nsec.wrapping_add(rhs.tv_nsec),~lhs.tv_nsec,
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential (HZ 100, 250, 300, 1000):"
rc=0
for hz in 100 250 300 1000; do echo "HZ=$hz"; runall "$out/hz$hz/t" || rc=1; done
[ $rc = 0 ] && echo PASS
exit $rc
