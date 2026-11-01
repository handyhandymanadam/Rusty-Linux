#!/usr/bin/env bash
# port/test/timeconv/run.sh -- differential for kernel/time/timeconv.c (time64_to_tm).
#   run.sh             full run (8 shards)
#   run.sh --sabotage  prove the harness fails on mutants of the Rust
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/timeconv"
out="${TMPDIR:-/tmp}/timeconv.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${TIMECONV_RS:-$root/port/tree/kernel/time/timeconv_rs.rs}"
C="$root/port/pristine/kernel/time/timeconv.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name timeconv_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -Dtime64_to_tm=c_time64_to_tm -I "$here/shim" -DTIMECONV_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" 8 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if TIMECONV_PROVE_CAN_FAIL=1 TIMECONV_DAYS=400 TIMECONV_NRAND=10 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if TIMECONV_DAYS=3000000 TIMECONV_NRAND=3000000 timeout 300 "$out/m$n/t" 0 1 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
secs-per-hour~const SECS_PER_HOUR: i64 = 60 * 60;~const SECS_PER_HOUR: i64 = 60 * 61;
wday-base~(4i64.wrapping_add(days)) % 7~(5i64.wrapping_add(days)) % 7
wday-neg~result.tm_wday += 7;~result.tm_wday += 6;
epoch-const~2305843009213814918u64~2305843009213814919u64
century~146097~146096
leap-century~century % 4 == 0~century % 4 == 1
leap-year~year_of_century % 4 == 0~year_of_century % 4 == 1
doy-div~/ 2939745 / 4;~/ 2939745 / 5;
month-const~132377~132378
day-div~/ 2141;~/ 1900;
jan-feb~day_of_year >= 306~day_of_year >= 305
year-adj~wrapping_sub(6313183731940000u64)~wrapping_sub(6313183731940001u64)
month-minus~month.wrapping_sub(12)~month.wrapping_sub(11)
yday-leap~31 + 28 + is_leap_year as u32~31 + 28 + !is_leap_year as u32
year-1900~year.wrapping_sub(1900)~year.wrapping_sub(1901)
rem-neg~while rem < 0 {~while rem < -1 {
rem-ge~while rem >= SECS_PER_DAY {~while rem > SECS_PER_DAY {
sec~result.tm_sec = (rem % 60)~result.tm_sec = (rem % 61)
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
