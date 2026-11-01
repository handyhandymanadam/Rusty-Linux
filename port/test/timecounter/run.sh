#!/usr/bin/env bash
# port/test/timecounter/run.sh -- differential for kernel/time/timecounter.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/timecounter"
out="${TMPDIR:-/tmp}/timecounter.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${TC_RS:-$root/port/tree/kernel/time/timecounter_rs.rs}"
C="$root/port/pristine/kernel/time/timecounter.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
REN=""; for fn in timecounter_init timecounter_read timecounter_cyc2time; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name timecounter_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -I "$here/shim" -I "$root/src/linux/include" -DTIMECOUNTER_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if TC_PROVE_CAN_FAIL=1 TC_N=2000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if TC_N=300000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
cyc2ns-add~ns.wrapping_mul(unsafe { (*cc).mult } as u64).wrapping_add(*frac);~ns.wrapping_mul(unsafe { (*cc).mult } as u64);
cyc2ns-frac~*frac = ns & mask;~*frac = ns & (mask >> 1);
cyc2ns-shift~ns.wrapping_shr(unsafe { (*cc).shift })<NL>}~ns.wrapping_shr(unsafe { (*cc).shift } + 1)<NL>}
init-last~tc.cycle_last = unsafe { ((*cc).read.unwrap_unchecked())(cc) };~tc.cycle_last = 0;
init-mask~1u64.wrapping_shl(unsafe { (*cc).shift }).wrapping_sub(1)~1u64.wrapping_shl(unsafe { (*cc).shift })
init-frac~tc.frac = 0;~tc.frac = 1;
read-mask~cycle_now.wrapping_sub(tc.cycle_last) & unsafe { (*tc.cc).mask }~cycle_now.wrapping_sub(tc.cycle_last)
read-last~tc.cycle_last = cycle_now;~tc.cycle_last = cycle_now.wrapping_sub(1);
read-acc~nsec = nsec.wrapping_add(tc.nsec);~nsec = nsec.wrapping_add(1);
back-frac~.wrapping_sub(frac)~.wrapping_add(frac)
c2t-half~if delta > cc_mask / 2 {~if delta >= cc_mask / 2 {
c2t-back~delta = tc.cycle_last.wrapping_sub(cycle_tstamp) & cc_mask;~delta = cycle_tstamp.wrapping_sub(tc.cycle_last) & cc_mask;
c2t-sub~nsec = nsec.wrapping_sub(unsafe { cc_cyc2ns_backwards~nsec = nsec.wrapping_add(unsafe { cc_cyc2ns_backwards
c2t-fwd-mask~let mut delta = cycle_tstamp.wrapping_sub(tc.cycle_last) & cc_mask;~let mut delta = cycle_tstamp.wrapping_sub(tc.cycle_last);
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
