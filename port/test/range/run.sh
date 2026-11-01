#!/usr/bin/env bash
# port/test/range/run.sh -- differential for kernel/range.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/range"
out="${TMPDIR:-/tmp}/range.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${RANGE_RS:-$root/port/tree/kernel/range_rs.rs}"
C="$root/port/pristine/kernel/range.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
REN=""; for fn in add_range add_range_with_merge subtract_range clean_sort_range sort_range; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name range_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -I "$here/shim" -DRANGE_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if RANGE_PROVE_CAN_FAIL=1 RANGE_N=20000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if RANGE_N=2000000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
add-ge~if start >= end {<NL>        return nr_range;<NL>    }<NL><NL>    /* Out of slots: */~if start > end {<NL>        return nr_range;<NL>    }<NL><NL>    /* Out of slots: */
add-slots~if nr_range >= az {~if nr_range > az {
merge-skip-empty~if unsafe { (*ri).end } == 0 {~if unsafe { (*ri).end } == 1 {
merge-touch~if common_start > common_end {~if common_start >= common_end {
merge-start~start = core::cmp::min(unsafe { (*ri).start }, start);~start = core::cmp::max(unsafe { (*ri).start }, start);
merge-end~end = core::cmp::max(unsafe { (*ri).end }, end);~end = core::cmp::min(unsafe { (*ri).end }, end);
merge-count~(nr_range - (i + 1)) as usize,~(nr_range - (i + 2)) as usize,
merge-clear~(*range.offset((nr_range - 1) as isize)).end = 0;~(*range.offset((nr_range - 1) as isize)).end = 1;
merge-redo~        i -= 1;<NL>        i += 1;~        i += 1;
sub-whole~if start <= rj.start && end >= rj.end {~if start <= rj.start && end > rj.end {
sub-left~if start <= rj.start && end < rj.end && rj.start < end {~if start <= rj.start && end < rj.end {
sub-right~if start > rj.start && end >= rj.end && rj.end > start {~if start > rj.start && end >= rj.end {
sub-split-end~ri.end = rj.end;~ri.end = rj.start;
sub-split-start~ri.start = end;~ri.start = start;
sub-msg~3%s: run out of slot in ranges~3%s: run out of slots in ranges
sub-func~c"subtract_range"~c"subtract_ranges"
sub-level~\x013%s~\x014%s
sub-spare~if i < az {~if i + 1 < az {
cmp-less~if r1.start < r2.start {~if r1.start <= r2.start {
clean-compact~k = j;<NL>                break;~k = j - 1;<NL>                break;
clean-count~nr_range = i;<NL>            break;~nr_range = i + 1;<NL>            break;
clean-break~if j == i {<NL>            break;~if j == i + 1 {<NL>            break;
sort-n~            nr_range as usize,<NL>            core::mem::size_of::<Range>(),<NL>            Some(cmp_range),<NL>            None,<NL>        )<NL>    };<NL>}~            nr_range as usize + 1,<NL>            core::mem::size_of::<Range>(),<NL>            Some(cmp_range),<NL>            None,<NL>        )<NL>    };<NL>}
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
