#!/usr/bin/env bash
# port/test/genalloc/run.sh -- lib/genalloc.c: bitmap_set_ll/clear_ll + the five allocation algorithms, differential + multi-thread stress,
# pristine C vs genalloc_glue.c's wrappers over genalloc_rs.rs.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/genalloc"
out="${TMPDIR:-/tmp}/genalloctest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${GA_RS:-$root/port/tree/lib/genalloc_rs.rs}"
C="$root/port/pristine/lib/genalloc.c"
G="$root/port/tree/lib/genalloc_glue.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c" helpers
python3 "$here/extract_ref.py" "$G" "$out/glue.c" glue
CREN=""; RREN=""
for fn in bitmap_set_ll bitmap_clear_ll gen_pool_first_fit gen_pool_first_fit_align gen_pool_fixed_alloc gen_pool_first_fit_order_align gen_pool_best_fit; do
    CREN="$CREN -D$fn=c_$fn"; RREN="$RREN -D$fn=rs_$fn"
done
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name genalloc_rs -o "$2/librs.a" "$1"
    cc -O2 -w $CREN -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -w $RREN -c -o "$2/glue.o" "$out/glue.c"
    cc -O2 -w -c -o "$2/shim.o" "$here/shim.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/shim.o" "$2/librs.a" -lpthread
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if GA_PROVE_CAN_FAIL=1 GA_N=100 GA_SECONDS=0 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if GA_N=100000 GA_SECONDS=2 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
set-busy~if val & mask_to_set != 0 {~if val & mask_to_set == !0 {
clear-busy~if val & mask_to_clear != mask_to_clear {~if val & mask_to_clear == 0 {
non-atomic-set~match word.compare_exchange(val, val | mask_to_set, Ordering::SeqCst, Ordering::SeqCst) {~match { let cur = word.load(Ordering::Relaxed); if cur == val { word.store(val | mask_to_set, Ordering::Relaxed); Ok(val) } else { Err(cur) } } {
first-mask~!0 << (start % BITS_PER_LONG)~!0 << (start % BITS_PER_LONG + 1)
last-mask~!0 >> (nbits.wrapping_neg() % BITS_PER_LONG)~!0 >> (nbits.wrapping_neg() % BITS_PER_LONG + 1)
set-nr~            nr -= bits_to_set;~            nr -= bits_to_set - 1;
clear-nr~            nr -= bits_to_clear;~            nr -= bits_to_clear - 1;
align-off~let align_off = (start_addr & align.wrapping_sub(1)) >> order;~let align_off = (start_addr & align.wrapping_sub(1)) >> (order + 1);
align-mask~let align_mask = (align.wrapping_add(1u64.wrapping_shl(order)).wrapping_sub(1) >> order).wrapping_sub(1);~let align_mask = (align.wrapping_add(1u64.wrapping_shl(order)) >> order).wrapping_sub(1);
fixed-cmp~if start_bit != offset_bit {~if start_bit > offset_bit {
order-fls~let fls = 64 - n.leading_zeros();~let fls = 63 - n.leading_zeros();
best-lt~if next_bit.wrapping_sub(index) < len {~if next_bit.wrapping_sub(index) <= len {
best-skip~index = bitmap_find_next_zero_area_off(map, size, next_bit.wrapping_add(1), nr, 0, 0);~index = bitmap_find_next_zero_area_off(map, size, next_bit.wrapping_add(2), nr, 0, 0);
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential + stress:"
runall "$out/real/t"
echo PASS
