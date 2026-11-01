#!/usr/bin/env bash
# port/test/bitmap/run.sh -- differential for lib/bitmap.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/bitmap"
out="${TMPDIR:-/tmp}/bitmap.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${BM_RS:-$root/port/tree/lib/bitmap_rs.rs}"
C="$root/port/pristine/lib/bitmap.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
REN=""
for fn in __bitmap_equal __bitmap_or_equal __bitmap_complement __bitmap_shift_right __bitmap_shift_left bitmap_cut __bitmap_and __bitmap_or __bitmap_xor \
          __bitmap_andnot __bitmap_replace __bitmap_intersects __bitmap_subset __bitmap_weight __bitmap_weight_and __bitmap_weight_andnot __bitmap_set \
          __bitmap_clear bitmap_find_next_zero_area_off bitmap_remap bitmap_bitremap bitmap_onto bitmap_fold bitmap_from_arr32 bitmap_to_arr32; do
    REN="$REN -D$fn=c_$fn"
done
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        --cfg CONFIG_NUMA -D unsafe_op_in_unsafe_fn -D warnings --crate-name bitmap_rs -o "$2/librs.a" "$2/probe.rs"
    # the ref's __bitmap_weight is called by its own bitmap_weight() shim: keep that call inside the C arm
    cc -O2 -w $REN -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "also builds without CONFIG_NUMA:"
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name bitmap_rs_nonuma -o "$out/nonuma.a" "$out/real/probe.rs" && echo "  ok"
echo "prove-can-fail:"
if BM_PROVE_CAN_FAIL=1 BM_N=200000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if BM_N=300000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
last-mask~!0u64 >> (nbits.wrapping_neg() & (BITS_PER_LONG - 1))~!0u64 >> (nbits.wrapping_neg() & (BITS_PER_LONG - 2))
first-mask~!0u64 << (start & (BITS_PER_LONG - 1))~!0u64 << (start & (BITS_PER_LONG - 2))
to-longs~((n as u64 + 63) / 64) as u32~((n as u64 + 62) / 64) as u32
equal-lim~let lim = bits / BITS_PER_LONG;<NL>    let mut k: u32 = 0;<NL>    while k < lim {<NL>        if unsafe { rd(bitmap1, k) != rd(bitmap2, k) } {~let lim = bits / BITS_PER_LONG;<NL>    let mut k: u32 = 1;<NL>    while k < lim {<NL>        if unsafe { rd(bitmap1, k) != rd(bitmap2, k) } {
oreq-tail~(tmp & last_word_mask(bits)) == 0<NL>}<NL><NL>// Types the contracts refer to~tmp == 0<NL>}<NL><NL>// Types the contracts refer to
complement~wr(dst, k, !rd(src, k))~wr(dst, k, rd(src, k))
shr-rem~if rem == 0 || off.wrapping_add(k).wrapping_add(1) >= lim {~if off.wrapping_add(k).wrapping_add(1) >= lim {
shr-upper-mask~if off + k + 1 == lim - 1 {<NL>                upper &= mask;~if off + k + 1 == lim {<NL>                upper &= mask;
shr-lower-mask~if off + k == lim - 1 {<NL>            lower &= mask;~if off + k == lim {<NL>            lower &= mask;
shr-zero~write_bytes(dst.add(lim.wrapping_sub(off) as usize), 0, off as usize)~write_bytes(dst.add(lim.wrapping_sub(off) as usize), 0, off as usize - 1)
shl-lower~rd(src, (k - 1) as u32) } >> (BITS_PER_LONG - rem)~rd(src, (k - 1) as u32) } >> (BITS_PER_LONG - rem + 1)
shl-k~rem != 0 && k > 0~rem != 0 && k > 1
shl-zero~core::ptr::write_bytes(dst, 0, off as usize)~core::ptr::write_bytes(dst, 0, off as usize - 1)
cut-keep~(!0u64 >> (BITS_PER_LONG - first % BITS_PER_LONG))~(!0u64 >> (BITS_PER_LONG - first % BITS_PER_LONG - 1))
cut-carry~if i < len.wrapping_sub(1) {~if i < len {
cut-loop~while cut != 0 {<NL>        cut -= 1;~while cut > 1 {<NL>        cut -= 1;
cut-final~wr(dst, w, rd(dst, w) | keep);~wr(dst, w, rd(dst, w) | 0);
and-tail~let v = unsafe { rd(bitmap1, k) & rd(bitmap2, k) } & last_word_mask(bits);~let v = unsafe { rd(bitmap1, k) & rd(bitmap2, k) };
and-ret~    result != 0<NL>}<NL><NL>// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):~    result != 0<NL>}<NL><NL>// Types the contracts refer to by back-reference (rig/kabi-symtypes.sh, from the C object):
or-op~wr(dst, k, rd(bitmap1, k) | rd(bitmap2, k))~wr(dst, k, rd(bitmap1, k) ^ rd(bitmap2, k))
xor-op~wr(dst, k, rd(bitmap1, k) ^ rd(bitmap2, k))~wr(dst, k, rd(bitmap1, k) | rd(bitmap2, k))
andnot-op~let v = unsafe { rd(bitmap1, k) & !rd(bitmap2, k) };<NL>        unsafe { wr(dst, k, v) };<NL>        result |= v;<NL>        k += 1;~let v = unsafe { rd(bitmap1, k) & rd(bitmap2, k) };<NL>        unsafe { wr(dst, k, v) };<NL>        result |= v;<NL>        k += 1;
replace~(rd(old, k) & !rd(mask, k)) | (rd(new, k) & rd(mask, k))~(rd(old, k) & rd(mask, k)) | (rd(new, k) & !rd(mask, k))
inter-tail~if bits % BITS_PER_LONG != 0 && unsafe { (rd(bitmap1, k) & rd(bitmap2, k)) & last_word_mask(bits) } != 0 {<NL>        return true;~if bits % BITS_PER_LONG != 0 && unsafe { (rd(bitmap1, k) & rd(bitmap2, k)) } != 0 {<NL>        return true;
subset-op~if unsafe { rd(bitmap1, k) & !rd(bitmap2, k) } != 0 {<NL>            return false;~if unsafe { rd(bitmap1, k) & rd(bitmap2, k) } != 0 {<NL>            return false;
weight-tail~w += (fetch(idx) & last_word_mask(bits)).count_ones();~w += fetch(idx).count_ones();
weight-and~weight(bits, |i| rd(bitmap1, i) & rd(bitmap2, i))~weight(bits, |i| rd(bitmap1, i) | rd(bitmap2, i))
weight-andnot~weight(bits, |i| rd(bitmap1, i) & !rd(bitmap2, i))~weight(bits, |i| rd(bitmap1, i) & rd(bitmap2, i))
set-cond~while len.wrapping_sub(bits_to_set) >= 0 {<NL>        unsafe { *p \|= mask_to_set };~while len.wrapping_sub(bits_to_set) > 0 {<NL>        unsafe { *p \|= mask_to_set };
clear-tail~mask_to_clear &= last_word_mask(size);~mask_to_clear &= first_word_mask(size);
area-align~(index.wrapping_add(align_offset).wrapping_add(align_mask) & !align_mask).wrapping_sub(align_offset)~(index.wrapping_add(align_mask) & !align_mask).wrapping_sub(align_offset)
area-end~if end > size {~if end >= size {
area-next~start = i + 1;~start = i;
ord-ge~if pos >= nbits \|\| !unsafe { test_bit(pos, buf) } {~if pos > nbits \|\| !unsafe { test_bit(pos, buf) } {
nth-ge~if n >= size {~if n > size {
remap-inplace~if dst as *const u64 == src {~if false {
remap-mod~(n as u32) % w) as u64~(n as u32) % (w + 1)) as u64
remap-ident~if n < 0 \|\| w == 0 {<NL>            unsafe { set_bit(oldbit, dst) };~if n < 0 {<NL>            unsafe { set_bit(oldbit, dst) };
bitremap-ident~if n < 0 \|\| w == 0 {<NL>        oldbit~if n < 0 {<NL>        oldbit
onto-m~if unsafe { test_bit(m, orig) } {<NL>            unsafe { set_bit(n, dst) };<NL>        }<NL>        m += 1;~if unsafe { test_bit(m, orig) } {<NL>            unsafe { set_bit(n, dst) };<NL>        }<NL>        m += 2;
fold-mod~set_bit(oldbit % sz, dst)~set_bit(oldbit % (sz + 1), dst)
from32-hi~<< 32)) };~<< 31)) };
to32-hi~(rd(bitmap, i / 2) >> 32) as u32~(rd(bitmap, i / 2) >> 31) as u32
to32-mask~u32::MAX >> (nbits.wrapping_neg() & 31)~u32::MAX >> (nbits.wrapping_neg() & 30)
from32-mask~rd(bitmap, (halfwords - 1) / 2) & last_word_mask(nbits)~rd(bitmap, (halfwords - 1) / 2)
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
