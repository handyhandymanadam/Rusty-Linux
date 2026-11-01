#!/usr/bin/env bash
# port/test/kfifo/run.sh -- lib/kfifo.c core: differential + SPSC stress, pristine C vs kfifo_rs.rs.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/kfifo"
out="${TMPDIR:-/tmp}/kfifotest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${KF_RS:-$root/port/tree/lib/kfifo_rs.rs}"
C="$root/port/pristine/lib/kfifo.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
REN=""; for fn in __kfifo_init __kfifo_in __kfifo_out_peek __kfifo_out_linear __kfifo_out __kfifo_max_r __kfifo_len_r __kfifo_in_r __kfifo_out_peek_r __kfifo_out_linear_r __kfifo_out_r __kfifo_skip_r; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name kfifo_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a" -lpthread
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if KF_PROVE_CAN_FAIL=1 KF_N=100 KF_SECONDS=0 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if KF_N=100000 KF_SECONDS=2 timeout 120 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
unused~(*fifo).mask.wrapping_add(1).wrapping_sub(~(*fifo).mask.wrapping_sub(1).wrapping_sub(
in-clamp~let len = if len > l { l } else { len };<NL><NL>    unsafe {<NL>        kfifo_copy_in~let len = if len > l.wrapping_add(1) { l } else { len };<NL><NL>    unsafe {<NL>        kfifo_copy_in
copy-split~let l = core::cmp::min(len, size.wrapping_sub(off));<NL><NL>    unsafe {<NL>        core::ptr::copy_nonoverlapping(src as *const u8~let l = core::cmp::min(len, size.wrapping_sub(off) + 1);<NL><NL>    unsafe {<NL>        core::ptr::copy_nonoverlapping(src as *const u8
esize-off~        off = off.wrapping_mul(esize);<NL>        size = size.wrapping_mul(esize);<NL>        len = len.wrapping_mul(esize);<NL>    }<NL>    let l = core::cmp::min(len, size.wrapping_sub(off));<NL><NL>    unsafe {<NL>        core::ptr::copy_nonoverlapping(src~        off = off.wrapping_mul(esize);<NL>        size = size.wrapping_mul(esize);<NL>        len = len.wrapping_mul(esize);<NL>    }<NL>    let l = core::cmp::min(len, size.wrapping_sub(off).wrapping_sub(esize));<NL><NL>    unsafe {<NL>        core::ptr::copy_nonoverlapping(src
out-add~st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(len))~st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(len + 1))
peek-len~let len = if len > l { l } else { len };<NL><NL>    unsafe { kfifo_copy_out~let len = if len > l.wrapping_add(1) { l } else { len };<NL><NL>    unsafe { kfifo_copy_out
linear-min~core::cmp::min(core::cmp::min(n, unsafe { ld(&raw const (*fifo).in_).wrapping_sub(ld(&raw const (*fifo).out)) }), size.wrapping_sub(off))~core::cmp::min(core::cmp::min(n, unsafe { ld(&raw const (*fifo).in_).wrapping_sub(ld(&raw const (*fifo).out)) }), size.wrapping_sub(off).wrapping_add(1))
linear-tail~unsafe { *tail = off };~unsafe { *tail = off + 1 };
max-r~1u32.wrapping_shl((recsize << 3) as u32)~1u32.wrapping_shl((recsize << 2) as u32)
peek-hi~l |= (unsafe { *data.add((out.wrapping_add(1) & mask) as usize) } as u32) << 8;~l |= (unsafe { *data.add((out.wrapping_add(1) & mask) as usize) } as u32) << 7;
poke-hi~(n >> 8) as u8~(n >> 7) as u8
in-r-fit~if (len as usize).wrapping_add(recsize) > unsafe { kfifo_unused(fifo) } as usize {~if (len as usize).wrapping_add(recsize) >= unsafe { kfifo_unused(fifo) } as usize {
in-r-off~kfifo_copy_in(fifo, buf, len, ld(&raw const (*fifo).in_).wrapping_add(recsize as u32));~kfifo_copy_in(fifo, buf, len, ld(&raw const (*fifo).in_));
out-r-adv~wrapping_add(n).wrapping_add(recsize as u32)) };<NL>    len<NL>}~wrapping_add(n)) };<NL>    len<NL>}
skip-adv~    unsafe { st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(n).wrapping_add(recsize as u32)) };<NL>}~    unsafe { st(&raw mut (*fifo).out, ld(&raw const (*fifo).out).wrapping_add(n)) };<NL>}
init-mask~(*fifo).mask = size - 1 };~(*fifo).mask = size };
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential + SPSC stress:"
runall "$out/real/t"
echo PASS
