#!/usr/bin/env bash
# port/test/nls_base/run.sh -- differential for the UTF conversion half of fs/nls/nls_base.c.
#   run.sh             full run (8 shards)
#   run.sh --sabotage  prove the harness fails on mutants of the Rust
# C arm = the four functions sliced out of port/pristine/fs/nls/nls_base.c (unmodified, extracted per run);
# Rust arm = port/tree/fs/nls/nls_base_rs.rs (the file the kernel builds).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/nls_base"
out="${TMPDIR:-/tmp}/nlsbase.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${NLSBASE_RS:-$root/port/tree/fs/nls/nls_base_rs.rs}"
BASE="$root/port/pristine/fs/nls/nls_base.c"
for f in "$RS" "$BASE"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$BASE" "$out/ref.c"
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name nls_base_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -Wno-unused-function -Dutf8_to_utf32=c_utf8_to_utf32 -Dutf32_to_utf8=c_utf32_to_utf8 \
        -Dutf8s_to_utf16s=c_utf8s_to_utf16s -Dutf16s_to_utf8s=c_utf16s_to_utf8s -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" 8 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if NLS_PROVE_CAN_FAIL=1 NLS_LIM8=70000 NLS_NRAND=10 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if NLS_FAILFAST=1 NLS_LIM8=100000000 NLS_NRAND=2000000 timeout 300 "$out/m$n/t" 0 1 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
eilseq-code~const EILSEQ: c_int = 84;~const EILSEQ: c_int = 83;
overflow-code~const EOVERFLOW: c_int = 75;~const EOVERFLOW: c_int = 74;
unicode-max~const UNICODE_MAX: u64 = 0x0010_ffff;~const UNICODE_MAX: u64 = 0x0011_ffff;
surrogate-mask~const SURROGATE_MASK: u64 = 0xffff_f800;~const SURROGATE_MASK: u64 = 0xffff_fc00;
row2-lval~lmask: 0x7FF, lval: 0x80 }~lmask: 0x7FF, lval: 0x81 }
row3-lval~lval: 0x800 }~lval: 0x801 }
inlen-check~if inlen <= nc {~if inlen < nc {
cont-check~if c & 0xC0 != 0 {~if c & 0x80 != 0 {
null-first~if s.is_null() {~if false {
maxout-zero~if maxout == 0 {~if maxout <= 0 {
encode-mask~(0x80 | ((l >> c) & 0x3F)) as u8~(0x80 | ((l >> c) & 0x7F)) as u8
plane-size~const PLANE_SIZE: u32 = 0x0001_0000;~const PLANE_SIZE: u32 = 0x0000_ffff;
maxout-lt2~if maxout < 2 {~if maxout < 1 {
hi-shift~((u >> 10) & SURROGATE_BITS as u32)~((u >> 9) & SURROGATE_BITS as u32)
le-swap~UTF16_LITTLE_ENDIAN => c.to_le(),~UTF16_LITTLE_ENDIAN => c.to_be(),
be-load~UTF16_BIG_ENDIAN => u16::from_be(c),~UTF16_BIG_ENDIAN => u16::from_le(c),
low-skip~if u & SURROGATE_LOW != 0 {~if u & SURROGATE_LOW == 0 {
pair-calc~PLANE_SIZE as u64 + ((u & SURROGATE_BITS) << 10)~PLANE_SIZE as u64 + ((u & SURROGATE_BITS) << 9)
inlen-break~if inlen <= 0 {~if inlen < 0 {
eilseq-skip~if size == -EILSEQ {~if size == -EOVERFLOW {
einval~const EINVAL: c_int = 22;~const EINVAL: c_int = 21;
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
