#!/usr/bin/env bash
# port/test/bitmap_str/run.sh -- differential for lib/bitmap-str.c (bitmap_parselist, bitmap_parse).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/bitmap_str"
out="${TMPDIR:-/tmp}/bitmapstr.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${BMS_RS:-$root/port/tree/lib/bitmap_str_rs.rs}"
C="$root/port/pristine/lib/bitmap-str.c"
for f in "$RS" "$C" "$root/port/pristine/lib/ctype.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name bitmap_str_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -Dbitmap_parselist=c_bitmap_parselist -Dbitmap_parse=c_bitmap_parse -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -w -I "$here/shim" -c -o "$2/ctype.o" "$root/port/pristine/lib/ctype.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/ctype.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if BMS_PROVE_CAN_FAIL=1 BMS_N=2000000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if BMS_N=500000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
errno-inval~const EINVAL: c_int = 22;~const EINVAL: c_int = 21;
errno-range~const ERANGE: c_int = 34;~const ERANGE: c_int = 33;
errno-overflow~const EOVERFLOW: c_int = 75;~const EOVERFLOW: c_int = 74;
ctype-s~const CTYPE_S: u8 = 0x20;~const CTYPE_S: u8 = 0x08;
set-region-len~core::cmp::min(r.end.wrapping_sub(start).wrapping_add(1), r.off)~core::cmp::min(r.end.wrapping_sub(start), r.off)
set-region-step~start = start.wrapping_add(r.group_len);~start = start.wrapping_add(r.group_len + 1);
set-region-cond~while start <= r.end {~while start < r.end {
check-gt~if r.start > r.end || r.group_len == 0 || r.off > r.group_len {~if r.start >= r.end || r.group_len == 0 || r.off > r.group_len {
check-glen~r.group_len == 0 ||~false ||
check-off~r.off > r.group_len~r.off >= r.group_len
check-range~if r.end >= r.nbits {~if r.end > r.nbits {
getnum-n~if unsafe { ch(str) } == b'N' {~if unsafe { ch(str) } == b'n' {
getnum-len~if len == 0 {~if len == 1 {
getnum-ovf~n != (n as u32) as u64~n != (n as u16) as u64
getnum-flag~len & KSTRTOX_OVERFLOW != 0 ||~len & (KSTRTOX_OVERFLOW >> 1) != 0 ||
end-of-str~c == b'\0' || c == b'\n'~c == b'\0'
end-region~isspace(c) || c == b','~isspace(c)
find-region~if end_of_str(unsafe { ch(str) }) {<NL>        core::ptr::null()~if unsafe { ch(str) } == b'\0' {<NL>        core::ptr::null()
reverse-cond~while start <= end && __end_of_region~while start < end && __end_of_region
all-len~str = unsafe { str.add(3) };~str = unsafe { str.add(2) };
all-case~strncasecmp(str, c"all".as_ptr(), 3) == 0~strncmp_stub(str, c"all".as_ptr(), 3) == 0
no-end~r.end = r.start;<NL>            return~r.end = r.start + 1;<NL>            return
dash~if unsafe { ch(str) } != b'-' {~if unsafe { ch(str) } != b'_' {
colon~if unsafe { ch(str) } != b':' {~if unsafe { ch(str) } != b';' {
slash~if unsafe { ch(str) } != b'/' {~if unsafe { ch(str) } != b'\\' {
nopat-off~r.off = r.end.wrapping_add(1);~r.off = r.end;
nopat-group~r.group_len = r.end.wrapping_add(1);~r.group_len = r.end;
list-zero~write_bytes(maskp, 0, ((r.nbits as u64 + 63) / 64) as usize)~write_bytes(maskp, 0, ((r.nbits as u64 + 63) / 64) as usize - 1)
x32-shift~ret \|= (c as u32) << i;~ret \|= (c as u32) << (i + 1);
x32-start~if start > end || __end_of_region~if start >= end || __end_of_region
x32-overflow~if c >= 0 {<NL>        return err_ptr(-EOVERFLOW);~if c > 0 {<NL>        return err_ptr(-EOVERFLOW);
parse-nl~b'\n' as c_int }.wrapping_sub(1)~b'\r' as c_int }.wrapping_sub(1)
parse-chunks~let had = chunks;<NL>        chunks = chunks.wrapping_sub(1);<NL>        if had == 0 {~let had = chunks;<NL>        chunks = chunks.wrapping_sub(1);<NL>        if had == 1 {
parse-unset~if unset_bit < nmaskbits {~if unset_bit <= nmaskbits {
parse-find~!= unset_bit as c_ulong {~== unset_bit as c_ulong {
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
