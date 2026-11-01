#!/usr/bin/env bash
# port/test/parser/run.sh -- differential for lib/parser.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/parser"
out="${TMPDIR:-/tmp}/parser.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${PARSER_RS:-$root/port/tree/lib/parser_rs.rs}"
C="$root/port/pristine/lib/parser.c"
for f in "$RS" "$C" "$root/port/pristine/lib/ctype.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
mkdir -p "$out/inc/linux"; cp "$root/src/linux/include/linux/parser.h" "$out/inc/linux/parser.h"   # the REAL header, alone
REN=""; for fn in match_token match_int match_uint match_u64 match_octal match_hex match_wildcard match_strlcpy; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name parser_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -I "$out/inc" -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -w -I "$here/shim" -c -o "$2/ctype.o" "$root/port/pristine/lib/ctype.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/ctype.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if PARSER_PROVE_CAN_FAIL=1 PARSER_N=200000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if PARSER_N=300000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
einval~const EINVAL: c_int = 22;~const EINVAL: c_int = 21;
erange~const ERANGE: c_int = 34;~const ERANGE: c_int = 33;
buf-len~const NUMBER_BUF_LEN: usize = 24;~const NUMBER_BUF_LEN: usize = 12;
maxargs~const MAX_OPT_ARGS: c_int = 3;~const MAX_OPT_ARGS: c_int = 2;
digit~const CTYPE_D: u8 = 0x04;~const CTYPE_D: u8 = 0x02;
null-pat~if p.is_null() {<NL>        return 1;~if p.is_null() {<NL>        return 0;
nometa~return (unsafe { strcmp(p, s) } == 0) as c_int;~return (unsafe { strcmp(p, s) } != 0) as c_int;
prefix~meta.offset_from(p) as usize) } != 0~meta.offset_from(p) as usize + 1) } != 0
skip~s = unsafe { s.offset(meta.offset_from(p)) };~s = unsafe { s.offset(meta.offset_from(p) + 1) };
percent~if c != b'%' as c_char {<NL>                return 0;~if c != b'x' as c_char {<NL>                return 0;
width-base~simple_strtoul(p, &mut endp, 10)~simple_strtoul(p, &mut endp, 16)
argc~if argc >= MAX_OPT_ARGS {~if argc > MAX_OPT_ARGS {
s-empty~if str_len == 0 {<NL>                    return 0;~if str_len == 1 {<NL>                    return 0;
s-len~(len as isize as usize) > str_len~(len as isize as usize) > str_len + 1
d-base~simple_strtol(s, &mut to, 0);~simple_strtol(s, &mut to, 10);
o-base~simple_strtoul(s, &mut to, 8);~simple_strtoul(s, &mut to, 10);
x-base~simple_strtoul(s, &mut to, 16);~simple_strtoul(s, &mut to, 10);
num-empty~if arg.to == arg.from {~if arg.to == arg.from.wrapping_add(1) {
default~_ => return 0,<NL>        }<NL>        s = arg.to;~_ => {}<NL>        }<NL>        s = arg.to;
tok-loop~while unsafe { match_one(s, (*p).pattern, args) } == 0 {~while unsafe { match_one(s, (*p).pattern, args) } == 1 {
strlcpy-len~let len = if ret >= size { size - 1 } else { ret };~let len = if ret > size { size - 1 } else { ret };
strlcpy-nul~*dest.add(len) = 0;~*dest.add(len) = 1;
strlcpy-size~if size != 0 {~if size > 1 {
num-ovf~if unsafe { match_strlcpy(buf.as_mut_ptr(), s, NUMBER_BUF_LEN) } >= NUMBER_BUF_LEN {<NL>        return -ERANGE;<NL>    }<NL>    let mut ret = 0;~if unsafe { match_strlcpy(buf.as_mut_ptr(), s, NUMBER_BUF_LEN) } > NUMBER_BUF_LEN {<NL>        return -ERANGE;<NL>    }<NL>    let mut ret = 0;
num-empty2~if endp as *const c_char == buf.as_ptr() {<NL>        ret = -EINVAL;~if false {<NL>        ret = -EINVAL;
num-range~val < c_int::MIN as c_long ||~val < c_int::MIN as c_long + 1 ||
num-max~val > c_int::MAX as c_long~val >= c_int::MAX as c_long
u64-store~if ret == 0 {<NL>        unsafe { *result = val };~if ret != 0 {<NL>        unsafe { *result = val };
uint-base~kstrtouint(buf.as_ptr(), 10, result)~kstrtouint(buf.as_ptr(), 0, result)
int-base~unsafe { match_number(s, result, 0) }~unsafe { match_number(s, result, 10) }
octal-base~unsafe { match_number(s, result, 8) }~unsafe { match_number(s, result, 10) }
hex-base~unsafe { match_number(s, result, 16) }~unsafe { match_number(s, result, 10) }
u64-base~unsafe { match_u64int(s, result, 0) }~unsafe { match_u64int(s, result, 10) }
wc-q~b'?' => {~b'#' => {
wc-star-str~str = s;<NL>                p = unsafe { p.add(1) };~str = s.wrapping_add(1);<NL>                p = unsafe { p.add(1) };
wc-nostar~if !star {<NL>                        return false;~if star {<NL>                        return false;
wc-adv~str = unsafe { str.add(1) };~str = unsafe { str.add(2) };
wc-tail~if unsafe { *p } == b'*' as c_char {<NL>        p = unsafe { p.add(1) };~if false {<NL>        p = unsafe { p.add(1) };
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
