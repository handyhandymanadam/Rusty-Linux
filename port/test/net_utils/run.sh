#!/usr/bin/env bash
# port/test/net_utils/run.sh -- differential for net/core/utils.c (in_aton, in4_pton, in6_pton).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/net_utils"
out="${TMPDIR:-/tmp}/netutils.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${NETU_RS:-$root/port/tree/net/core/utils_rs.rs}"
C="$root/port/pristine/net/core/utils.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name utils_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -Din_aton=c_in_aton -Din4_pton=c_in4_pton -Din6_pton=c_in6_pton -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if NETU_PROVE_CAN_FAIL=1 NETU_N=20000 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if NETU_N=2000000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
aton-nl~unsafe { *s } != b'\n'~unsafe { *s } != b'\r'
xd-delim~if c as i8 as c_int == delim || c == b'\0' {~if c as i8 as c_int == delim {
xd-colon~return IN6PTON_COLON_MASK;~return IN6PTON_COLON_1;
xd-dot~return IN6PTON_DOT;~return IN6PTON_DIGIT;
xd-digit~val | IN6PTON_XDIGIT | if val < 10 { IN6PTON_DIGIT } else { 0 }~val | IN6PTON_XDIGIT | if val < 9 { IN6PTON_DIGIT } else { 0 }
xd-unknown~if delim == -1 {~if delim == -2 {
in4-255~if (w & 0xffff) > 255 {~if (w & 0xffff) > 256 {
in4-four~if i != 4 {~if i != 3 {
in4-w0~if w == 0 {~if w == 1 {
in4-cont~if i >= 4 {<NL>                break 'out;<NL>            }<NL>            s = unsafe { s.add(1) };~if i >= 5 {<NL>                break 'out;<NL>            }<NL>            s = unsafe { s.add(1) };
in4-end~unsafe { *end = s as *const c_char };<NL>    }<NL>    ret<NL>}<NL><NL>kernel::kabi_export! {<NL>    in6_pton,~unsafe { *end = (s as *const c_char).wrapping_add(1) };<NL>    }<NL>    ret<NL>}<NL><NL>kernel::kabi_export! {<NL>    in6_pton,
in6-init-state~let mut state: c_int = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT | IN6PTON_NULL;~let mut state: c_int = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT;
in6-null~if state & IN6PTON_NULL == 0 {~if state & IN6PTON_NULL != 0 {
in6-c2-null~if d >= 16 {<NL>                            state |= IN6PTON_NULL;~if d > 16 {<NL>                            state |= IN6PTON_NULL;
in6-colon2~state = IN6PTON_XDIGIT | IN6PTON_DELIM;~state = IN6PTON_XDIGIT;
in6-colon12~state = IN6PTON_XDIGIT | IN6PTON_COLON_2;~state = IN6PTON_XDIGIT | IN6PTON_COLON_1;
in6-colon1~IN6PTON_COLON_1 => {<NL>                        state = IN6PTON_XDIGIT;~IN6PTON_COLON_1 => {<NL>                        state = IN6PTON_XDIGIT | IN6PTON_DELIM;
in6-w~w = (w << 4) | (0xff & c);~w = (w << 4) | (0x07 & c);
in6-xdigit~if w & 0xf000 == 0 {~if w & 0xf00 == 0 {
in6-colon12b~if dc.is_none() && d + 2 < 16 {~if dc.is_none() && d + 2 <= 16 {
in6-d2~if d + 2 >= 16 {~if d + 2 > 16 {
in6-dot~if (dc.is_some() && d + 4 < 16) || d + 4 == 16 {~if (dc.is_some() && d + 4 < 16) || d + 4 == 15 {
in6-full~if d >= 16 {<NL>                state &= !(IN6PTON_XDIGIT~if d > 16 {<NL>                state &= !(IN6PTON_XDIGIT
in6-d4~d += 4;<NL>                        break;~d += 3;<NL>                        break;
in6-tok~tok = unsafe { s.add(1) };~tok = s;
in6-copy-dc~while d >= dc {~while d > dc {
in6-fill~while i >= dc {~while i > dc {
in6-nocopy~core::ptr::copy_nonoverlapping(dbuf.as_ptr(), dst, 16)~core::ptr::copy_nonoverlapping(dbuf.as_ptr(), dst, 15)
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
