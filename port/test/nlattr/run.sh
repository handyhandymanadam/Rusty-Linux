#!/usr/bin/env bash
# port/test/nlattr/run.sh -- lib/nlattr.c: pristine C vs nlattr_glue.c over nlattr_rs.rs, random streams x random policies.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/nlattr"
out="${TMPDIR:-/tmp}/nlattrtest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${NL_RS:-$root/port/tree/lib/nlattr_rs.rs}"
G="${NL_GLUE:-$root/port/tree/lib/nlattr_glue.c}"
C="${NL_C:-$root/port/pristine/lib/nlattr.c}"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 - "$C" "$G" "$out" <<'PY'
import sys
c = open(sys.argv[1]).read(); g = open(sys.argv[2]).read(); out = sys.argv[3]
ref = c[c.index("/* For these data types"):c.index("#ifdef CONFIG_NET\n")]
glue = g[g.index("/* lib/nlattr_rs.rs */"):g.index("#ifdef CONFIG_NET\n")]
open(out + "/ref.c", "w").write('#include "kshim.h"\n' + ref)
open(out + "/glue.c", "w").write('#include "kshim.h"\n' + glue)
PY
CREN=""; RREN=""
for fn in nla_get_range_unsigned nla_get_range_signed __nla_validate nla_policy_len __nla_parse nla_find nla_strscpy nla_strdup nla_memcpy nla_memcmp nla_strcmp; do
    CREN="$CREN -D$fn=c_$fn"; RREN="$RREN -D$fn=rs_$fn"
done
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name nlattr_rs -o "$2/librs.a" "$1"
    cc -O2 -w -I "$here" $CREN -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -w -I "$here" $RREN -c -o "$2/glue.o" "$out/glue.c"
    cc -O2 -Wall -Wno-unused-parameter -I "$here" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if NL_PROVE_CAN_FAIL=1 NL_N=100 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    # Dropped as EQUIVALENT: `ty <= 0` -> `ty < 0` in validate_nla (its only caller skips type 0 before calling it).
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE"; head -8 "$out/build.log"; exit 1; }
        if NL_N=60000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
strict-start~ty >= strict_start_type as c_int~ty > strict_start_type as c_int
ok-len~unsafe { (*nla).nla_len } as c_int <= remaining~(unsafe { (*nla).nla_len } as c_int) < remaining
leftover~if rem > 0 {~if rem >= 0 {
nested-flag-check~if validate & NL_VALIDATE_NESTED != 0 {~if validate & NL_VALIDATE_UNSPEC != 0 {
nested-missing~(*nla).nla_type & NLA_F_NESTED == 0 {~(*nla).nla_type & NLA_F_NESTED != 0 {
flag-len~if attrlen > 0 {~if attrlen >= 0 {
sint-len~if attrlen != 4 && attrlen != 8 {~if attrlen != 4 || attrlen != 8 {
bitfield-sel~if value & !selector != 0 {~if value & selector != 0 {
nul-minlen~minlen = core::cmp::min(attrlen, p.len as c_int + 1);~minlen = core::cmp::min(attrlen, p.len as c_int);
str-trailing-nul~if *buf.add(attrlen as usize - 1) == 0 {~if *buf.add(attrlen as usize - 1) != 0 {
binary-len~if p.len != 0 && attrlen > p.len as c_int {~if p.len != 0 && attrlen >= p.len as c_int {
recursion-depth~const MAX_POLICY_RECURSION_DEPTH: c_uint = 10;~const MAX_POLICY_RECURSION_DEPTH: c_uint = 11;
unspec-len~if attrlen < p.len as c_int {~if attrlen <= p.len as c_int {
default-minlen~minlen = NLA_ATTR_MINLEN[p.type_ as usize] as c_int;~minlen = NLA_ATTR_MINLEN[p.type_ as usize] as c_int + 1;
range-min~if value < range.min || value > range.max {~if value <= range.min || value > range.max {
mask-test~(*pt).mask32() as u64) != 0 {~(*pt).mask32() as u64) > 1 {
be16-swap~NLA_BE16 => u16::from_be(get_u16(nla)) as u64,~NLA_BE16 => get_u16(nla) as u64,
s8-sign~NLA_S8 => get_u8(nla) as i8 as i64,~NLA_S8 => get_u8(nla) as i64,
u64-short~let n = core::cmp::min(8, nla_len(nla));~let n = 8;
uint-len~if nla_len(nla) as usize == 4 {~if nla_len(nla) as usize == 8 {
u16-max~NLA_U16 | NLA_BE16 | NLA_BINARY => (*range).max = u16::MAX as u64,~NLA_U16 | NLA_BE16 | NLA_BINARY => (*range).max = u16::MAX as u64 - 1,
find-type~if nla_type(nla) == attrtype {~if (*nla).nla_type as c_int == attrtype {
strscpy-len~if srclen >= dstsize {~if srclen > dstsize {
memcpy-min~let minlen = core::cmp::min(count, nla_len(src));~let minlen = core::cmp::max(count, nla_len(src));
policy-len~if p.len != 0 {~if p.len > 1 {
array-short~if nla_len(entry) < NLA_HDRLEN {~if nla_len(entry) <= NLA_HDRLEN {
reject-policy~(*extack).policy = core::ptr::null();~(*extack).policy = pt;
validate-fn~if !p.ptr().is_null() {<NL>                        let f: ValidateFn~if p.ptr().is_null() {<NL>                        let f: ValidateFn
range-warn-binary~ptr.type_ == NLA_BINARY && value > range.max {~ptr.type_ == NLA_BINARY && value >= range.max {
signed-range-min~NLA_VALIDATE_MIN => (*range).min = pt.min16() as i64,~NLA_VALIDATE_MIN => (*range).min = pt.min16() as u16 as i64,
strict-attrs~if validate & NL_VALIDATE_STRICT_ATTRS != 0 {~if validate & NL_VALIDATE_TRAILING != 0 {
maxtype-unknown~if validate & NL_VALIDATE_MAXTYPE != 0 {~if validate & NL_VALIDATE_UNSPEC != 0 {
trailing~if validate & NL_VALIDATE_TRAILING != 0 {<NL>                return -EINVAL;~if validate & NL_VALIDATE_MAXTYPE != 0 {<NL>                return -EINVAL;
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo PASS
