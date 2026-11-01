#!/usr/bin/env bash
# port/test/string/run.sh -- differential for lib/string.c (the functions string_rs.rs has).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/string"
out="${TMPDIR:-/tmp}/stringtest.$$"; mkdir -p "$out"; [ -n "${KEEP:-}" ] || trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${STR_RS:-$root/port/tree/lib/string_rs.rs}"
C="$root/port/pristine/lib/string.c"
for f in "$RS" "$C" "$root/port/pristine/lib/ctype.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
REN=""
for fn in strncasecmp strcasecmp strcpy strncpy stpcpy strcat strncat strcmp strncmp strchr strchrnul strnchrnul strrchr strnchr strlen strnlen strspn strcspn strpbrk strsep memcmp bcmp memscan strstr strnstr memchr memchr_inv; do
    REN="$REN -D$fn=c_$fn"
done
build() {
    mkdir -p "$2"
    # the stub goes AFTER the crate's inner attributes (#![no_builtins])
    python3 - "$1" "$2/probe.rs" <<'PY'
import sys, re
s = open(sys.argv[1]).read().replace("\n//!", "\n//")
s = re.sub(r"^//!", "//", s)
stub = '#[allow(unused_macros, unused_imports)]\nmod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }\n'
m = list(re.finditer(r"^#!\[.*\]\s*$", s, re.M))
i = m[-1].end() if m else 0
open(sys.argv[2], "w").write(s[:i] + "\n" + stub + s[i:])
PY
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name string_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -ffreestanding -fno-builtin $REN -I "$here/shim" -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -w -I "$here/shim" -c -o "$2/ctype.o" "$root/port/pristine/lib/ctype.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/ctype.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if STR_PROVE_CAN_FAIL=1 STR_N=100 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if STR_N=300000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
ctype-u~const CTYPE_U: u8 = 0x01;~const CTYPE_U: u8 = 0x02;
lower~c.wrapping_add(b'a'.wrapping_sub(b'A'))~c.wrapping_add(b'a'.wrapping_sub(b'B'))
ncasecmp-zero~if len == 0 {<NL>        return 0;~if len == 1 {<NL>        return 0;
ncasecmp-lower~            c1 = tolower(c1);<NL>            c2 = tolower(c2);~            c1 = tolower(c1);
casecmp-end~if !(c1 == c2 && c1 != 0) {~if !(c1 == c2) {
strncpy-pad~        if c != 0 {<NL>            src = unsafe { src.add(1) };~        if c != 99 {<NL>            src = unsafe { src.add(1) };
stpcpy-ret~    unsafe { d.sub(1) }~    d
strncat-term~            if count == 0 {<NL>                unsafe { *d = 0 };~            if count == 1 {<NL>                unsafe { *d = 0 };
strncat-if~    if count != 0 {<NL>        while unsafe { *d } != 0 {~    if count != 1 {<NL>        while unsafe { *d } != 0 {
strcmp-ord~return if c1 < c2 { -1 } else { 1 };~return if c1 < c2 { 1 } else { -1 };
strncmp-count~        if c1 == 0 {<NL>            break;<NL>        }<NL>        count -= 1;~        if c1 == 0 {<NL>            break;<NL>        }<NL>        count -= 2;
strchr-nul~        if unsafe { *s } == 0 {<NL>            return core::ptr::null_mut();~        if unsafe { *s } == 0 {<NL>            return s as *mut c_char;
strnchrnul-cond~if had == 0 || unsafe { *s } == 0 || unsafe { *s } == c as c_char {~if had == 0 || unsafe { *s } == 0 {
strrchr-last~            last = s;~            last = s.wrapping_add(1);
strnchr-nul~        let end = unsafe { *s } == 0;<NL>        s = unsafe { s.add(1) };<NL>        if end {<NL>            break;<NL>        }<NL>    }<NL>    core::ptr::null_mut()~        let end = false;<NL>        s = unsafe { s.add(1) };<NL>        if end {<NL>            break;<NL>        }<NL>    }<NL>    core::ptr::null_mut()
strlen-off~    while unsafe { *sc } != 0 {~    while unsafe { *sc } != 0 && false {
strnlen-cond~if had == 0 || unsafe { *sc } == 0 {~if had == 0 {
strspn-invert~if unsafe { strchr(accept, *p as c_int) }.is_null() {~if !unsafe { strchr(accept, *p as c_int) }.is_null() {
strcspn-invert~if !unsafe { strchr(reject, *p as c_int) }.is_null() {~if unsafe { strchr(reject, *p as c_int) }.is_null() {
strpbrk-ret~            return sc as *mut c_char;<NL>        }<NL>        sc = unsafe { sc.add(1) };~            return sc.wrapping_add(1) as *mut c_char;<NL>        }<NL>        sc = unsafe { sc.add(1) };
strsep-null~    if sbegin.is_null() {~    if false {
strsep-term~        unsafe { *end = 0 };~        unsafe { *end = 1 };
memcmp-skip~            count -= 8;<NL>            if count < 8 {~            count -= 7;<NL>            if count < 8 {
memcmp-diff~        res = unsafe { *p1 } as c_int - unsafe { *p2 } as c_int;~        res = if unsafe { *p1 } > unsafe { *p2 } { 1 } else { -1 };
memcmp-word~            if a != b {<NL>                break;~            if a == b {<NL>                break;
memscan-end~        size -= 1;<NL>    }<NL>    p as *mut c_void~        size -= 1;<NL>    }<NL>    core::ptr::null_mut()
strstr-empty~    if l2 == 0 {<NL>        return s1 as *mut c_char;<NL>    }<NL>    let mut l1~    if l2 == 0 {<NL>        return core::ptr::null_mut();<NL>    }<NL>    let mut l1
strstr-cond~    while l1 >= l2 {~    while l1 > l2 {
strnstr-cond~    while len >= l2 {~    while len > l2 {
memchr-cmp~        if c as u8 == b {~        if c as u8 != b {
check8~        if unsafe { *start } != value {~        if unsafe { *start } == value {
inv-small~    if bytes <= 16 {~    if bytes <= 15 {
inv-prefix~        prefix = 8 - prefix;~        prefix = 7 - prefix;
inv-words~    let mut words = (bytes / 8) as u32;~    let mut words = (bytes / 8) as u32 + 1;
inv-tail~(bytes % 8) as u32) }~(bytes % 7) as u32) }
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
