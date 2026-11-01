#!/usr/bin/env bash
# port/test/random32/run.sh -- differential for lib/random32.c (generator).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/random32"
out="${TMPDIR:-/tmp}/random32.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${R32_RS:-$root/port/tree/lib/random32_rs.rs}"
C="$root/port/pristine/lib/random32.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name random32_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -Dprandom_u32_state=c_prandom_u32_state -Dprandom_bytes_state=c_prandom_bytes_state -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if R32_PROVE_CAN_FAIL=1 R32_N=100 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if R32_N=300000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
s1-a~tausworthe(st.s1, 6, 13, 4294967294, 18)~tausworthe(st.s1, 7, 13, 4294967294, 18)
s1-b~tausworthe(st.s1, 6, 13, 4294967294, 18)~tausworthe(st.s1, 6, 14, 4294967294, 18)
s1-c~tausworthe(st.s1, 6, 13, 4294967294, 18)~tausworthe(st.s1, 6, 13, 4294967295, 18)
s1-d~tausworthe(st.s1, 6, 13, 4294967294, 18)~tausworthe(st.s1, 6, 13, 4294967294, 17)
s2~tausworthe(st.s2, 2, 27, 4294967288, 2)~tausworthe(st.s2, 2, 27, 4294967288, 3)
s3~tausworthe(st.s3, 13, 21, 4294967280, 7)~tausworthe(st.s3, 13, 21, 4294967281, 7)
s4~tausworthe(st.s4, 3, 12, 4294967168, 13)~tausworthe(st.s4, 3, 11, 4294967168, 13)
xor~st.s1 ^ st.s2 ^ st.s3 ^ st.s4~st.s1 ^ st.s2 ^ st.s3
taus-form~((s & c) << d) ^ (((s << a) ^ s) >> b)~((s & c) << d) ^ (((s << a) ^ s) >> (b + 1))
bytes-adv~ptr = unsafe { ptr.add(4) };~ptr = unsafe { ptr.add(3) };
bytes-rem~if bytes > 0 {<NL>        let mut rem~if bytes > 1 {<NL>        let mut rem
bytes-shift~rem >>= 8;~rem >>= 7;
bytes-byte~*ptr = rem as u8~*ptr = (rem >> 1) as u8
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
