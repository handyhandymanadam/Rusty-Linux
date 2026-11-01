#!/usr/bin/env bash
# port/test/sha3_generic/run.sh -- differential for crypto/sha3_generic.c.
#   run.sh             pristine C vs Rust vs hashlib
#   run.sh --sabotage  each mutant of the Rust must be caught
# Scope: keccak core + the three entry bodies (init/update/finup). NOT the
# shash_alg table and registration (C glue, exercised in the kernel by
# libtest.c through the crypto API).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/sha3_generic"
out="${TMPDIR:-/tmp}/sha3-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/sha3_generic.c"
RS="$root/port/tree/crypto/sha3_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the stand-in constants/struct must be the kernel's
norm() { grep -E '^#define SHA3_(224|STATE)' "$1" | grep -vE 'EXPORT' | tr -d ' \t' | sort; sed -n '/^struct sha3_state {/,/^};/p' "$1" | tr -d ' \t\n'; }
[ "$(norm "$root/src/linux/include/crypto/sha3.h")" = "$(norm "$here/ref.c")" ] \
    || { echo "SHIM MISMATCH vs include/crypto/sha3.h"; exit 1; }
echo "stand-in sizes/struct match include/crypto/sha3.h"
python3 "$here/extract.py" "$C" "$out/extract.c"
sed "s|EXTRACT|$out/extract.c|" "$here/ref.c" > "$out/ref.c"
python3 "$here/vectors.py" 3 > "$out/vec.txt"
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name sha3_rs -o "$2/librs.a" "$1"
    cc -O2 -Wall -Wno-unused-function -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if SHA3_PROVE_CAN_FAIL=1 "$out/real/t" "$out/vec.txt" 1000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned output detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)>=1, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" "$out/vec.txt" 20000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
round-constant~0x8000000080008008,~0x8000000080008009,
rho-rotation~(st[6] ^ t[1]).rotate_left(44)~(st[6] ^ t[1]).rotate_left(45)
theta-index~t[1] = bc[0] ^ (bc[2])~t[1] = bc[0] ^ (bc[3])
chi-not~bc[0] = !st[1] & st[2];~bc[0] = st[1] & st[2];
iota-wrong-const~st[0] ^= KECCAKF_RNDC[round];~st[0] ^= KECCAKF_RNDC[round] ^ 1;
update-remainder~len.wrapping_sub(rsiz)~len.wrapping_sub(rsiz + 1)
domain-byte~block[len] = 0x06;~block[len] = 0x1f;
final-pad-bit~block[rsiz - 1] |= 0x80;~block[rsiz - 1] |= 0x40;
tail-word~(st[full] as u32).to_le()~((st[full] >> 32) as u32).to_le()
digest-loop~for i in 0..full {~for i in 0..full.saturating_sub(1) {
init-partial~ptr::write_bytes(st, 0, 25)~ptr::write_bytes(st, 0, 24)
absorb-one-word-short~for i in 0..rsizw {~for i in 0..rsizw.saturating_sub(1) {
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" "$out/vec.txt" 600000
