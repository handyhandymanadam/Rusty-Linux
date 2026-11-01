#!/usr/bin/env bash
# port/test/ghash_generic/run.sh [--sabotage] -- differential for crypto/ghash-generic.c
#   pristine C callbacks vs Rust, both over the PRISTINE (upstream) lib/crypto/gf128mul.c,
#   plus a pure-Python NIST SP 800-38D GHASH as an independent oracle.
# Scope: init/setkey/update/finup/exit bodies. NOT the GF(2^128) multiply
# (gf128mul.c, still C) and NOT the shash_alg table (C glue, exercised in the
# kernel by libtest.c through the crypto API).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/ghash_generic"
out="${TMPDIR:-/tmp}/ghash-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/ghash-generic.c"
RS="$root/port/tree/crypto/ghash_rs.rs"
# oracle: upstream gf128mul.c from port/pristine (the tree file is the Rust glue now)
GF="$root/port/pristine/lib/crypto/gf128mul.c"
for f in "$C" "$RS" "$GF"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
INC="-I $here/shim -I $root/src/linux/include"
python3 "$here/extract.py" "$C" "$out/extract.c"
sed "s|EXTRACT|$out/extract.c|" "$here/ref.c" > "$out/ref.c"
python3 "$here/vectors.py" 5 > "$out/vec.txt"
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name ghash_rs -o "$2/librs.a" "$1"
    cc -O2 -Wall -Wno-unused-function $INC -c -o "$2/ref.o" "$out/ref.c"
    cc -O2 -Wall $INC -c -o "$2/gf.o" "$GF"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/gf.o" "$2/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
if GHASH_PROVE_CAN_FAIL=1 "$out/real/t" "$out/vec.txt" 1000 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned output detected"
if GHASH_PROVE_BASIS_CAN_FAIL=1 "$out/real/t" - 100 >/dev/null 2>&1; then echo "*** BASIS CHECK CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: a wrong reduction polynomial in the NIST multiply is detected by the basis check"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; assert s.count(f)>=1, f; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" "$out/vec.txt" 5000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
keylen-check~if keylen as usize != GHASH_BLOCK_SIZE {~if keylen as usize > GHASH_BLOCK_SIZE {
no-free-old~kfree_sensitive((*slot).cast());~let _ = 0;
einval-code~return -EINVAL;~return -EINVAL + 1;
enomem-code~return -ENOMEM;~return -ENOMEM + 1;
exit-no-free~pub unsafe extern "C" fn crypto_ghash_rs_exit(slot: *mut *mut Gf128mul4k) {~pub unsafe extern "C" fn crypto_ghash_rs_exit(slot: *mut *mut Gf128mul4k) { if true { return; }
update-xor-short~for i in 0..GHASH_BLOCK_SIZE {~for i in 0..GHASH_BLOCK_SIZE - 1 {
update-remainder~srclen.wrapping_sub(GHASH_BLOCK_SIZE as u32)~srclen.wrapping_sub(GHASH_BLOCK_SIZE as u32 + 1)
finup-xor-short~for i in 0..len as usize {~for i in 0..(len as usize).saturating_sub(1) {
finup-mul-guard~if len != 0 {~if len > 1 {
init-short~ptr::write_bytes(buffer, 0, GHASH_BLOCK_SIZE)~ptr::write_bytes(buffer, 0, GHASH_BLOCK_SIZE - 1)
key-copy-short~ptr::copy_nonoverlapping(key, k.0.as_mut_ptr(), GHASH_BLOCK_SIZE)~ptr::copy_nonoverlapping(key, k.0.as_mut_ptr(), GHASH_BLOCK_SIZE - 1)
digest-copy-short~ptr::copy_nonoverlapping(buffer, dst, GHASH_BLOCK_SIZE)~ptr::copy_nonoverlapping(buffer, dst, GHASH_BLOCK_SIZE - 1)
MUT
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" "$out/vec.txt" 300000
