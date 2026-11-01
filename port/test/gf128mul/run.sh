#!/usr/bin/env bash
# port/test/gf128mul/run.sh [--sabotage] [N]  -- differential for
#   lib/crypto/gf128mul.c -> gf128mul_glue.c + gf128mul_rs.rs
#   subject  : glue (C thunks + allocation) + the Rust, compiled as the kernel does
#   oracle A : the PRISTINE upstream gf128mul.c, public names renamed ref_*
#   oracle B : independent bit-by-bit C references (main.c)
# Not covered: the constant-time property; the kernel build (kbuild flags, real
# kzalloc/EXPORT_SYMBOL/module machinery -- shimmed here); the C glue under
# CONFIG_RUST=n (that arm is the pristine file by construction).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/gf128mul"
out="${TMPDIR:-/tmp}/gf128mul-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
RS="$root/port/tree/lib/crypto/gf128mul_rs.rs"
GLUE="$root/port/tree/lib/crypto/gf128mul_glue.c"
PRIS="$root/port/pristine/lib/crypto/gf128mul.c"
for f in "$RS" "$GLUE" "$PRIS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
INC="-I $here/shim -I $root/src/linux/include"
REN=""; for s in gf128mul_x8_ble gf128mul_lle gf128mul_init_64k_bbe gf128mul_free_64k gf128mul_64k_bbe gf128mul_init_4k_lle gf128mul_4k_lle; do REN="$REN -D$s=ref_$s"; done
build() {   # build <rs> <glue> <dir>
    mkdir -p "$3"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name gf128mul_rs -o "$3/librs.a" "$1"
    cc -O2 -Wall $INC -c -o "$3/glue.o" "$2"
    cc -O2 -Wall $INC $REN -c -o "$3/ref.o" "$PRIS"
    cc -O2 -Wall -Wno-unused-function $INC -c -o "$3/main.o" "$here/main.c"
    cc -o "$3/t" "$3/main.o" "$3/glue.o" "$3/ref.o" "$3/librs.a"
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$GLUE" "$out/real"
if GF128_PROVE_CAN_FAIL=1 "$out/real/t" 200 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned subject output detected"
if GF128_PROVE_BASIS_CAN_FAIL=1 "$out/real/t" 200 >/dev/null 2>&1; then echo "*** ORACLE B CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: a wrong reduction polynomial in oracle B is detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0; i=0
    for kind in rs glue; do
        src=$RS; [ $kind = glue ] && src=$GLUE
        i=0
        while :; do
            i=$((i+1)); ext=rs; [ $kind = glue ] && ext=c
            set +e; name=$(python3 "$here/mutants.py" "$src" $i "$out/mut.$ext"); rc=$?; set -e
            [ $rc = 3 ] && break
            [ $rc = 0 ] || { echo "mutant $i: harness error"; exit 1; }
            n=$((n+1))
            if [ $kind = rs ]; then build "$out/mut.rs" "$GLUE" "$out/m$n" >/dev/null 2>&1; else build "$RS" "$out/mut.c" "$out/m$n" >/dev/null 2>&1; fi || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
            if timeout 300 "$out/m$n/t" 3000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
            rm -rf "$out/m$n"
        done
    done
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
"$out/real/t" "${1:-300000}"
