#!/usr/bin/env bash
# port/test/rsa/run.sh -- differential for crypto/rsa.c (RSAEP / RSADP-CRT, key loading, size and FIPS exponent rules).
#   run.sh             both builds (FIPS unset = both kernel configs, and the CONFIG_CRYPTO_FIPS arm run with fips_enabled 0 and 1)
#   run.sh --sabotage  mutants of the Rust must each be caught
# C arm = the UNMODIFIED port/pristine/crypto/rsa.c compiled as a userspace TU; Rust arm = port/tree/crypto/rsa_glue.c +
# port/tree/crypto/rsa_rs.rs; both over mpi_mock.c (GMP, fault injection at every MPI creation and operation, call trace,
# live-object count); oracle = GMP (main.c). Needs libgmp (gmp-devel).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/rsa"
out="${TMPDIR:-/tmp}/rsa-diff.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="$root/port/pristine/crypto/rsa.c"
G="$root/port/tree/crypto/rsa_glue.c"
RS="${RSA_RS:-$root/port/tree/crypto/rsa_rs.rs}"
for f in "$C" "$G" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
build() {   # build <rs> <dir> <fips 0|1>
    mkdir -p "$2"
    { echo 'mod kernel {}'; sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    local cfg=() cdef=()
    if [ "$3" = 1 ]; then cfg=(--cfg 'CONFIG_CRYPTO_FIPS'); cdef=(-DFIPS); fi
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on "${cfg[@]}" \
        --check-cfg 'cfg(CONFIG_CRYPTO_FIPS)' --check-cfg 'cfg(kani)' -D unsafe_op_in_unsafe_fn -D warnings --crate-name rsa_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O1 -w "${cdef[@]}" -I "$here/shim" -DPRISTINE_RSA="\"$C\"" -c -o "$2/c_arm.o" "$here/c_arm.c"
    cc -O1 -w "${cdef[@]}" -I "$here/shim" -DGLUE_RSA="\"$G\"" -c -o "$2/r_arm.o" "$here/r_arm.c"
    cc -O1 -w "${cdef[@]}" -I "$here/shim" -c -o "$2/mock.o" "$here/mpi_mock.c"
    cc -O2 -Wall "${cdef[@]}" -I "$here/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c_arm.o" "$2/r_arm.o" "$2/mock.o" "$2/librs.a" -lgmp
}
# run.sh --object <rsa_rs.o>: link the REAL object the kernel build produced (CONFIG_CRYPTO_FIPS unset, as in both kernel
# configs; kernel flags, retpoline thunks stubbed) instead of re-compiling the Rust.
if [ "${1:-}" = "--object" ]; then
    obj=${2:?usage: run.sh --object <build-dir>/crypto/rsa_rs.o}
    mkdir -p "$out/obj"
    cc -O1 -w -I "$here/shim" -DPRISTINE_RSA="\"$C\"" -c -o "$out/obj/c_arm.o" "$here/c_arm.c"
    cc -O1 -w -I "$here/shim" -DGLUE_RSA="\"$G\"" -c -o "$out/obj/r_arm.o" "$here/r_arm.c"
    cc -O1 -w -I "$here/shim" -c -o "$out/obj/mock.o" "$here/mpi_mock.c"
    cc -O2 -Wall -I "$here/shim" -c -o "$out/obj/main.o" "$here/main.c"
    cc -c -o "$out/obj/thunks.o" "$here/thunks.S"
    cc -o "$out/obj/t" "$out/obj/main.o" "$out/obj/c_arm.o" "$out/obj/r_arm.o" "$out/obj/mock.o" "$obj" "$out/obj/thunks.o" -lgmp
    echo "object: $obj ($(sha256sum "$obj" | cut -c1-16))"
    if "$out/obj/t" --poison >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "prove-can-fail: poisoned result detected"
    "$out/obj/t"
    exit 0
fi
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/plain" 0
build "$RS" "$out/fips" 1
if "$out/plain/t" --poison >/dev/null 2>&1 || "$out/fips/t" --poison >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "prove-can-fail: poisoned Rust result detected in both builds"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0; eq=0; eqok=0; nocomp=0
    mut() {   # mut <name> <from> <to> [nth] [equiv]
        python3 - "$RS" "$out/mut.rs" "$2" "$3" "${4:-1}" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b, nth = sys.argv[3], sys.argv[4], int(sys.argv[5])
assert s.count(a) >= nth, "pattern missing: " + a
i = -1
for _ in range(nth): i = s.index(a, i + 1)
open(sys.argv[2], "w").write(s[:i] + b + s[i + len(a):])
PY
        n=$((n+1)); build "$out/mut.rs" "$out/m$n" 1 >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; nocomp=$((nocomp+1)); n=$((n-1)); return 0; }
        if "$out/m$n/t" >/dev/null 2>&1; then
            if [ "${5:-}" = equiv ]; then echo "equivalent mutant $1: not seen (as expected)"; eqok=$((eqok+1)); eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: *** NOT CAUGHT"; fi
        else
            if [ "${5:-}" = equiv ]; then echo "equivalent mutant $1: SEEN -- not equivalent"; eq=$((eq+1)); n=$((n-1))
            else echo "mutant $1: caught"; caught=$((caught+1)); fi
        fi
    }
    . "$here/mutants.inc"
    echo "$caught of $n mutants caught; $eqok of $eq equivalent mutants unseen; $nocomp did not compile"
    [ "$caught" = "$n" ] && [ "$eqok" = "$eq" ] && [ "$nocomp" = 0 ]; exit
fi
"$out/plain/t"
"$out/fips/t"
