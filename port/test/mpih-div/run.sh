#!/usr/bin/env bash
# port/test/mpih-div/run.sh -- the userspace differential for
# lib/crypto/mpi/mpih-div.c.
#
# SCOPE: mpihelp_mod_1, mpihelp_divmod_1, mpihelp_divrem -- none exported,
# all real symbols mpi-div.c calls directly.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C
# is port/pristine/, not the tree. longlong.h is NOT shimmed -- the real
# upstream file is on the include path (after the shim dir), because its
# udiv_qrnnd/umul_ppmm/add_ssaaaa/sub_ddmmss macros are exactly what the C
# arm is compiled against and what this differential checks the Rust
# reimplementation against.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpih-div"
out="${TMPDIR:-/tmp}/mpihdiv-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpih-div.c"
RS="$root/port/tree/lib/crypto/mpi/mpih_div_rs.rs"
RS_MPIH="$root/port/tree/lib/crypto/mpi/generic_mpih_rs.rs"
for f in "$C" "$RS" "$RS_MPIH"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

gen_rs() {
    {
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        sed 's|^//!|//|' "$1"
    } > "$2"
}
gen_rs "$RS" "$out/probe_div.rs"
gen_rs "$RS_MPIH" "$out/probe_mpih.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpih_div_rs -o "$out/libdiv.a" "$out/probe_div.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name generic_mpih_rs -o "$out/libmpih.a" "$out/probe_mpih.rs"

# The real longlong.h, AFTER the shim directory, for the same reason
# port/test/mpi-add/run.sh uses the real mpi-inline.h.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim" -I "$root/src/linux/lib/crypto/mpi")
REN=(-Dmpihelp_mod_1=c_mpihelp_mod_1 -Dmpihelp_divmod_1=c_mpihelp_divmod_1 -Dmpihelp_divrem=c_mpihelp_divrem)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/libdiv.a" "$out/libmpih.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIHDIV_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
