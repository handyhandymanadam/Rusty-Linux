#!/usr/bin/env bash
# port/test/mpi-add/run.sh -- the userspace differential for
# lib/crypto/mpi/mpi-add.c and lib/crypto/mpi/mpi-sub-ui.c.
#
# SCOPE: mpi_add/mpi_sub/mpi_addm/mpi_subm (mpi-add.c -> mpi_add_rs.rs) and
# mpi_sub_ui (mpi-sub-ui.c -> mpi_sub_ui_rs.rs) -- built and checked
# together since both call the identical mpihelp_add_1/mpihelp_sub_1
# (mpi-inline.h, static inline, reproduced independently in each Rust file
# per its own module doc comment) and this harness's drv.c shares one
# from-scratch bignum reference between them. See drv.c's own header
# comment for the reference's role.
#
# THE RUST IS GENERATED from the files the kernel builds, not copied. The C
# is port/pristine/, not the tree.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpi-add"
out="${TMPDIR:-/tmp}/mpiadd-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C_ADD="$root/port/pristine/lib/crypto/mpi/mpi-add.c"
C_SUBUI="$root/port/pristine/lib/crypto/mpi/mpi-sub-ui.c"
RS_ADD="$root/port/tree/lib/crypto/mpi/mpi_add_rs.rs"
RS_SUBUI="$root/port/tree/lib/crypto/mpi/mpi_sub_ui_rs.rs"
RS_UTIL="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
RS_MPIH="$root/port/tree/lib/crypto/mpi/generic_mpih_rs.rs"
for f in "$C_ADD" "$C_SUBUI" "$RS_ADD" "$RS_SUBUI" "$RS_UTIL" "$RS_MPIH"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

gen_rs() {   # $1 = source .rs, $2 = output .rs, $3 = crate name (unused here,
             # kept for readability at call sites)
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
gen_rs "$RS_UTIL" "$out/probe_util.rs"
gen_rs "$RS_ADD" "$out/probe_add.rs"
gen_rs "$RS_SUBUI" "$out/probe_subui.rs"
gen_rs "$RS_MPIH" "$out/probe_mpih.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpiutil_rs -o "$out/libutil.a" "$out/probe_util.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_add_rs -o "$out/libadd.a" "$out/probe_add.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_sub_ui_rs -o "$out/libsubui.a" "$out/probe_subui.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name generic_mpih_rs -o "$out/libmpih.a" "$out/probe_mpih.rs"

# The real mpi-inline.h (unmodified) is on this path, AFTER the shim
# directory -- see shim/mpi-internal.h's own comment for why this must be
# the genuine upstream file rather than a copy.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim" -I "$root/src/linux/lib/crypto/mpi")
REN=(-Dmpi_add=c_mpi_add -Dmpi_sub=c_mpi_sub -Dmpi_addm=c_mpi_addm -Dmpi_subm=c_mpi_subm)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c_add.o" "$C_ADD"
cc "${CF[@]}" -Dmpi_sub_ui=c_mpi_sub_ui -c -o "$out/c_subui.o" "$C_SUBUI"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

# mpi_mod()/mpi_normalize() come from drv.c itself (a small real stand-in,
# not the pristine C) -- see drv.c's own header comment for why: neither is
# under test here, and linking the real ones would pull in mpih-div.c/
# mpih-mul.c/mpi-mul.c/mpi-bit.c's whole dependency chain for functions
# this differential does not check.
cc -o "$out/t" "$out/drv.o" "$out/c_add.o" "$out/c_subui.o" \
    "$out/libutil.a" "$out/libadd.a" "$out/libsubui.a" "$out/libmpih.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIADD_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
