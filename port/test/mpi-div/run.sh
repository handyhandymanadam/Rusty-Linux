#!/usr/bin/env bash
# port/test/mpi-div/run.sh -- the userspace differential for
# lib/crypto/mpi/mpi-div.c and lib/crypto/mpi/mpi-mod.c.
#
# SCOPE: mpi_fdiv_r/mpi_tdiv_r/mpi_tdiv_qr (mpi-div.c -> mpi_div_rs.rs) and
# mpi_mod (mpi-mod.c -> mpi_mod_rs.rs, a one-line wrapper around
# mpi_fdiv_r) -- built and checked together since mpi_mod's only job is to
# call mpi_fdiv_r, per rusty-linux-e6's task message.
#
# Shared dependencies pulled in as real code, not stubs: mpiutil_rs (alloc/
# resize/copy/free), mpi_add_rs (mpi_add, used by mpi_fdiv_r's
# temp_divisor path), mpih_div_rs + generic_mpih_rs (mpihelp_mod_1/
# divmod_1/divrem/lshift/rshift) -- all already independently verified by
# their own harnesses; not under test here.
#
# THE RUST IS GENERATED from the files the kernel builds, not copied. The C
# is port/pristine/, not the tree.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpi-div"
out="${TMPDIR:-/tmp}/mpidiv-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C_DIV="$root/port/pristine/lib/crypto/mpi/mpi-div.c"
C_MOD="$root/port/pristine/lib/crypto/mpi/mpi-mod.c"
RS_DIV="$root/port/tree/lib/crypto/mpi/mpi_div_rs.rs"
RS_MOD="$root/port/tree/lib/crypto/mpi/mpi_mod_rs.rs"
RS_UTIL="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
RS_ADD="$root/port/tree/lib/crypto/mpi/mpi_add_rs.rs"
RS_DIVHELP="$root/port/tree/lib/crypto/mpi/mpih_div_rs.rs"
RS_MPIH="$root/port/tree/lib/crypto/mpi/generic_mpih_rs.rs"
for f in "$C_DIV" "$C_MOD" "$RS_DIV" "$RS_MOD" "$RS_UTIL" "$RS_ADD" "$RS_DIVHELP" "$RS_MPIH"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

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
gen_rs "$RS_UTIL" "$out/probe_util.rs"
gen_rs "$RS_ADD" "$out/probe_add.rs"
gen_rs "$RS_DIVHELP" "$out/probe_divhelp.rs"
gen_rs "$RS_MPIH" "$out/probe_mpih.rs"
gen_rs "$RS_DIV" "$out/probe_div.rs"
gen_rs "$RS_MOD" "$out/probe_mod.rs"

RUSTC_FLAGS=(--edition 2021 --crate-type staticlib -O
             -C panic=abort -C overflow-checks=on
             -D unsafe_op_in_unsafe_fn -D warnings)
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpiutil_rs -o "$out/libutil.a" "$out/probe_util.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_add_rs -o "$out/libadd.a" "$out/probe_add.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpih_div_rs -o "$out/libdivhelp.a" "$out/probe_divhelp.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name generic_mpih_rs -o "$out/libmpih.a" "$out/probe_mpih.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_div_rs -o "$out/libdiv.a" "$out/probe_div.rs"
"$KB_RUSTC" "${RUSTC_FLAGS[@]}" --crate-name mpi_mod_rs -o "$out/libmod.a" "$out/probe_mod.rs"

# The real mpi-internal.h/longlong.h shims below cover only count_leading_
# zeros -- mpi-div.c's only direct use of that header, everything else
# (udiv_qrnnd etc.) lives inside the already-separately-verified
# mpihelp_* functions. See shim/longlong.h's own comment.
CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmpi_fdiv_r=c_mpi_fdiv_r -Dmpi_tdiv_r=c_mpi_tdiv_r -Dmpi_tdiv_qr=c_mpi_tdiv_qr)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c_div.o" "$C_DIV"
cc "${CF[@]}" -Dmpi_mod=c_mpi_mod -c -o "$out/c_mod.o" "$C_MOD"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/c_div.o" "$out/c_mod.o" \
    "$out/libdiv.a" "$out/libmod.a" "$out/libdivhelp.a" "$out/libmpih.a" \
    "$out/libadd.a" "$out/libutil.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIDIV_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
