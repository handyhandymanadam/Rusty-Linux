#!/usr/bin/env bash
# port/test/mpi-cmp/run.sh -- the userspace differential for
# lib/crypto/mpi/mpi-cmp.c.
#
# SCOPE: mpi_cmp()/mpi_cmp_ui() logic only. mpi_normalize() and
# mpihelp_cmp() are shared reference support code in drv.c, not what's
# under test -- see drv.c's own header comment.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpi-cmp"
out="${TMPDIR:-/tmp}/mpicmp-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpi-cmp.c"
RS="$root/port/tree/lib/crypto/mpi/mpi_cmp_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

{
    echo '#![allow(non_snake_case)]'
    echo '#[allow(unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
    echo '}'
    sed 's|^//!|//|' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name mpi_cmp_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim" -I "$here/shim/linux")
REN=(-Dmpi_cmp_ui=c_mpi_cmp_ui -Dmpi_cmp=c_mpi_cmp)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPICMP_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
