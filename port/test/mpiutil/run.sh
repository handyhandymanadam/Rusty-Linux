#!/usr/bin/env bash
# port/test/mpiutil/run.sh -- the userspace differential for
# lib/crypto/mpi/mpiutil.c.
#
# SCOPE: mpi_alloc/mpi_free (EXPORT_SYMBOL_GPL) plus mpi_alloc_limb_space/
# mpi_free_limb_space/mpi_assign_limb_space/mpi_resize/mpi_copy (not
# exported, but real symbols other still-C files in lib/crypto/mpi/ call
# directly). The allocation shape is logs/allocation.md's standing
# exception -- kmalloc/kcalloc/kfree/kfree_sensitive stay in a small
# retained C thunk, same as lib/generic-radix-tree.c's rust_genradix_*
# pair, just with four wrappers instead of two. See drv.c's own header
# comment for why the comparison is over struct fields and buffer
# contents, never pointer identity.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C
# is port/pristine/, not the tree.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/mpiutil"
out="${TMPDIR:-/tmp}/mpiutil-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/mpi/mpiutil.c"
RS="$root/port/tree/lib/crypto/mpi/mpiutil_rs.rs"
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
    --crate-name mpiutil_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dmpi_alloc=c_mpi_alloc -Dmpi_free=c_mpi_free
     -Dmpi_alloc_limb_space=c_mpi_alloc_limb_space
     -Dmpi_free_limb_space=c_mpi_free_limb_space
     -Dmpi_assign_limb_space=c_mpi_assign_limb_space
     -Dmpi_resize=c_mpi_resize -Dmpi_copy=c_mpi_copy)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if MPIUTIL_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
