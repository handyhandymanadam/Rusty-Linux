#!/usr/bin/env bash
# port/test/generic-radix-tree/run.sh -- the userspace differential for
# lib/generic-radix-tree.c.
#
# SCOPE: single-threaded logic only -- see drv.c's own header comment for
# exactly what this does and does not prove. No caller of this code exists
# in either build config's boot path, so nothing here is exercised at boot.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/generic-radix-tree"
out="${TMPDIR:-/tmp}/genradix-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/generic-radix-tree.c"
RS="$root/port/tree/lib/generic_radix_tree_rs.rs"
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
    --crate-name generic_radix_tree_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(
    -D__genradix_ptr=c___genradix_ptr
    -D__genradix_ptr_alloc=c___genradix_ptr_alloc
    -D__genradix_iter_peek=c___genradix_iter_peek
    -D__genradix_iter_peek_prev=c___genradix_iter_peek_prev
    -D__genradix_prealloc=c___genradix_prealloc
    -D__genradix_free=c___genradix_free
)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if GENRADIX_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
