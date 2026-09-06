#!/usr/bin/env bash
# port/test/find_bit/run.sh -- the userspace differential for lib/find_bit.c.
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. The C is
# port/pristine/, not the tree. Random bitmaps, 200,000 iterations, all 17
# live exported symbols. See drv.c's header comment for the rest.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/find_bit"
out="${TMPDIR:-/tmp}/find_bit-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/find_bit.c"
RS="$root/port/tree/lib/find_bit_rs.rs"
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
    --crate-name find_bit_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=(
    -D_find_first_bit=cref__find_first_bit
    -D_find_first_and_bit=cref__find_first_and_bit
    -D_find_first_andnot_bit=cref__find_first_andnot_bit
    -D_find_first_and_and_bit=cref__find_first_and_and_bit
    -D_find_first_zero_bit=cref__find_first_zero_bit
    -D_find_next_bit=cref__find_next_bit
    -D__find_nth_bit=cref__find_nth_bit
    -D__find_nth_and_bit=cref__find_nth_and_bit
    -D__find_nth_andnot_bit=cref__find_nth_andnot_bit
    -D__find_nth_and_andnot_bit=cref__find_nth_and_andnot_bit
    -D_find_next_and_bit=cref__find_next_and_bit
    -D_find_next_andnot_bit=cref__find_next_andnot_bit
    -D_find_next_or_bit=cref__find_next_or_bit
    -D_find_next_zero_bit=cref__find_next_zero_bit
    -D_find_last_bit=cref__find_last_bit
    -Dfind_next_clump8=cref_find_next_clump8
    -Dfind_random_bit=cref_find_random_bit
    # __bitmap_weight and __get_random_u32_below are drv.c's OWN real
    # definitions -- rename the C's calls to bitmap_weight()/
    # get_random_u32_below() (its shim headers) so nothing collides;
    # the shim headers already call straight through to the real
    # (unrenamed) __bitmap_weight/__get_random_u32_below drv.c defines.
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
cc "${CF[@]}" "${RENAME[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if FB_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
