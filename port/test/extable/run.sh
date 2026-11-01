#!/usr/bin/env bash
# port/test/extable/run.sh -- the userspace differential for lib/extable's
# sort_extable()/search_extable().
#
# WHY IT EXISTS. A prove-can-fail sabotage (reversing cmp_ex_sort's
# comparison) built a kernel that still booted clean, wall time unchanged,
# no faults -- this project's minimal busybox init never triggers a
# recoverable fault, so search_extable() was never exercised. Boot alone is
# not a proof caller for this file; this harness is.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/extable"
out="${TMPDIR:-/tmp}/extable-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/extable.c"
RS="$root/port/tree/lib/extable_rs.rs"
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
    --crate-name extable_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
REN=(-Dsort_extable=c_sort_extable -Dsearch_extable=c_search_extable)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if EXTABLE_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
