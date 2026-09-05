#!/usr/bin/env bash
# port/test/cmdline/run.sh -- the userspace differential for lib/cmdline.
#
# WHY IT EXISTS. CONFIG_CMDLINE_KUNIT_TEST covers get_option() and
# get_options() and found two real defects in this port. It does not touch
# memparse(), next_arg() or parse_option_str() -- and when I wrote in-kernel
# vectors for next_arg() by reasoning about the C, I got one of them wrong and
# blamed the port. That is what an oracle is for.
#
# THE RUST IS GENERATED from the file the kernel builds, not copied. The C is
# port/pristine/, not the tree.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/cmdline"
out="${TMPDIR:-/tmp}/cmdline-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/cmdline.c"
RS="$root/port/tree/lib/cmdline_rs.rs"
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
    --crate-name cmdline_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
# The C arm's five entry points are renamed so both can be linked at once.
REN=(-Dget_option=c_get_option -Dget_options=c_get_options
     -Dmemparse=c_memparse -Dparse_option_str=c_parse_option_str
     -Dnext_arg=c_next_arg -Dget_range=c_get_range)
cc "${CF[@]}" "${REN[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if CMDLINE_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
