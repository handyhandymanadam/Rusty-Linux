#!/usr/bin/env bash
# port/test/dynamic_queue_limits/run.sh -- the userspace differential for
# lib/dynamic_queue_limits.c.
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. The C is
# port/pristine/, not the tree. See drv.c's header comment for the harness
# shape (shared jiffies, full-struct memcmp, BUG_ON/tracepoint recording).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/dynamic_queue_limits"
out="${TMPDIR:-/tmp}/dql-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/dynamic_queue_limits.c"
RS="$root/port/tree/lib/dynamic_queue_limits_rs.rs"
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
    --crate-name dynamic_queue_limits_rs -o "$out/librs.a" "$out/probe.rs"

RENAME=(
    -Ddql_completed=cref_dql_completed
    -Ddql_reset=cref_dql_reset
    -Ddql_init=cref_dql_init
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")
cc "${CF[@]}" "${RENAME[@]}" -c -o "$out/c.o" "$C"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if DQL_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t"
