#!/usr/bin/env bash
# port/test/ratelimit/run.sh -- differential test for lib/ratelimit.c ->
# lib/ratelimit_rs.rs. See drv.c's header comment for the harness shape.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/ratelimit-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/ratelimit.c"
RC="$root/port/tree/lib/ratelimit.c"
RS="$root/port/tree/lib/ratelimit_rs.rs"

for f in "$PC" "$RC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# ratelimit_rs.rs calls kernel::kabi_rule!/kabi_export! -- stub them out,
# same shape as dynamic_queue_limits/run.sh.
{
    echo '#![allow(non_snake_case)]'
    echo '#[allow(unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_rule, kabi_export};'
    echo '}'
    sed 's|^//!|//|' "$RS"
} > "$out/probe.rs"

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name ratelimit_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

cc "${CF[@]}" -D___ratelimit=ratelimit_c_ref -c -o "$out/pc.o" "$PC"
cc "${CF[@]}" -c -o "$out/rc.o" "$RC"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/rc.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if RATELIMIT_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-20000}" "${2:-20260906}"
