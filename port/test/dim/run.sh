#!/usr/bin/env bash
# port/test/dim/run.sh -- differential test for lib/dim/dim.c's
# dim_calc_stats() against dim_rs.rs's dim_calc_stats(). See drv.c's header
# comment for why this file exists and what it's checking.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/dim-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/dim/dim.c"
RS="$root/port/tree/lib/dim/dim_rs.rs"

for f in "$PC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# dim_rs.rs calls kernel::kabi_rule!/kabi_export! -- stub them out, same
# shape as ratelimit/run.sh and dynamic_queue_limits/run.sh.
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
    --crate-name dim_rs -o "$out/librs.a" "$out/probe.rs"

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

cc "${CF[@]}" -Ddim_calc_stats=dim_calc_stats_c_ref -Ddim_on_top=dim_on_top_c_ref \
   -Ddim_turn=dim_turn_c_ref -Ddim_park_on_top=dim_park_on_top_c_ref \
   -Ddim_park_tired=dim_park_tired_c_ref -c -o "$out/pc.o" "$PC"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed --
# and by the printed verdict, not the exit code alone: a segfault also
# exits nonzero while verifying nothing, the mistake port/test/interval_tree/
# run.sh's v1 made and an adversary review caught here before it repeated.
DIM_PROVE_CAN_FAIL=1 "$out/t" >"$out/pcf.log" 2>&1 || true
if ! grep -q "PROVE_CAN_FAIL_VERDICT: mismatch correctly detected" "$out/pcf.log"; then
    echo "*** THE HARNESS CANNOT DISAGREE -- no verdict, or poisoned run reported no mismatch"
    cat "$out/pcf.log"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-200000}" "${2:-20260906}"
