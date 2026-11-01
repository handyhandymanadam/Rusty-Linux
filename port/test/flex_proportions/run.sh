#!/usr/bin/env bash
# port/test/flex_proportions/run.sh -- differential test for
# lib/flex_proportions.c -> lib/flex_proportions_rs.rs. See drv.c's header
# comment for the harness shape, especially why fprop_new_period() itself
# cannot be called here (real cli/sti, faults in userspace).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/flexprop-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC="$root/port/pristine/lib/flex_proportions.c"
RC="$root/port/tree/lib/flex_proportions.c"
RS="$root/port/tree/lib/flex_proportions_rs.rs"

for f in "$PC" "$RC" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

echo "sources:"
for f in "$PC" "$RC" "$RS"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# flex_proportions_rs.rs uses no kernel::kabi_* macros at all (no
# EXPORT_SYMBOL in the pristine C), so it compiles directly, no stub
# wrapper needed.
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name flex_proportions_rs -o "$out/librs.a" "$RS"

RENAME=(
    -Dfprop_global_init=fprop_global_init_c_ref
    -Dfprop_global_destroy=fprop_global_destroy_c_ref
    -Dfprop_new_period=fprop_new_period_c_ref
    -Dfprop_local_init_percpu=fprop_local_init_percpu_c_ref
    -Dfprop_local_destroy_percpu=fprop_local_destroy_percpu_c_ref
    -D__fprop_add_percpu=fprop_add_percpu_c_ref
    -D__fprop_add_percpu_max=fprop_add_percpu_max_c_ref
    -Dfprop_fraction_percpu=fprop_fraction_percpu_c_ref
)

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

cc "${CF[@]}" "${RENAME[@]}" -c -o "$out/pc.o" "$PC"
cc "${CF[@]}" -c -o "$out/rc.o" "$RC"
cc "${CF[@]}" -c -o "$out/shim.o" "$here/shim.c"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

cc -o "$out/t" "$out/drv.o" "$out/pc.o" "$out/rc.o" "$out/shim.o" "$out/librs.a"

# The arrangement proves itself FIRST, before its clean run is believed.
if FLEXPROP_PROVE_CAN_FAIL=1 "$out/t" >/dev/null 2>&1; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-20000}" "${2:-20260906}"
