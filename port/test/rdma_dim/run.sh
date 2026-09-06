#!/usr/bin/env bash
# port/test/rdma_dim/run.sh -- end-to-end differential for rdma_dim(),
# driving the whole exported function on both arms over a shared struct
# dim and comparing the entire struct after each call. See drv.c's header
# comment for the design and why (adversary review of dc181d0/a5540e5).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/rdma-dim-diff.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

PC_DIM="$root/port/pristine/lib/dim/dim.c"
PC_RDMA="$root/port/pristine/lib/dim/rdma_dim.c"
RS_DIM="$root/port/tree/lib/dim/dim_rs.rs"
RS_RDMA="$root/port/tree/lib/dim/rdma_dim_rs.rs"
THUNK="$root/port/tree/lib/dim/rdma_dim_thunk.c"

for f in "$PC_DIM" "$PC_RDMA" "$RS_DIM" "$RS_RDMA" "$THUNK"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

echo "sources:"
for f in "$PC_DIM" "$PC_RDMA" "$RS_DIM" "$RS_RDMA" "$THUNK"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

probe() {  # $1 = source .rs, $2 = crate name, $3 = output .a
    {
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export};'
        echo '}'
        sed 's|^//!|//|' "$1"
    } > "$out/$2.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name "$2" -o "$out/$3" "$out/$2.rs"
}
probe "$RS_DIM" dim_rs libdim.a
probe "$RS_RDMA" rdma_dim_rs librdma.a

CF=(-O2 -g -Wall -Wno-unused-parameter -I "$here/shim")

# Pristine C reference: dim.c + rdma_dim.c compiled TOGETHER so rdma_dim.c's
# internal calls into dim_turn/dim_calc_stats get renamed consistently with
# the definitions, then rdma_dim itself renamed so it doesn't collide with
# the Rust side's real, unrenamed export.
cc "${CF[@]}" -Ddim_calc_stats=dim_calc_stats_c_ref -Ddim_on_top=dim_on_top_c_ref \
   -Ddim_turn=dim_turn_c_ref -Ddim_park_on_top=dim_park_on_top_c_ref \
   -Ddim_park_tired=dim_park_tired_c_ref -c -o "$out/pc_dim.o" "$PC_DIM"
cc "${CF[@]}" -Ddim_calc_stats=dim_calc_stats_c_ref -Ddim_turn=dim_turn_c_ref \
   -Drdma_dim=rdma_dim_c_ref -c -o "$out/pc_rdma.o" "$PC_RDMA"
cc "${CF[@]}" -c -o "$out/ktime_shim.o" "$here/ktime_shim.c"
cc "${CF[@]}" -c -o "$out/thunk.o" "$THUNK"
cc "${CF[@]}" -I "$here" -c -o "$out/drv.o" "$here/drv.c"

# librdma.a's real Rust rdma_dim() calls dim_turn/dim_calc_stats, which
# live in libdim.a -- order matters for static-archive resolution, so
# librdma.a comes first to create the undefined refs libdim.a then resolves.
cc -o "$out/t" "$out/drv.o" "$out/pc_dim.o" "$out/pc_rdma.o" "$out/ktime_shim.o" \
   "$out/thunk.o" "$out/librdma.a" "$out/libdim.a"

# The arrangement proves itself FIRST, by the printed verdict, not the exit
# code alone -- a segfault also exits nonzero while verifying nothing
# (port/test/dim/run.sh's own fixed mistake).
RDMA_DIM_PROVE_CAN_FAIL=1 "$out/t" >"$out/pcf.log" 2>&1 || true
if ! grep -q "PROVE_CAN_FAIL_VERDICT: mismatch correctly detected" "$out/pcf.log"; then
    echo "*** THE HARNESS CANNOT DISAGREE -- no verdict, or poisoned run reported no mismatch"
    cat "$out/pcf.log"
    exit 1
fi
echo "prove-can-fail: poisoned input is detected"

"$out/t" "${1:-20000}" "${2:-20260906}"
