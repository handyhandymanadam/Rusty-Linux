#!/usr/bin/env bash
# Layout test 1/2 for lib/xarray.c -> port/tree/lib/xarray_rs.rs.
#
# Full-struct sizeof/offsetof comparison between the REAL C (via the
# real include/linux/xarray.h, NOT the differential's shim, which
# deliberately runs a different XA_CHUNK_SHIFT for corpus depth -- see
# xarray_rs.rs's own module doc on why that harness's layout is never
# evidence for this test) and xarray_rs.rs's own #[repr(C)] mirrors,
# for BOTH CONFIG_BASE_SMALL arms.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
out="${TMPDIR:-/tmp}/xarray-layout.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

status=0
for arm in 0 1; do
    name="real-config"
    [ "$arm" = 1 ] && name="CONFIG_BASE_SMALL"
    echo "=== $name (CONFIG_BASE_SMALL=$arm) ==="

    cc -O2 -DCONFIG_BASE_SMALL="$arm" \
        -I "$here/shim" -I "$root/port/test/common/shim" \
        -I "$root/src/linux-6.18.49/include" \
        -o "$out/c-$arm" "$here/layout_probe.c"

    rustc_cfg=(--cfg xa_layout_probe)
    [ "$arm" = 1 ] && rustc_cfg+=(--cfg xa_harness_small_chunk)
    # xarray_rs.rs now carries kernel::kabi_export!/kabi_rule! blocks
    # (inserted by rig/kabi-migrate.py) -- needs the same kernel_stub.rs
    # crate the differential harness (run.sh) links against.
    "$KB_RUSTC" --edition 2021 --crate-type rlib \
        --crate-name kernel -o "$out/libkernel.rlib" "$here/../kernel_stub.rs"
    "$KB_RUSTC" --edition 2021 "${rustc_cfg[@]}" \
        --extern kernel="$out/libkernel.rlib" \
        -o "$out/rs-$arm" "$here/layout_probe.rs" 2>"$out/rustc-$arm.err" \
        || { cat "$out/rustc-$arm.err"; exit 1; }

    "$out/c-$arm" | sort > "$out/c-$arm.sorted"
    "$out/rs-$arm" | sort > "$out/rs-$arm.sorted"

    if diff -u "$out/c-$arm.sorted" "$out/rs-$arm.sorted"; then
        echo "  OK: identical"
    else
        echo "  MISMATCH"
        status=1
    fi
    echo
done

echo "=== workingset.c field-access shim (test 2/2) ==="
cc -O2 -Wall -Wextra -Wno-unused-parameter -DCONFIG_BASE_SMALL=0 \
    -I "$here/shim" -I "$root/port/test/common/shim" \
    -I "$root/src/linux-6.18.49/include" \
    -o "$out/workingset_shim" "$here/workingset_shim.c"
if "$out/workingset_shim"; then
    :
else
    status=1
fi
echo

exit "$status"
