#!/usr/bin/env bash
# Differential test for lib/xarray.c -> port/tree/lib/xarray_rs.rs.
#
#   run.sh [runs] [seed]
#   run.sh --selfcheck [runs] [seed]   # ref vs ref: proves the harness only
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
# XA_CHUNK_SHIFT is overridden to 4 (shim/linux/kernel.h) for corpus
# depth -- both arms see the same override, since both include the same
# real include/linux/xarray.h through this harness's own shim.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/xarray-difftest.$$"

self=0
if [ "${1:-}" = "--selfcheck" ]; then self=1; shift; fi

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

XARRAY="$root/port/pristine/lib/xarray.c"
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux-6.18.49/include")

echo "sources:"
for f in "$root/port/tree/lib/xarray_rs.rs" "$XARRAY"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)
LINTS=(-D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs
       -W rust_2018_idioms -W unreachable_pub -A stable_features
       -A unused_features -D warnings)

if [ "$self" = 0 ]; then
    echo "config sweep: xarray_rs.rs builds for x86_64 and aarch64, MULTI on and off"
    # CONFIG_XARRAY_MULTI is NOT always on for this project: build-full
    # has it, build-fast does not (verified by reading .config, after an
    # earlier comment in xarray_rs.rs claimed otherwise without
    # checking). Sweeping both states here is what would have caught,
    # at write time rather than by hand later, the 7 exports/4 helpers
    # that need #[cfg(CONFIG_XARRAY_MULTI)] to avoid becoming dead code
    # in the off state.
    swept_nonx86=0
    swept_nomulti=0
    for t in x86_64-unknown-linux-gnu aarch64-unknown-none; do
        # kernel::kabi_export!/kabi_rule! stand-ins, a REAL separate crate
        # (not a same-file module) -- see kernel_stub.rs's own comment.
        # rlibs are target-specific, so built once per target swept.
        RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -Z crate-attr=no_std --target "$t" \
            --crate-name kernel -o "$out/libkernel-$t.rlib" "$here/kernel_stub.rs"
        for multi_cfg in "--cfg CONFIG_XARRAY_MULTI" ""; do
            multi_name="multi"
            [ -z "$multi_cfg" ] && multi_name="nomulti"
            if RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
                -C panic=abort -Z crate-attr=no_std $multi_cfg "${LINTS[@]}" \
                --extern kernel="$out/libkernel-$t.rlib" \
                --target "$t" --crate-name sweep --emit=metadata \
                -o "$out/sweep-$t-$multi_name.rmeta" \
                "$root/port/tree/lib/xarray_rs.rs" \
                2>"$out/sweep.err"
            then
                echo "  ok  $t ($multi_name)"
                case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
                [ "$multi_name" = nomulti ] && swept_nomulti=1
            else
                sed -n '1,20p' "$out/sweep.err"; echo "  FAIL $t ($multi_name)"; exit 1
            fi
        done
    done
    [ "$swept_nonx86" = 1 ] || { echo "  UNSWEPT: no non-x86 target"; exit 1; }
    [ "$swept_nomulti" = 1 ] || { echo "  UNSWEPT: no CONFIG_XARRAY_MULTI=n arm"; exit 1; }
    echo

    "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
        --crate-name kernel -o "$out/libkernel-host.rlib" "$here/kernel_stub.rs"
    # --cfg xa_harness_small_chunk is NOT optional here: the C reference
    # (via shim/linux/kernel.h) always builds with XA_CHUNK_SHIFT=4.
    # Without this flag the Rust arm builds with the real kernel's
    # XA_CHUNK_SHIFT=6 instead, and the two arms silently shard the same
    # index space differently -- structurally wrong, but not wrong
    # often enough to show up before a few hundred ops.
    # --cfg CONFIG_XARRAY_MULTI is likewise not optional: the shim's
    # kernel.h unconditionally #defines CONFIG_XARRAY_MULTI 1 for the C
    # reference (real config on either build-fast or build-full would
    # do, but the reference needs ONE fixed choice); without this flag
    # the Rust arm drops xas_get_order/xas_split/xas_split_alloc/
    # xas_try_split/xas_try_split_min_order/xa_get_order/xa_store_range
    # entirely (see their #[cfg(CONFIG_XARRAY_MULTI)] gates) while the C
    # reference keeps them, an undefined-reference link failure rather
    # than a silent one -- still worth being explicit about, since a
    # future refactor could plausibly make it link clean and silently
    # wrong instead.
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        --cfg xa_harness_small_chunk --cfg CONFIG_XARRAY_MULTI \
        "${LINTS[@]}" -A unreachable_pub \
        --extern kernel="$out/libkernel-host.rlib" \
        --crate-name xarray_rs \
        -o "$out/libxarray_rs.a" "$here/probe.rs"
fi

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_xarray.o" "$here/ref_xarray.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/radix_tree_stub.o" "$here/radix_tree_stub.c"
# call_rcu() is a real (non-static) symbol declared, not defined, by
# shim/linux/rcupdate.h -- needed by ref_xarray.c/radix_tree_stub.c in
# BOTH modes, and by the Rust arm's own extern "C" call_rcu in the
# non-selfcheck build.
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/rust_helpers_stub.o" "$here/rust_helpers_stub.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"

if [ "$self" = 1 ]; then
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/selfcheck.o" "$here/selfcheck.c"
    cc -rdynamic -o "$out/difftest" "$out"/*.o
else
    cc -rdynamic -o "$out/difftest" "$out"/*.o "$out/libxarray_rs.a"
fi

cd "$root"
"$out/difftest" "${1:-200}" "${2:-20260906}"
