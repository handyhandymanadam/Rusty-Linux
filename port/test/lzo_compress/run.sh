#!/usr/bin/env bash
# Differential test for lib/lzo/lzo1x_compress.c + lzo1x_compress_safe.c
# -> port/tree/lib/lzo/lzo1x_compress_rs.rs.
#
#   run.sh [runs] [seed]
#   run.sh --selfcheck [runs] [seed]   # ref vs ref: proves the harness only
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/lzocompress-difftest.$$"

self=0
if [ "${1:-}" = "--selfcheck" ]; then self=1; shift; fi

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/lzo"
INC=(-I "$root/port/test/lzo/shim" -I "$root/port/test/common/shim" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/lzo/lzo1x_compress_rs.rs" \
         "$P/lzo1x_compress.c" "$P/lzo1x_compress_safe.c" "$P/lzo1x_decompress_safe.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)
LINTS=(-D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs
       -W rust_2018_idioms -W unreachable_pub -A stable_features
       -A unused_features -D warnings)

if [ "$self" = 0 ]; then
    echo "config sweep: lzo1x_compress_rs.rs builds for x86_64 and aarch64"
    echo "              (no CONFIG_ fork -- unlike the zstd/huf subsystem,"
    echo "              this file's only axis is the SAFE const generic,"
    echo "              which both arms of every target build regardless)"
    swept_nonx86=0
    for t in x86_64-unknown-linux-gnu aarch64-unknown-none; do
        # kernel::kabi_export!/kabi_rule! stand-ins, a REAL separate crate
        # (not a same-file module -- see kernel_stub.rs's own comment on
        # why that would not resolve from a `#[path]`-included submodule,
        # which the sweep below treats the real file as, same as the
        # kernel build does). rlibs are target-specific, so built once per
        # target swept.
        RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -Z crate-attr=no_std --target "$t" \
            --crate-name kernel -o "$out/libkernel-$t.rlib" "$here/kernel_stub.rs"
        if RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -C panic=abort -Z crate-attr=no_std "${LINTS[@]}" \
            --extern kernel="$out/libkernel-$t.rlib" \
            --target "$t" --crate-name sweep --emit=metadata \
            -o "$out/sweep-$t.rmeta" \
            "$root/port/tree/lib/lzo/lzo1x_compress_rs.rs" \
            2>"$out/sweep.err"
        then
            echo "  ok  $t"
            case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
        else
            sed -n '1,14p' "$out/sweep.err"; echo "  FAIL $t"; exit 1
        fi
    done
    [ "$swept_nonx86" = 1 ] || { echo "  UNSWEPT: no non-x86 target"; exit 1; }
    echo

    "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
        --crate-name kernel -o "$out/libkernel-host.rlib" "$here/kernel_stub.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        "${LINTS[@]}" -A unreachable_pub \
        --extern kernel="$out/libkernel-host.rlib" \
        --crate-name lzo1x_compress_rs \
        -o "$out/liblzo1x_compress_rs.a" "$here/probe.rs"
fi

for f in ref_lzo1x_compress ref_lzo1x_compress_safe main; do
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/$f.o" "$here/$f.c"
done
# Divergence 1's proof, same shape as port/test/lzo/run.sh's decompress
# harness: the SAME pristine C, once with the 64-bit unaligned fast path
# and once without, renamed refu_*. main.c compares ref_ against refu_
# directly -- proving the fast path the Rust always takes is
# behaviour-preserving, not merely asserted.
cc "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=0 \
   -Dlzo1x_1_compress=refu_lzo1x_1_compress -Dlzorle1x_1_compress=refu_lzorle1x_1_compress \
   -c -o "$out/refu_lzo1x_compress.o" "$P/lzo1x_compress.c"
cc "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=0 \
   -Dlzo1x_1_compress_safe=refu_lzo1x_1_compress_safe -Dlzorle1x_1_compress_safe=refu_lzorle1x_1_compress_safe \
   -c -o "$out/refu_lzo1x_compress_safe.o" "$P/lzo1x_compress_safe.c"
# The round-trip oracle: the already-ported, already-tested decompressor's
# own pristine C, unrenamed (only definition of `lzo1x_decompress_safe` in
# this binary).
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/decomp.o" "$P/lzo1x_decompress_safe.c"

if [ "$self" = 1 ]; then
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/selfcheck.o" "$here/selfcheck.c"
    cc -o "$out/difftest" "$out"/*.o
else
    cc -o "$out/difftest" "$out"/*.o "$out/liblzo1x_compress_rs.a"
fi

cd "$root"
"$out/difftest" "${1:-20000}" "${2:-20260906}"
