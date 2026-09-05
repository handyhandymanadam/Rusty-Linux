#!/usr/bin/env bash
# run-be.sh -- run the differentials BIG-ENDIAN, cross-built for s390x and
# executed under qemu-user.
#
#   port/test/common/run-be.sh [zstd_entropy|lzo|all] [runs] [seed]
#
# WHY A SEPARATE SCRIPT rather than a --be flag inside each run.sh.
#   The per-harness run.sh files are the thing the project trusts; bolting a
#   second toolchain into them risks the little-endian rig for the sake of the
#   big-endian one. This duplicates their build lines instead, which is a real
#   cost -- IT CAN DRIFT. If a run.sh changes, this must be changed with it.
#   Folding the two together is the right eventual shape; it is deliberately
#   not attempted in the same change that first got big-endian running at all.
#
# WHAT IS AND IS NOT COVERED
#   Covered: the C oracle arms and the Rust arm are both built for s390x and
#   compared against each other on a big-endian machine.
#   NOT covered: the rustc config sweep zstd_entropy/run.sh does, and the
#   selfcheck mode. Run run.sh for those; they are host-independent.
#
# Runs are ~40x slower under qemu-user than native, so the defaults here are
# much smaller than the native ones. Pass a larger count for a real soak.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
what="${1:-all}"
runs="${2:-}"
seed="${3:-}"

source "$root/kbuild-env.sh"
# shellcheck source=be-cross.sh
source "$here/be-cross.sh"

if ! be_probe; then
    echo
    echo "no big-endian toolchain. bootstrap it (nothing is installed system-wide):"
    echo "    $here/be-cross.sh --bootstrap"
    exit 1
fi
be_check_rust || exit 1

out="${TMPDIR:-/tmp}/be-difftest.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

RSFLAGS=(--edition 2021 --crate-type staticlib -O --target "$BE_RUSTTARGET"
         -C panic=abort -C debug-assertions=on -C overflow-checks=on
         -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs
         -W rust_2018_idioms -W unreachable_pub -A stable_features
         -A unused_features -D warnings -A unreachable_pub)
CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

echo "arch:  $BE_ARCH (big-endian), rust target $BE_RUSTTARGET"
echo "cc:    $BE_CC"
echo "run:   $BE_RUN"
echo "rustc: $("$KB_RUSTC" --version)"
echo

run_zstd_entropy() {
    local h="$root/port/test/zstd_entropy"
    local P="$root/port/pristine/lib/zstd/common"
    local o="$out/zstd_entropy"; mkdir -p "$o"
    local INC=(-I "$h/shim" -I "$root/port/test/common/shim"
               -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/include")
    local f
    for f in ref_entropy_common ref_fse_decompress ref_error_private \
             ref_zstd_common main; do
        $BE_CC "${CFLAGS[@]}" "${INC[@]}" -c -o "$o/$f.o" "$h/$f.c"
    done
    # Same reason as run.sh: zstd_internal.h makes ZSTD_isError a macro, so the
    # rename can only happen on the object.
    "$BE_OBJCOPY" --redefine-sym ZSTD_isError=ref_ZSTD_isError "$o/ref_zstd_common.o"
    $BE_CC "${CFLAGS[@]}" -c -o "$o/corpus.o" "$h/corpus.c"
    "$KB_RUSTC" "${RSFLAGS[@]}" --crate-name entropy_common_rs \
        -o "$o/libentropy_common_rs.a" "$h/probe.rs"
    $BE_CC -o "$o/difftest" "$o"/*.o "$o/libentropy_common_rs.a"
    echo "== zstd_entropy, big-endian =="
    (cd "$root" && $BE_RUN "$o/difftest" "${runs:-20000}" "${seed:-20260904}")
    echo
}

run_lzo() {
    local h="$root/port/test/lzo"
    local P="$root/port/pristine/lib/lzo"
    local o="$out/lzo"; mkdir -p "$o"
    local INC=(-I "$h/shim" -I "$root/port/test/common/shim" -I "$P")
    "$KB_RUSTC" "${RSFLAGS[@]}" --crate-name lzo_rs -o "$o/liblzo_rs.a" \
        "$root/port/tree/lib/lzo/lzo1x_decompress_safe_rs.rs"
    $BE_CC "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=1 \
        -Dlzo1x_decompress_safe=ref_lzo1x_decompress_safe \
        -c -o "$o/ref_dec.o" "$P/lzo1x_decompress_safe.c"
    $BE_CC "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=0 \
        -Dlzo1x_decompress_safe=refu_lzo1x_decompress_safe \
        -c -o "$o/refu_dec.o" "$P/lzo1x_decompress_safe.c"
    $BE_CC "${CFLAGS[@]}" "${INC[@]}" -c -o "$o/comp.o" "$P/lzo1x_compress.c"
    $BE_CC "${CFLAGS[@]}" "${INC[@]}" -c -o "$o/main.o" "$h/main.c"
    $BE_CC -o "$o/difftest" "$o/main.o" "$o/comp.o" "$o/ref_dec.o" \
        "$o/refu_dec.o" "$o/liblzo_rs.a"
    echo "== lzo, big-endian =="
    (cd "$root" && $BE_RUN "$o/difftest" "${runs:-3000}" "${seed:-20260903}")
    echo
}

run_lib() {
    local h="$root/port/test/lib"
    local o="$out/lib"; mkdir -p "$o"
    # Same two generated headers run.sh makes; they are host-independent.
    python3 "$h/extract_crc16_table.py" \
            "$root/port/pristine/lib/crc/crc16.c" \
            "$h/ref_crc16_table_generated.h"
    python3 "$h/extract_bsearch.py" \
            "$root/src/linux/include/linux/bsearch.h" \
            "$h/bsearch_inline_generated.h"
    local srcs=("$root"/port/tree/lib/*_rs.rs "$root"/port/tree/lib/crc/*_rs.rs
                "$root"/port/tree/lib/crypto/*_rs.rs
                "$root"/port/tree/lib/crypto/mpi/*_rs.rs)
    local objs=() s n
    for s in "${srcs[@]}"; do
        n=$(basename "$s" .rs)
        "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
            --target "$BE_RUSTTARGET" \
            -C panic=abort -C debug-assertions=on -C overflow-checks=on \
            -D unsafe_op_in_unsafe_fn -W missing-docs \
            --crate-name "$n" -o "$o/lib$n.a" "$s"
        objs+=("$o/lib$n.a")
    done
    $BE_CC "${CFLAGS[@]}" -I "$h/shim" -I "$root/port/test/common/shim" \
        -o "$o/difftest" \
        "$h/main.c" "$h/ref_lib.c" "$h/ref_sort.c" "$h/ref_sort_x86.c" \
        "$h/ref_bsearch.c" "$h/ref_list_sort.c" "$h/ref_xxhash.c" \
        "$h/ref_earlycpio.c" "$h/ref_plist.c" "$h/ref_arc4.c" \
        "$h/ref_crc_ccitt.c" "$h/ref_chacha.c" "$h/ref_crypto_utils.c" \
        "$h/ref_ucs2.c" "$h/ref_check_signature.c" "${objs[@]}"
    echo "== lib, big-endian =="
    # run.sh's default is 4000000; that is minutes natively and far worse
    # under emulation, so the default here is much smaller.
    (cd "$root" && $BE_RUN "$o/difftest" "${runs:-20000}")
    echo
}

case "$what" in
    zstd_entropy) run_zstd_entropy ;;
    lzo)          run_lzo ;;
    lib)          run_lib ;;
    all)          run_zstd_entropy; run_lzo; run_lib ;;
    *) echo "unknown harness: $what (zstd_entropy|lzo|lib|all)"; exit 2 ;;
esac
