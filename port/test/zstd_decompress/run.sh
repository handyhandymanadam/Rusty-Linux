#!/usr/bin/env bash
# Differential test for lib/zstd/decompress/zstd_decompress.c
# -> port/tree/lib/zstd/decompress/zstd_decompress_rs.rs.
#
#   run.sh [runs] [seed]
#
# Three arms in one binary: the pristine C (renamed ref_*), this port (via
# probe.rs, real names), and system libzstd loaded via dlopen/dlsym (the
# independent oracle -- see main.c's header comment for why dlopen and not
# a normal -lzstd link).
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/, not
# copies -- a stale copy tested here while the kernel builds something else
# is the failure notes/PRIOR-ART.md §2 records four times.
#
# zstd_decompress_block.c and zstd_ddict.c are NOT under differential test
# here -- they stay pristine C on BOTH arms (decompress-porter's Rust
# version of the block file isn't in port/tree/ yet). Only zstd_decompress.c
# itself differs between the ref and rust arms.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zstddecompress-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

echo "sources:"
for f in "$root/port/tree/lib/zstd/decompress/zstd_decompress_rs.rs" \
         "$root/port/pristine/lib/zstd/decompress/zstd_decompress.c" \
         "$root/port/pristine/lib/zstd/decompress/zstd_decompress_block.c" \
         "$root/port/pristine/lib/zstd/decompress/zstd_ddict.c"; do
    [ -f "$f" ] && printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

# logs/floor.md RAISE 1: zstd_decompress_rs.rs's ZstdDCtx has one real
# CONFIG_ fork of its own, DYNAMIC_BMI2, which changes the struct's field
# list (the `bmi2` field only exists when it's set) -- same shape
# huf_decompress_rs.rs and zstd_decompress_block_rs.rs already sweep, same
# three targets, same reasoning: baseline x86_64 and aarch64 both leave the
# dispatch shape on/off for the WRONG reason (portability_macros.h derives it
# from the target, and CONFIG_X86_NATIVE_CPU=y's -Ctarget-cpu=native sets
# __BMI2__ on this host), so the arm where it's off ON x86 has to be built
# explicitly too.
echo "config sweep: zstd_decompress_rs.rs builds for x86_64 (DYNAMIC_BMI2=1),"
echo "              x86_64+bmi2 (DYNAMIC_BMI2=0), and aarch64 (DYNAMIC_BMI2=0)"
swept_nonx86=0
for t in x86_64-unknown-linux-gnu x86_64-unknown-linux-gnu+bmi2 aarch64-unknown-none; do
    tf=""
    case "$t" in *+bmi2) t=${t%%+bmi2}; tf="-C target-feature=+bmi2";; esac
    if RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
        -C panic=abort -Z crate-attr=no_std \
        -D unsafe_op_in_unsafe_fn -W missing_docs \
        $tf --target "$t" --crate-name sweep --emit=metadata \
        -o "$out/sweep-$t$tf.rmeta" \
        "$root/port/tree/lib/zstd/decompress/zstd_decompress_rs.rs" \
        2>"$out/sweep.err"
    then
        echo "  ok  $t ${tf:+(bmi2)}"
        case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
    else
        sed -n '1,20p' "$out/sweep.err"; echo "  FAIL $t"; exit 1
    fi
done
[ "$swept_nonx86" = 1 ] || { echo "  UNSWEPT: no non-x86 target"; exit 1; }
echo

INC=(-I "$root/port/test/zstd_entropy/shim" -I "$root/port/test/common/shim"
     -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/lib/zstd/decompress"
     -I "$root/src/linux/include")
CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# ---- the rust arm's own object ------------------------------------------
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D unsafe_op_in_unsafe_fn -W missing_docs \
    --crate-name zstd_decompress_rs \
    -o "$out/libzstd_decompress_rs.a" "$here/probe.rs"

# ---- the ref arm: pristine C, renamed ------------------------------------
for f in ref_zstd_decompress ref_zstd_decompress_block ref_zstd_ddict; do
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/$f.o" "$here/$f.c"
done
# reused rather than duplicated -- see each file's own header comment
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_entropy_common.o" \
   "$root/port/test/zstd_entropy/ref_entropy_common.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_fse_decompress.o" \
   "$root/port/test/zstd_entropy/ref_fse_decompress.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_error_private.o" \
   "$root/port/test/zstd_entropy/ref_error_private.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_zstd_common.o" \
   "$root/port/test/zstd_entropy/ref_zstd_common.c"
# ZSTD_isError is a macro in the header until zstd_common.c's own #undef, so
# the -D-style rename above cannot reach it; renamed on the object instead.
# Spelled out here and in ref_zstd_common.c's own header comment rather than
# done quietly -- see that file.
objcopy --redefine-sym ZSTD_isError=ref_ZSTD_isError "$out/ref_zstd_common.o"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_huf_decompress.o" \
   "$root/port/test/zstd_huf/ref_huf_decompress.c"
cc "${CFLAGS[@]}" -I "$root/port/test/lib/shim" -I "$root/port/test/common/shim" \
   -I "$root/src/linux/include" -c -o "$out/ref_xxhash.o" \
   "$root/port/test/lib/ref_xxhash.c"

# ---- the rust arm's shared dependencies: pristine C zstd_decompress_block.c/
# zstd_ddict.c (real names, unrenamed -- see this file's header comment) and
# the SAME already-ported .rs files the kernel actually links (entropy_common,
# error_private, huf_decompress, xxhash), also real names.
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/real_zstd_decompress_block.o" \
   "$root/port/pristine/lib/zstd/decompress/zstd_decompress_block.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/real_zstd_ddict.o" \
   "$root/port/pristine/lib/zstd/decompress/zstd_ddict.c"
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --crate-name entropy_common_rs -o "$out/libentropy_common_rs.a" \
    "$root/port/tree/lib/zstd/common/entropy_common_rs.rs"
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --crate-name error_private_rs -o "$out/liberror_private_rs.a" \
    "$root/port/tree/lib/zstd/common/error_private_rs.rs"
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --crate-name huf_decompress_rs -o "$out/libhuf_decompress_rs.a" \
    "$root/port/tree/lib/zstd/decompress/huf_decompress_rs.rs"
# xxhash_rs.rs calls kernel::kabi_rule!/kabi_modinfo!, which the kernel build
# provides and this standalone compile does not -- same no-op stub every
# other harness in this project uses (e.g. port/test/math/run.sh), applied
# here as a flat prelude (not a nested `#[path] mod`) so `kernel::` resolves
# without a crate-root mismatch.
{
    echo '#![allow(non_snake_case, unused_macros, unused_imports)]'
    echo 'mod kernel {'
    echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
    echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
    echo '    pub(crate) use {kabi_export, kabi_modinfo, kabi_rule};'
    echo '}'
    sed 's|^//!|//|' "$root/port/tree/lib/xxhash_rs.rs"
} > "$out/xxhash-probe.rs"
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --crate-name xxhash_rs -o "$out/libxxhash_rs.a" "$out/xxhash-probe.rs"

cc "${CFLAGS[@]}" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" \
   "$out/ref_zstd_decompress.o" "$out/ref_zstd_decompress_block.o" "$out/ref_zstd_ddict.o" \
   "$out/ref_entropy_common.o" "$out/ref_fse_decompress.o" "$out/ref_error_private.o" \
   "$out/ref_huf_decompress.o" "$out/ref_xxhash.o" "$out/ref_zstd_common.o" \
   "$out/libzstd_decompress_rs.a" \
   "$out/real_zstd_decompress_block.o" "$out/real_zstd_ddict.o" \
   "$out/libentropy_common_rs.a" "$out/liberror_private_rs.a" \
   "$out/libhuf_decompress_rs.a" "$out/libxxhash_rs.a" \
   -ldl

cd "$root"
"$out/difftest" "${1:-50000}" "${2:-20260906}"
