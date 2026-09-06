#!/usr/bin/env bash
# Proves ZstdDCtx (zstd_decompress_block_rs.rs) mirrors struct ZSTD_DCtx_s
# (zstd_decompress_internal.h) field-for-field: offsetof() in check_offsets.c
# vs. offset_of!() in offsets.rs, one field at a time, diffed. Rerun after
# any change to ZstdDCtx or to the kernel's ZSTD_DCtx_s.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zdb-offsets.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

source "$root/kbuild-env.sh"

INC=(-I "$root/port/test/zstd_entropy/shim" -I "$root/port/test/common/shim"
     -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/lib/zstd/decompress"
     -I "$root/src/linux/include")

cc "${INC[@]}" -o "$out/check_offsets" "$here/check_offsets.c"
"$out/check_offsets" > "$out/c_offsets.txt"

# include!() inserts at the macro call site, not the crate root: strip the
# module-level //! docs and #![allow(...)] line, both illegal there.
sed -e '/^\/\/!/d' -e '/^#!\[allow/d' \
    "$root/port/tree/lib/zstd/decompress/zstd_decompress_block_rs.rs" \
    > "$out/zstd_decompress_block_rs_stripped.rs"

ZSTD_DECOMPRESS_BLOCK_RS_STRIPPED="$out/zstd_decompress_block_rs_stripped.rs" \
    "$KB_RUSTC" --edition 2021 -O --cfg DYNAMIC_BMI2 -o "$out/offsets_bin" "$here/offsets.rs"
"$out/offsets_bin" > "$out/rust_offsets.txt"

echo "--- C ($here/check_offsets.c) ---"
cat "$out/c_offsets.txt"
echo "--- Rust ($here/offsets.rs) ---"
cat "$out/rust_offsets.txt"

if diff <(cut -d' ' -f2- "$out/c_offsets.txt" | tail -n +2) \
        <(cut -d' ' -f2- "$out/rust_offsets.txt" | tail -n +2) >/dev/null \
   && diff <(sed -n '1p' "$out/c_offsets.txt" | grep -o '[0-9]*$') \
           <(sed -n '1p' "$out/rust_offsets.txt" | grep -o '[0-9]*$') >/dev/null
then
    echo "OK: every field offset and total sizeof match"
else
    echo "MISMATCH: ZstdDCtx has drifted from struct ZSTD_DCtx_s"
    exit 1
fi
