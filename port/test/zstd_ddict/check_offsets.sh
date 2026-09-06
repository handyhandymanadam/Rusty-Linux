#!/usr/bin/env bash
# Proves zstd_ddict_rs.rs's ZstdDCtx and ZstdDDict mirror struct ZSTD_DCtx_s
# and struct ZSTD_DDict_s field-for-field: offsetof() in check_offsets.c vs.
# offset_of!() in offsets.rs, one field at a time, diffed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zddict-offsets.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

source "$root/kbuild-env.sh"

INC=(-I "$root/port/test/zstd_entropy/shim" -I "$root/port/test/common/shim"
     -I "$root/src/linux/lib/zstd/common" -I "$root/src/linux/lib/zstd/decompress"
     -I "$root/src/linux/include")

cc "${INC[@]}" -o "$out/check_offsets" "$here/check_offsets.c"
"$out/check_offsets" > "$out/c_offsets.txt"

sed -e '/^\/\/!/d' -e '/^#!\[allow/d' \
    "$root/port/tree/lib/zstd/decompress/zstd_ddict_rs.rs" \
    > "$out/zstd_ddict_rs_stripped.rs"

ZSTD_DDICT_RS_STRIPPED="$out/zstd_ddict_rs_stripped.rs" \
    "$KB_RUSTC" --edition 2021 -O --cfg DYNAMIC_BMI2 -o "$out/offsets_bin" "$here/offsets.rs"
"$out/offsets_bin" > "$out/rust_offsets.txt"

echo "--- C ($here/check_offsets.c) ---"
cat "$out/c_offsets.txt"
echo "--- Rust ($here/offsets.rs) ---"
cat "$out/rust_offsets.txt"

if diff <(awk '{print $NF}' "$out/c_offsets.txt") <(awk '{print $NF}' "$out/rust_offsets.txt") >/dev/null
then
    echo "OK: every field offset and every sizeof match"
else
    echo "MISMATCH: zstd_ddict_rs.rs has drifted from the real headers"
    exit 1
fi
