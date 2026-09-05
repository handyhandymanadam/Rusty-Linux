#!/usr/bin/env bash
# Differential test for lib/xz/xz_dec_lzma2.c -> xz_dec_lzma2_rs.rs.
# Drives xz_dec_lzma2_run() DIRECTLY on raw LZMA2 chunk streams.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/xzlzma2-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/xz"
# The shim is xz_stream's, which already extends xz's with min/max/vmalloc.
INC=(-I "$root/port/test/xz_stream/shim" -I "$P" -I "$root/src/linux/include"
     -I "$root/port/pristine/include")

echo "sources:"
for f in "$root/port/tree/lib/xz/xz_dec_lzma2_rs.rs" "$P/xz_dec_lzma2.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

# floor.md RAISE 1: every combination of the Kconfig symbols this file reads.
# CONFIG_XZ_DEC_MICROLZMA is a real symbol (lib/xz/Kconfig:48) that fs/erofs
# selects, so both states are supported configs even though ours has it off.
echo "config sweep: xz_dec_lzma2_rs.rs builds with and without CONFIG_XZ_DEC_MICROLZMA"
for c in "--cfg CONFIG_XZ_DEC_MICROLZMA" ""; do
    "$KB_RUSTC" --edition 2021 --crate-type rlib -O -C panic=abort \
        -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings $c \
        --crate-name sweep --emit=metadata -o "$out/sweep.rmeta" \
        "$root/port/tree/lib/xz/xz_dec_lzma2_rs.rs"
done
echo

# NOTE ON -A unreachable_pub, and why the staticlib build differs from the
# sweep above. probe.rs pulls the port in as `#[path] mod ..._rs;` -- a PRIVATE
# module -- so every `pub` item in the ported file becomes unreachable-pub in
# THIS crate. That is an artefact of how the harness nests the file, not a
# property of the file: the kernel compiles each .rs as its own crate root,
# where the same items are reachable. The sweep above, which does compile it as
# a crate root, keeps the lint on and is where it does real work.
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings -A unreachable_pub \
    --crate-name xz_dec_lzma2_rs -o "$out/libxz_dec_lzma2_rs.a" "$here/probe.rs"

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_lzma2.o" "$here/ref_lzma2.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o"      "$here/main.c"
cc "${CFLAGS[@]}"             -c -o "$out/corpus.o"    "$here/corpus.c"
cc "${CFLAGS[@]}"             -c -o "$out/alloc_shim.o" "$here/alloc_shim.c"

cc -o "$out/difftest" "$out/main.o" "$out/corpus.o" "$out/alloc_shim.o" "$out/ref_lzma2.o" \
   "$out/libxz_dec_lzma2_rs.a" -llzma

cd "$root"
"$out/difftest" "${1:-20000}" "${2:-20260904}"
