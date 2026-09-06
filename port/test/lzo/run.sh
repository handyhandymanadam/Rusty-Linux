#!/usr/bin/env bash
# Differential test for lib/lzo/lzo1x_decompress_safe.c -> ..._rs.rs.
# Userspace, no kernel. Three arms in one binary; the only difference between
# them is which decompressor is called.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/lzo-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/lzo"
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/lzo/lzo1x_decompress_safe_rs.rs" \
         "$P/lzo1x_decompress_safe.c" "$P/lzo1x_compress.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
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
    --crate-name lzo_rs -o "$out/liblzo_rs.a" \
    "$root/port/tree/lib/lzo/lzo1x_decompress_safe_rs.rs"

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# Arm A -- the oracle, wide unaligned access on (what both kernel configs build).
cc "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=1 \
   -Dlzo1x_decompress_safe=ref_lzo1x_decompress_safe \
   -c -o "$out/ref_dec.o" "$P/lzo1x_decompress_safe.c"

# Arm C -- the SAME pristine C with it off, taking the byte-at-a-time paths.
# The port has only one path; this is what makes divergence 1 measured.
cc "${CFLAGS[@]}" "${INC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=0 \
   -Dlzo1x_decompress_safe=refu_lzo1x_decompress_safe \
   -c -o "$out/refu_dec.o" "$P/lzo1x_decompress_safe.c"

# The encoder, shared: it is not under test, and it is the one the kernel
# ships beside this decoder rather than a system liblzo2.
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/comp.o" "$P/lzo1x_compress.c"

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" "$out/comp.o" \
   "$out/ref_dec.o" "$out/refu_dec.o" "$out/liblzo_rs.a"

cd "$root"
"$out/difftest" "${1:-50000}" "${2:-20260903}"
