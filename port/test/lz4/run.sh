#!/usr/bin/env bash
# Differential test for lib/lz4/lz4_decompress.c -> lz4_decompress_rs.rs.
# Userspace, no kernel. Two arms in one binary; the only difference between
# them is which implementation is called.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, via a #[path] wrapper in
# probe.rs -- not a copy.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/lz4-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/lz4"
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$P" -I "$root/src/linux/include")

# THESE TWO ARE NOT DECORATION AND THEY GO ON THE COMMAND LINE, NOT IN A SHIM
# HEADER. lz4defs.h forks on CONFIG_64BIT and __LITTLE_ENDIAN, and it includes
# <linux/unaligned.h>, <linux/bitops.h>, <linux/string.h>, <linux/lz4.h> and
# <linux/types.h> -- but NOT <linux/kernel.h>, which is where port/test/lzo/'s
# shim keeps them. Without CONFIG_64BIT the oracle compiles LZ4_ARCH64 = 0 and
# the compressor selects the byPtr table type, whose table needs twice the
# space LZ4_STREAMSIZE reserves. That produced, in order: "malloc(): corrupted
# top size", a decompressor rejecting its own encoder's output, and a segfault
# reading 0x5555555555555555 -- three faces of the ORACLE BEING A DIFFERENT
# PROGRAM FROM THE ONE THE KERNEL COMPILES. main.c prints both back at the top
# of every run so this cannot happen quietly again.
ARCH=(-DCONFIG_64BIT=1)

echo "sources:"
for f in "$root/port/tree/lib/lz4/lz4_decompress_rs.rs" \
         "$root/port/tree/lib/lz4/lz4_decompress_thunk.c" \
         "$P/lz4_decompress.c" "$P/lz4defs.h"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# lz4_decompress_rs.rs reads no #[cfg] at all, so logs/floor.md RAISE 1's
# sweep is a single configuration and is the ordinary build below.
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
    --crate-name lz4_decompress_rs -o "$out/liblz4_rs.a" "$here/probe.rs"

# -O3 is what lib/lz4/Makefile uses; the oracle is built the way the kernel
# builds it or it is a different program.
CFLAGS=(-O3 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

cc "${CFLAGS[@]}" "${ARCH[@]}" "${INC[@]}" -c -o "$out/ref_lz4.o" "$here/ref_lz4.c"
cc "${CFLAGS[@]}" -c -o "$out/sysenc.o" "$here/sysenc.c"
cc "${CFLAGS[@]}" "${ARCH[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" "$out/ref_lz4.o" "$out/sysenc.o" \
   "$out/liblz4_rs.a" /usr/lib64/liblz4.so.1

cd "$root"
"$out/difftest" "${1:-200000}" "${2:-20260903}"
