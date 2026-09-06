#!/usr/bin/env bash
# Differential test for lib/xz/xz_dec_stream.c -> xz_dec_stream_rs.rs.
# Userspace, no kernel. Three arms plus two independent oracles in one binary.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/xzstream-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/xz"
INC=(-I "$here/shim" -I "$P" -I "$root/src/linux/include" -I "$root/port/pristine/include")

# The seven BCJ filters, matching CONFIG_XZ_DEC_* in both our kernel configs.
# floor.md criterion 8: the oracle is compiled in the configuration the kernel
# builds, not whatever the harness finds convenient.
FILT=(-DXZ_DEC_X86 -DXZ_DEC_POWERPC -DXZ_DEC_ARM -DXZ_DEC_ARMTHUMB
      -DXZ_DEC_ARM64 -DXZ_DEC_SPARC -DXZ_DEC_RISCV)
RSCFG=(--cfg CONFIG_XZ_DEC_BCJ)

echo "sources:"
for f in "$root/port/tree/lib/xz/xz_dec_stream_rs.rs" "$P/xz_dec_stream.c" \
         "$P/xz_dec_lzma2.c" "$P/xz_dec_bcj.c" "$P/xz_crc32.c"; do
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
    "${RSCFG[@]}" --crate-name xz_dec_stream_rs \
    -o "$out/libxz_dec_stream_rs.a" "$here/probe.rs"

# floor.md RAISE 1: the port must build in EVERY combination of the Kconfig
# symbols it reads, not just the two our configs happen to select. This file
# reads exactly one, CONFIG_XZ_DEC_BCJ, and a constant left ungated while its
# only use is #[cfg]-gated becomes "constant is never used" -- which
# CONFIG_WERROR=y turns into a build failure. That is the defect that raised
# this project's floor the first time.
echo "config sweep: xz_dec_stream_rs.rs builds with and without CONFIG_XZ_DEC_BCJ"
for c in "--cfg CONFIG_XZ_DEC_BCJ" ""; do
    "$KB_RUSTC" --edition 2021 --crate-type rlib -O -C panic=abort \
        -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings $c \
        --crate-name sweep --emit=metadata -o "$out/sweep.rmeta" \
        "$root/port/tree/lib/xz/xz_dec_stream_rs.rs"
done
echo

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# The pieces below the stream layer are NOT ported: lzma2, bcj and crc32 are
# the kernel's own pristine C, compiled once and shared by every arm. Only
# xz_dec_stream.c's own symbols are renamed.
for f in xz_dec_lzma2 xz_dec_bcj xz_crc32; do
    cc "${CFLAGS[@]}" "${INC[@]}" "${FILT[@]}" \
       -c -o "$out/$f.o" "$P/$f.c"
done

# Arm A -- the oracle, in the configuration our kernels build.
cc "${CFLAGS[@]}" "${INC[@]}" "${FILT[@]}" -c -o "$out/ref_stream.o" "$here/ref_stream.c"
# Arm C -- the same pristine C WITH XZ_DEC_ANY_CHECK, which our kernels do not
# set. Criterion 8's other half: compile both ways and compare.
cc "${CFLAGS[@]}" "${INC[@]}" "${FILT[@]}" -c -o "$out/ref_any.o" "$here/ref_stream_anycheck.c"

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o"   "$here/main.c"
cc "${CFLAGS[@]}" -c -o "$out/corpus.o" "$here/corpus.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/crc_shim.o" "$here/crc_shim.c"

cc -o "$out/difftest" "$out/main.o" "$out/corpus.o" "$out/crc_shim.o" "$out/ref_stream.o" \
   "$out/ref_any.o" "$out/xz_dec_lzma2.o" "$out/xz_dec_bcj.o" "$out/xz_crc32.o" \
   "$out/libxz_dec_stream_rs.a" -llzma

cd "$root"
"$out/difftest" "${1:-20000}" "${2:-20260904}"
