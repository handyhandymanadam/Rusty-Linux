#!/usr/bin/env bash
# Byte-exact check for lib/fonts/font_8x16.c -> lib/fonts/font_8x16_rs.rs.
# Not a differential in the usual sense of this project's harnesses --
# there is no algorithm here, just a 4096-byte glyph array and one
# struct -- so this dumps every field plus every glyph byte plus the
# extra[]/REFCOUNT ABI detail from both the pristine C and the Rust,
# and diffs the two outputs directly. Same shape as
# port/test/xarray/layout/. Userspace, no kernel.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/fonts-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/fonts"

echo "sources:"
for f in "$root/port/tree/lib/fonts/font_8x16_rs.rs" "$P/font_8x16.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-std=gnu11 -g -O2 -Wall -Wextra -Wno-unused-parameter -I "$here/shim")
cc "${CFLAGS[@]}" -c -o "$out/font_8x16.o" "$P/font_8x16.c"
cc "${CFLAGS[@]}" -c -o "$out/layout_probe.o" "$here/layout_probe.c"
cc -o "$out/c_probe" "$out/font_8x16.o" "$out/layout_probe.o"
echo "C probe compiled clean."

RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
    --crate-name kernel -o "$out/libkernel.rlib" "$here/kernel_stub.rs"

RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --cfg fonts_test_probe \
    --extern kernel="$out/libkernel.rlib" \
    -o "$out/rs_probe" "$here/layout_probe.rs" 2>"$out/rustc.err" \
    || { cat "$out/rustc.err"; exit 1; }
echo "Rust probe compiled clean."
echo

"$out/c_probe" > "$out/c.out"
"$out/rs_probe" > "$out/rs.out"

if diff -u "$out/c.out" "$out/rs.out"; then
    echo "OK: identical (struct fields, extra[]/REFCOUNT ABI, all 4096 glyph bytes)"
else
    echo "MISMATCH -- see diff above"
    exit 1
fi
