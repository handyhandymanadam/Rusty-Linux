#!/usr/bin/env bash
# Differential test for lib/string_helpers.c -> string_helpers_rs.rs.
# Userspace, no kernel. Both arms run the SAME pristine string_helpers.c
# (renamed ref_*); the RS arm links the real string_helpers_rs.rs through
# probe.rs's rs_* wrappers.
#
#   run.sh [runs] [seed]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/string-helpers-difftest.$$"

RUSTC=/home/adam/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib"
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/string_helpers_rs.rs" "$P/string_helpers.c" \
         "$root/port/tree/lib/cmdline_rs.rs"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# kernel_stub, the RS arm's rust probe, and cmdline_rs.rs's real get_options
# -- all three need --extern kernel resolving to the same stub.
"$RUSTC" --edition 2021 --crate-type rlib -O -Cpanic=abort \
    --crate-name kernel -o "$out/libkernel.rlib" "$here/kernel_stub.rs"

"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --extern kernel="$out/libkernel.rlib" \
    --crate-name string_helpers_probe -o "$out/libstring_helpers_probe.a" "$here/probe.rs"

"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    --extern kernel="$out/libkernel.rlib" \
    --crate-name cmdline_rs -o "$out/libcmdline_rs.a" "$root/port/tree/lib/cmdline_rs.rs"

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# REF arm: pristine string_helpers.c, every one of its 19 globals renamed
# to ref_*. get_options() is left unrenamed -- a shared, neutral dependency
# (lib/cmdline_rs.rs, already Rust, already verified elsewhere), not what
# is under test here.
REF=(-Dstring_get_size=ref_string_get_size
     -Dparse_int_array=ref_parse_int_array
     -Dparse_int_array_user=ref_parse_int_array_user
     -Dstring_unescape=ref_string_unescape
     -Dstring_escape_mem=ref_string_escape_mem
     -Dkstrdup_quotable=ref_kstrdup_quotable
     -Dkstrdup_quotable_cmdline=ref_kstrdup_quotable_cmdline
     -Dkstrdup_quotable_file=ref_kstrdup_quotable_file
     -Dkstrdup_and_replace=ref_kstrdup_and_replace
     -Dkasprintf_strarray=ref_kasprintf_strarray
     -Dkfree_strarray=ref_kfree_strarray
     -Ddevm_kasprintf_strarray=ref_devm_kasprintf_strarray
     -Dskip_spaces=ref_skip_spaces
     -Dstrim=ref_strim
     -Dsysfs_streq=ref_sysfs_streq
     -Dmatch_string=ref_match_string
     -D__sysfs_match_string=ref___sysfs_match_string
     -Dstrreplace=ref_strreplace
     -Dmemcpy_and_pad=ref_memcpy_and_pad)
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -c -o "$out/ref_string_helpers.o" "$P/string_helpers.c"

cc "${CFLAGS[@]}" -I "$here/shim" -c -o "$out/alloc_shim.o" "$here/alloc_shim.c"
# The real table, byte-identical to lib/ctype_rs.rs's own -- linked
# directly rather than retyped, so the harness cannot silently diverge
# from either.
cc "${CFLAGS[@]}" -I "$here/shim" -c -o "$out/ctype.o" "$P/ctype.c"
cc "${CFLAGS[@]}" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" "$out/alloc_shim.o" "$out/ctype.o" "$out/ref_string_helpers.o" \
   "$out/libstring_helpers_probe.a" "$out/libcmdline_rs.a"

cd "$root"
"$out/difftest" "${1:-2000}" "${2:-20260906}"
