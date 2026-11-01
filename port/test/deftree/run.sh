#!/usr/bin/env bash
# Differential test for lib/zlib_deflate/deftree.c -> deftree_rs.rs.
# Userspace, no kernel. Both arms run the SAME pristine deflate.c; the only
# difference is which zlib_tr_*() bodies it resolves to.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, via an include! wrapper in
# probe.rs -- not a copy. A stale copy tested here while the kernel built
# something else is the failure notes/PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/deftree-difftest.$$"

RUSTC=/home/adam/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/zlib_deflate"
INC=(-I "$here" -I "$here/shim" -I "$root/port/test/zlib_inflate/shim" -I "$root/port/test/common/shim" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/zlib_deflate/deftree_rs.rs" \
         "$P/deflate.c" "$P/deftree.c" "$P/defutil.h"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# The Rust under test. Overflow checks and debug assertions ON, same as the
# other differential suites -- the invariants in the port's comments are
# load-bearing here even though the kernel compiles them out.
"$RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings -A unreachable_pub \
    --crate-name deftree_rs -o "$out/libdeftree_rs.a" "$here/probe.rs"

# The crate-root sweep: what the kernel build actually compiles this file as.
# deftree_rs.rs reads no #[cfg]s of its own, so there is exactly one
# configuration to check -- this still catches a warning/lint regression the
# staticlib build's -A unreachable_pub would hide.
"$RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
    -C panic=abort -C overflow-checks=on \
    -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
    --crate-name sweep --out-dir "$out" \
    "$root/port/tree/lib/zlib_deflate/deftree_rs.rs"
echo "config sweep: deftree_rs.rs builds as its own crate root"

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# Arm REF -- the oracle. Pristine deflate.c calling pristine deftree.c, with
# every symbol renamed so both arms can live in one binary: deflate.c's own
# API (so main.c can address this arm) AND the internal zlib_tr_*() calls
# (so this arm's deftree.c body is the one it actually reaches, not the
# other arm's).
REF=(-Dzlib_deflateInit2=ref_zlib_deflateInit2
     -Dzlib_deflateReset=ref_zlib_deflateReset
     -Dzlib_deflate=ref_zlib_deflate
     -Dzlib_deflateEnd=ref_zlib_deflateEnd
     -Dzlib_deflate_workspacesize=ref_zlib_deflate_workspacesize
     -Dzlib_deflate_dfltcc_enabled=ref_zlib_deflate_dfltcc_enabled
     -Dzlib_tr_init=ref_zlib_tr_init
     -Dzlib_tr_tally=ref_zlib_tr_tally
     -Dzlib_tr_flush_block=ref_zlib_tr_flush_block
     -Dzlib_tr_align=ref_zlib_tr_align
     -Dzlib_tr_stored_block=ref_zlib_tr_stored_block
     -Dzlib_tr_stored_type_only=ref_zlib_tr_stored_type_only)
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -c -o "$out/ref_deflate.o" "$P/deflate.c"
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -c -o "$out/ref_deftree.o" "$P/deftree.c"

# Arm RS -- pristine deflate.c again, same source, this time with only its
# OWN API renamed. The zlib_tr_*() calls inside it are left UNPREFIXED, so
# they resolve to the real Rust symbols in libdeftree_rs.a -- the same names
# the kernel build links against.
RS=(-Dzlib_deflateInit2=rs_zlib_deflateInit2
    -Dzlib_deflateReset=rs_zlib_deflateReset
    -Dzlib_deflate=rs_zlib_deflate
    -Dzlib_deflateEnd=rs_zlib_deflateEnd
    -Dzlib_deflate_workspacesize=rs_zlib_deflate_workspacesize
    -Dzlib_deflate_dfltcc_enabled=rs_zlib_deflate_dfltcc_enabled)
cc "${CFLAGS[@]}" "${INC[@]}" "${RS[@]}" -c -o "$out/rs_deflate.o" "$P/deflate.c"

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"
cc "${CFLAGS[@]}" -c -o "$out/sysinflate.o" "$here/sysinflate.c"

cc -o "$out/difftest" "$out/main.o" "$out/sysinflate.o" \
   "$out/ref_deflate.o" "$out/ref_deftree.o" "$out/rs_deflate.o" \
   "$out/libdeftree_rs.a" -lz

cd "$root"
"$out/difftest" "${1:-4000}" "${2:-20260906}"
