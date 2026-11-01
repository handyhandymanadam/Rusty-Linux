#!/usr/bin/env bash
# Differential test for lib/zlib_deflate/deflate.c -> deflate_glue.c + deflate_rs.rs (with deftree_rs.rs behind it).
# Userspace, no kernel. Oracle arm: pristine deflate.c + pristine deftree.c. Rust arm: the kernel's own
# deflate_glue.c (renamed API) calling deflate_rs.rs, which calls deftree_rs.rs -- the exact CONFIG_RUST=y stack.
# Every accepted stream is compared byte-for-byte between the arms and inflated by the SYSTEM zlib.
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
for f in "$root/port/tree/lib/zlib_deflate/deflate_rs.rs" "$root/port/tree/lib/zlib_deflate/deftree_rs.rs" \
         "$root/port/tree/lib/zlib_deflate/deflate_glue.c" "$P/deflate.c" "$P/deftree.c" "$P/defutil.h"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# The Rust under test. Overflow checks and debug assertions ON, same as the
# other differential suites -- the invariants in the port's comments are
# load-bearing here even though the kernel compiles them out.
rust_lib() {   # rust_lib <deflate_rs.rs to test> <outdir> -> <outdir>/libdeflate_rs.a
    mkdir -p "$2"
    printf '//! probe\n#[path = "%s"]\nmod deftree_rs;\n#[path = "%s"]\nmod deflate_rs;\n' \
        "$root/port/tree/lib/zlib_deflate/deftree_rs.rs" "$1" > "$2/probe.rs"
    "$RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings -A unreachable_pub \
        --crate-name deflate_rs -o "$2/libdeflate_rs.a" "$2/probe.rs"
}
rust_lib "$root/port/tree/lib/zlib_deflate/deflate_rs.rs" "$out/real"

# The crate-root sweep: what the kernel build actually compiles each file as (one crate root per file).
# deftree_rs.rs reads no #[cfg]s of its own, so there is exactly one
# configuration to check -- this still catches a warning/lint regression the
# staticlib build's -A unreachable_pub would hide.
"$RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
    -C panic=abort -C overflow-checks=on \
    -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
    --crate-name sweep --out-dir "$out" \
    "$root/port/tree/lib/zlib_deflate/deftree_rs.rs"
"$RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
    -C panic=abort -C overflow-checks=on \
    -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
    --crate-name sweep2 --out-dir "$out" \
    "$root/port/tree/lib/zlib_deflate/deflate_rs.rs"
echo "config sweep: deftree_rs.rs and deflate_rs.rs build as their own crate roots"

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

# Arm RS -- the kernel's deflate_glue.c (the CONFIG_RUST=y C entry file) with only its OWN API renamed. Its calls
# into rust_zlib_*() are left alone, so they resolve to the real Rust symbols in libdeflate_rs.a, which in turn calls
# the real zlib_tr_*() Rust symbols -- the names the kernel build links.
RS=(-Dzlib_deflateInit2=rs_zlib_deflateInit2
    -Dzlib_deflateReset=rs_zlib_deflateReset
    -Dzlib_deflate=rs_zlib_deflate
    -Dzlib_deflateEnd=rs_zlib_deflateEnd
    -Dzlib_deflate_workspacesize=rs_zlib_deflate_workspacesize
    -Dzlib_deflate_dfltcc_enabled=rs_zlib_deflate_dfltcc_enabled)
cc "${CFLAGS[@]}" "${INC[@]}" "${RS[@]}" -c -o "$out/rs_glue.o" "$root/port/tree/lib/zlib_deflate/deflate_glue.c"

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"
cc "${CFLAGS[@]}" -c -o "$out/sysinflate.o" "$here/sysinflate.c"

link() {   # link <libdir> <exe>
    cc -o "$2" "$out/main.o" "$out/sysinflate.o" \
       "$out/ref_deflate.o" "$out/ref_deftree.o" "$out/rs_glue.o" \
       "$1/libdeflate_rs.a" -lz
}
link "$out/real" "$out/difftest"

cd "$root"
if [ "${1:-}" = "--sabotage" ]; then
    # Dropped as EQUIVALENT (checked by reasoning, not by a run): `len > best_len` -> `>=` (the pre-check
    # match[best_len] == scan[best_len] makes len == best_len impossible); `m >= wsize` -> `m > wsize` in the head slide
    # (m == wsize gives m - wsize == 0 == NIL either way).
    # Each mutant of deflate_rs.rs must be caught by the differential (nonzero exit) within 4000 runs.
    n=0; caught=0
    while IFS='~' read -r name from to; do
        [ -n "$name" ] || continue
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$root/port/tree/lib/zlib_deflate/deflate_rs.rs" > "$out/mut$n.rs" \
            || { echo "mutant $name: PATTERN MISSING"; exit 1; }
        rust_lib "$out/mut$n.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        link "$out/m$n" "$out/mt$n"
        if timeout 600 "$out/mt$n" 4000 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
chain-quarter~chain_length >>= 2;~chain_length >>= 1;
limit~(*s).strstart - max_dist(s) } else { NIL }~(*s).strstart - max_dist(s) + 1 } else { NIL }
too-far~const TOO_FAR: UInt = 4096;~const TOO_FAR: UInt = 4095;
lazy-bound~(*s).match_length <= 5~(*s).match_length <= 4
fast-insert~(*s).match_length <= (*s).max_lazy_match && (*s).lookahead >= MIN_MATCH~(*s).match_length < (*s).max_lazy_match && (*s).lookahead >= MIN_MATCH
level-flags~((*s).level - 1) >> 1~((*s).level) >> 1
adler-header~if (*(*strm).state).noheader == 0 {~if (*(*strm).state).noheader != 0 {
stored-max~pending_buf_size.wrapping_sub(5);~pending_buf_size.wrapping_sub(4);
total-out~(*strm).total_out.wrapping_add(len as c_ulong)~(*strm).total_out.wrapping_add(len as c_ulong + 1)
full-flush~if flush == Z_FULL_FLUSH {~if flush == Z_FULL_FLUSH + 100 {
prev-mask~*(*s).prev.add((str_ & (*s).w_mask) as usize)~*(*s).prev.add((str_ & ((*s).w_mask >> 1)) as usize)
end-busy~if status == BUSY_STATE {~if status == FINISH_STATE {
last-flush~(*s).last_flush = -1;~(*s).last_flush = 0;
put-short~put_byte(s, (w & 0xff) as Byte);<NL>        put_byte(s, (w >> 8) as Byte);~put_byte(s, (w >> 8) as Byte);<NL>        put_byte(s, (w & 0xff) as Byte);
lit-bufsize~(*s).lit_bufsize = 1 << (mem_level + 6);~(*s).lit_bufsize = 1 << (mem_level + 5);
lazy-flush~if zlib_tr_tally(s, 0, *(*s).window.add((*s).strstart as usize - 1) as c_uint) != 0 {~if zlib_tr_tally(s, 0, *(*s).window.add((*s).strstart as usize - 1) as c_uint) == 0 {
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
"$out/difftest" "${1:-4000}" "${2:-20260906}"
