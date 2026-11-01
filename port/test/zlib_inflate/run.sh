#!/usr/bin/env bash
# Differential test for lib/zlib_inflate/{inffast,inftrees,inflate}.c -> *_rs.rs.
# Userspace, no kernel. Both arms are the pristine C pipeline; the only
# difference between them is which inflate_fast() is linked in.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, via an include! wrapper in
# probe.rs -- not a copy. A stale copy tested here while the kernel built
# something else is the failure notes/PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/zlib-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/zlib_inflate"
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$P")

echo "sources:"
for f in "$root/port/tree/lib/zlib_inflate/inffast_rs.rs" \
         "$root/port/tree/lib/zlib_inflate/inftrees_rs.rs" \
         "$root/port/tree/lib/zlib_inflate/inflate_rs.rs" \
         "$root/port/tree/lib/zlib_inflate/inffixed_rs.rs" \
         "$root/port/tree/lib/zlib_inflate/inflate.c" \
         "$P/inffast.c" "$P/inflate.c" "$P/inftrees.c"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# The Rust under test. Same flags the other suites use: overflow checks and
# debug assertions ON, which is what makes the invariants in the port's
# comments load-bearing here even though the kernel compiles them out.
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
    --crate-name inffast_rs -o "$out/libinffast_rs.a" "$here/probe.rs"

# logs/floor.md RAISE 1: every combination of the #[cfg]s a ported file reads.
# inflate_rs.rs reads exactly one, CONFIG_ZLIB_DFLTCC, which is `depends on
# S390` -- so nothing here can build or run it, and leaving it unswept is how
# a supported architecture breaks silently.
for cfg in "" "--cfg CONFIG_ZLIB_DFLTCC"; do
    if ! "$KB_RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
            -C panic=abort -C overflow-checks=on \
            -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings $cfg \
            --crate-name sweep --out-dir "$out" \
            "$root/port/tree/lib/zlib_inflate/inflate_rs.rs" 2>"$out/sweep.err"; then
        echo "CONFIG SWEEP FAILED with [${cfg:-none}]"
        head -5 "$out/sweep.err"
        exit 1
    fi
done
echo "config sweep: inflate_rs.rs builds with and without CONFIG_ZLIB_DFLTCC"

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

# Arm A -- the oracle. Pristine inflate.c calling pristine inffast.c, with
# every global renamed so both arms can live in one binary.
REF=(-Dzlib_inflate_table=ref_zlib_inflate_table
     -Dzlib_inflate=ref_zlib_inflate
     -Dzlib_inflateEnd=ref_zlib_inflateEnd
     -Dzlib_inflateIncomp=ref_zlib_inflateIncomp
     -Dzlib_inflateInit2=ref_zlib_inflateInit2
     -Dzlib_inflateReset=ref_zlib_inflateReset
     -Dzlib_inflate_workspacesize=ref_zlib_inflate_workspacesize
     -Dinflate_fast=ref_inflate_fast)
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -c -o "$out/ref_inflate.o" "$P/inflate.c"
# The oracle's inflate_fast() is compiled under a different name and reached
# through a counting wrapper in main.c. Otherwise "the fast path was entered"
# would be an inference from the chunking rather than a number read back.
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=1 \
   -Uinflate_fast -Dinflate_fast=ref_inflate_fast_inner \
   -c -o "$out/ref_inffast.o" "$P/inffast.c"

# Arm C -- the SAME pristine inffast.c with its unaligned-access option OFF,
# so it takes the byte-wise get_unaligned16() path instead of the wide load.
# The Rust replaces both spellings with one read_unaligned(); running all
# three arms is what makes that a measured claim rather than an assertion.
RU=(-Dzlib_inflate_table=ref_zlib_inflate_table
    -Dzlib_inflate=refu_zlib_inflate
    -Dzlib_inflateEnd=refu_zlib_inflateEnd
    -Dzlib_inflateIncomp=refu_zlib_inflateIncomp
    -Dzlib_inflateInit2=refu_zlib_inflateInit2
    -Dzlib_inflateReset=refu_zlib_inflateReset
    -Dzlib_inflate_workspacesize=refu_zlib_inflate_workspacesize
    -Dinflate_fast=refu_inflate_fast)
cc "${CFLAGS[@]}" "${INC[@]}" "${RU[@]}" -c -o "$out/ru_inflate.o" "$P/inflate.c"
cc "${CFLAGS[@]}" "${INC[@]}" "${RU[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=0 \
   -c -o "$out/ru_inffast.o" "$P/inffast.c"

# Arm B -- ALL THREE ported files. From 2026-09-03 this is not pristine
# inflate.c with one function swapped: zlib_inflate() itself is Rust, so the
# arm compiles the SHIPPED THUNK FILE out of port/tree/ and links it against
# the Rust bodies. What runs here is what the kernel builds.
RS=(-Dzlib_inflate=rs_zlib_inflate
    -Dzlib_inflateEnd=rs_zlib_inflateEnd
    -Dzlib_inflateIncomp=rs_zlib_inflateIncomp
    -Dzlib_inflateInit2=rs_zlib_inflateInit2
    -Dzlib_inflateReset=rs_zlib_inflateReset
    -Dzlib_inflate_workspacesize=rs_zlib_inflate_workspacesize)
cc "${CFLAGS[@]}" "${INC[@]}" "${RS[@]}" -c -o "$out/rs_inflate.o" \
   "$root/port/tree/lib/zlib_inflate/inflate.c"

# inftrees.c IS under test now. It used to be compiled once and shared by all
# three arms as "table building is not under test"; zlib_inflate_table() is
# Rust as of 2026-09-03, so the oracle arms get their own renamed copy and the
# RS arm's call resolves to the Rust in probe.rs. The RU arm deliberately
# shares the oracle's -- it exists to vary inffast.c's unaligned-access option,
# and inftrees.c has no such fork.
cc "${CFLAGS[@]}" "${INC[@]}" "${REF[@]}" -c -o "$out/ref_inftrees.o" "$P/inftrees.c"

# Arm D -- THE RETAINED PRE-BOOT BODY, from port/tree/, with STATIC defined.
# That branch used to be the pristine C verbatim; since 2026-09-03 it carries
# upstream zlib's `copy > whave` guard, the same five lines as
# upstream/zlib-inflate-oob/'s patch. Compiling it here is the first time any
# retained pre-boot body in this project has been tested AT ALL -- lzo's and
# xz's are still compiled by nothing and checked by nothing.
#
# Its inflate_fast() and zlib_inflate_table() are pointed at the oracle's, so
# this arm is pure C and the only thing under test in it is the hunk.
PRE=(-DSTATIC=1
     -Dzlib_inflate=pre_zlib_inflate
     -Dzlib_inflateEnd=pre_zlib_inflateEnd
     -Dzlib_inflateIncomp=pre_zlib_inflateIncomp
     -Dzlib_inflateInit2=pre_zlib_inflateInit2
     -Dzlib_inflateReset=pre_zlib_inflateReset
     -Dzlib_inflate_workspacesize=pre_zlib_inflate_workspacesize
     -Dzlib_inflate_table=ref_zlib_inflate_table
     -Dinflate_fast=ref_inflate_fast)
cc "${CFLAGS[@]}" "${INC[@]}" "${PRE[@]}" -c -o "$out/pre_inflate.o" \
   "$root/port/tree/lib/zlib_inflate/inflate.c"

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"
cc "${CFLAGS[@]}" -c -o "$out/corpus.o" "$here/corpus.c"

cc -o "$out/difftest" "$out/main.o" "$out/corpus.o" "$out/ref_inftrees.o" \
   "$out/ref_inflate.o" "$out/ref_inffast.o" "$out/rs_inflate.o" \
   "$out/pre_inflate.o" \
   "$out/ru_inflate.o" "$out/ru_inffast.o" \
   "$out/libinffast_rs.a" -lz

# Run from the repo root: the corpus reads a few real files by relative path.
cd "$root"
# Back to 30000 after a detour. Fixing run()'s premature exit on Z_BUF_ERROR
# (2026-09-04) made each run decode ~37% more, and a BUG IN THAT FIX made the
# harness spin: it retried after Z_BUF_ERROR even when the loop head could not
# hand the decoder anything new, burning iterations until the guard. That, not
# the extra coverage, is what took the run past 20 minutes. With the spin gone,
# 30000 runs cost about a minute.
"$out/difftest" "${1:-30000}" "${2:-20260903}"
