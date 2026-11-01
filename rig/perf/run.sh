#!/usr/bin/env bash
# The shared measuring rig (notes/GOALS.md §4). ONE binary, both arms inside it.
#
#   run.sh              measure the kerf, then take a series
#   run.sh --kerf-only  measure the kerf and stop
#
# THE KERF IS MEASURED FIRST, EVERY TIME. §4: "You cannot check a 10% target
# with a tool that is wrong by 20%." The control puts identical code in both
# arms; whatever deviation appears IS the kerf, by definition. Nothing below
# it means anything.
#
# Rows go to logs/quick-perf.tsv, which is NOT citable and never compared
# against logs/system-perf.tsv -- different instrument, different question.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
shim="$root/port/test/lib/shim"
out="${TMPDIR:-/tmp}/perf-rig.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

source "$root/kbuild-env.sh"

# The rig stamp. Every row carries it; change any field and the series ends
# and a new one begins (§4).
stamp_machine="$(uname -s) $(uname -r) $(uname -m)"
stamp_cpu=$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo)
stamp_rustc=$("$KB_RUSTC" --version | awk '{print $1" "$2}')
stamp_cc=$(cc --version | head -1)

echo "rig stamp"
printf '  machine  %s\n  cpu      %s\n  rustc    %s\n  cc       %s\n\n' \
    "$stamp_machine" "$stamp_cpu" "$stamp_rustc" "$stamp_cc"

# The Rust arms: the SAME .rs files the kernel compiles, out of port/tree/.
srcs=("$root"/port/tree/lib/*_rs.rs "$root"/port/tree/lib/crc/*_rs.rs
      "$root"/port/tree/lib/crypto/*_rs.rs "$root"/port/tree/lib/math/*_rs.rs
      "$root"/port/tree/lib/zlib_inflate/*_rs.rs
      "$root"/port/tree/lib/lzo/*_rs.rs)
# A file that another ported file include!()s is a FRAGMENT, not a crate: it
# has no `use` lines of its own and will not compile alone.
# lib/zlib_inflate/inffixed_rs.rs is one (inflate_rs.rs include!()s it), and
# this glob tried to build it as a crate and failed with "cannot find type
# `Code` in this scope". Drop anything another ported file includes.
keep=()
for s_ in "${srcs[@]}"; do
    b=$(basename "$s_")
    if grep -rqF "include!(\"$b\")" "$root"/port/tree --include='*.rs' 2>/dev/null; then
        continue
    fi
    keep+=("$s_")
done
srcs=("${keep[@]}")

objs=()
for s in "${srcs[@]}"; do
    n=$(basename "$s" .rs)
    # -C overflow-checks=y BECAUSE THE KERNEL DOES. Verified against the real
    # build, not assumed: Makefile:886 is
    #     KBUILD_RUSTFLAGS += -Coverflow-checks=$(if $(CONFIG_RUST_OVERFLOW_CHECKS),y,n)
    # and build-fast/lib/zstd/common/.entropy_common_rs.o.cmd contains
    # `-Coverflow-checks=y`. Omitting it here measured a Rust that does not
    # exist -- faster than the one we ship, on every arithmetic operation --
    # so every delta this rig ever reported FLATTERED Rust. That was recorded
    # as an open defect on 2026-09-03 and fixed 2026-09-04.
    #
    # The C arm gets no equivalent flag and should not: the kernel's C has no
    # overflow checking. The asymmetry is real and is part of what we are
    # measuring, not an artefact to be cancelled out.
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C overflow-checks=y -C debug-assertions=n \
        -C panic=abort -D unsafe_op_in_unsafe_fn -W missing-docs \
        --crate-name "$n" -o "$out/lib$n.a" "$s"
    objs+=("$out/lib$n.a")
done

# The C arms: the PRISTINE kernel sources, compiled -- not transcriptions.
python3 "$root/port/test/lib/extract_crc16_table.py" \
        "$root/port/pristine/lib/crc/crc16.c" \
        "$root/port/test/lib/ref_crc16_table_generated.h"

# The zlib_inflate arms. Same construction as port/test/zlib_inflate: both
# arms are the pristine C pipeline, and the only difference between them is
# which inflate_fast() is linked in. Its own shim, its own objects.
ZP="$root/port/pristine/lib/zlib_inflate"
ZSHIM="$root/port/test/zlib_inflate/shim"
ZINC=(-I "$ZSHIM" -I "$root/port/test/common/shim" -I "$ZP")
ZCF=(-O2 -Wall -Wno-unused-parameter -Wno-sign-compare)
ZREF=(-Dzlib_inflate=ref_zlib_inflate -Dzlib_inflateEnd=ref_zlib_inflateEnd
      -Dzlib_inflateIncomp=ref_zlib_inflateIncomp
      -Dzlib_inflateInit2=ref_zlib_inflateInit2
      -Dzlib_inflateReset=ref_zlib_inflateReset
      -Dzlib_inflate_workspacesize=ref_zlib_inflate_workspacesize
      -Dinflate_fast=ref_inflate_fast)
ZRS=(-Dzlib_inflate=rs_zlib_inflate -Dzlib_inflateEnd=rs_zlib_inflateEnd
     -Dzlib_inflateIncomp=rs_zlib_inflateIncomp
     -Dzlib_inflateInit2=rs_zlib_inflateInit2
     -Dzlib_inflateReset=rs_zlib_inflateReset
     -Dzlib_inflate_workspacesize=rs_zlib_inflate_workspacesize)
cc "${ZCF[@]}" "${ZINC[@]}" "${ZREF[@]}" -c -o "$out/z_ref_inflate.o" "$ZP/inflate.c"
cc "${ZCF[@]}" "${ZINC[@]}" "${ZREF[@]}" -c -o "$out/z_ref_inffast.o" "$ZP/inffast.c"
cc "${ZCF[@]}" "${ZINC[@]}" "${ZRS[@]}"  -c -o "$out/z_rs_inflate.o"  "$ZP/inflate.c"
cc "${ZCF[@]}" "${ZINC[@]}"              -c -o "$out/z_inftrees.o"    "$ZP/inftrees.c"
cc "${ZCF[@]}" "${ZINC[@]}" -c -o "$out/z_bench.o" "$here/bench_zlib.c"
cc "${ZCF[@]}" -c -o "$out/z_corpus.o" "$root/port/test/zlib_inflate/corpus.c"

# The LZO arms. Same construction: pristine C as the oracle, the ported
# function swapped in, one binary. The encoder is the in-tree one.
LP="$root/port/pristine/lib/lzo"
LINC=(-I "$root/port/test/lzo/shim" -I "$root/port/test/common/shim" -I "$LP")
cc "${ZCF[@]}" "${LINC[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=1 \
   -Dlzo1x_decompress_safe=ref_lzo1x_decompress_safe \
   -c -o "$out/l_ref_dec.o" "$LP/lzo1x_decompress_safe.c"
cc "${ZCF[@]}" "${LINC[@]}" -c -o "$out/l_comp.o" "$LP/lzo1x_compress.c"
cc "${ZCF[@]}" "${LINC[@]}" -c -o "$out/l_bench.o" "$here/bench_lzo.c"

cc -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -I "$shim" \
   -I "$root/port/test/common/shim" \
   -I "$root/port/test/lib" \
   -o "$out/bench" "$here/bench.c" "$here/stubs.c" \
   "$root/port/test/glob/ref_glob.c" \
   "$root/port/test/math/ref_math.c" \
   "$root/port/test/lib/ref_lib.c" \
   "$root/port/test/lib/ref_crc_ccitt.c" \
   "$root/port/test/lib/ref_xxhash.c" \
   "$root/port/test/lib/ref_chacha.c" \
   "$root/port/test/lib/ref_check_signature.c" \
   "$out/z_bench.o" "$out/z_corpus.o" "$out/z_inftrees.o" \
   "$out/l_bench.o" "$out/l_comp.o" "$out/l_ref_dec.o" \
   "$out/z_ref_inflate.o" "$out/z_ref_inffast.o" "$out/z_rs_inflate.o" \
   "${objs[@]}" -lz

# `$1` is the repetition count, EXCEPT when it is the mode flag. Passing
# --kerf-only straight through made it the repetition count, atoi("--kerf-only")
# is 0, and bench.c then ran zero repetitions and printed its 1e30 sentinel as
# every timing -- a wrong number that looked like a number. Found 2026-09-03
# while adding the inflate rows.
kerf_only=0
reps=7
if [ "${1:-}" = "--kerf-only" ]; then
    kerf_only=1
    reps=${2:-7}
elif [ -n "${1:-}" ]; then
    reps=$1
fi

# bench refuses reps < 1 and exits 2, but run.sh drops its stderr, so without
# this the refusal would arrive as silence and a non-zero status -- a silent
# failure standing in for a wrong number, which is not an improvement.
if ! [ "$reps" -ge 1 ] 2>/dev/null; then
    echo "run.sh: repetition count must be an integer >= 1, got '$reps'" >&2
    exit 2
fi

echo "== CONTROL: identical code in both arms.  This is the kerf."
"$out/bench" --control "$reps" 2>/dev/null | tee "$out/control.txt"
echo

if [ "$kerf_only" -eq 1 ]; then
    exit 0
fi

echo "== SERIES: C arm vs Rust arm"
"$out/bench" "" "$reps" 2>/dev/null | tee "$out/series.txt"

python3 "$here/record.py" "$root" "$out/control.txt" "$out/series.txt" \
    "$stamp_machine" "$stamp_cpu" "$stamp_rustc" "$stamp_cc"
