#!/usr/bin/env bash
# inline-prize.sh [iters] [blocksize]
#
# WHAT PUTTING RUST IN THE LTO GRAPH BUYS, on lib/-shaped code, measured.
#
# All arms run the SAME program: the C entry thunk calling ported Rust, with
# inflate_rs calling inffast_rs and inftrees_rs across crate boundaries exactly
# as the kernel builds them (one crate per _rs.rs). Only the link differs.
#
#   A  no LTO                    as we ship today
#   B  -flto=thin                the kernel's own mode (Makefile:1013)
#   C  B + import-instr-limit    the callees are actually OFFERED to the inliner
#   D  C + inline-threshold      the inliner is FORCED to take them
#
# ARMS C AND D EXIST BECAUSE THE FIRST VERSION OF THIS SCRIPT DREW A WRONG
# CONCLUSION FROM ARM B. It reported "+0.004%, the inliner declined on cost,
# as it should". Adversarial review read the ThinLTO index:
#
#     inflate_fast        extern (inst: 595)
#     zlib_inflate_table  extern (inst: 619)
#     rust_zlib_inflate   extern (inst: 2010)
#
# against LLVM's default -import-instr-limit of 100. The IMPORTER refused those
# bodies before any cost model ran, and `-print-imports` confirms none of them
# was imported. So arm B alone cannot say anything about what an inliner
# decided -- and a reader who checks would reasonably conclude we had
# benchmarked a disabled optimisation.
#
# Arm C raises the import limit so the bodies really are in-module. Arm D then
# forces the inline. D is the arm that turns "the inliner declined" from an
# assertion into a measurement.
#
# THE PRIMARY MEASURE IS RETIRED INSTRUCTIONS UNDER CALLGRIND, deterministic
# and layout-independent. Two arms means two binaries, and the rig's own note
# records that "a single binary constitutes just one sample from the space of
# program layouts" -- the trick bench.c uses (both arms in one binary) is
# unavailable when the arms differ by how they were LINKED. Cycles are reported
# as a cross-check; wall time is not citable.
#
# BLOCK SIZE MATTERS AS MUCH AS THE COMPILER. The ratio is a function of how
# often the boundary is crossed, so it is meaningless without that count.
# Review measured 400 crossings (one 256 KB stream) to 81,920 (512 B blocks) --
# 205x more crossings, 18x larger effect, same sign. Pass a block size to run
# the page-shaped workload, which is how squashfs, zram, initramfs and ubifs
# actually call this code.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
iters=${1:-400}          # default 400: the committed table is a 400-iter run
bs=${2:-0}               # 0 = one stream over the whole buffer
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"

ZP="$root/port/pristine/lib/zlib_inflate"
INC=(-I "$root/port/test/zlib_inflate/shim" -I "$root/port/test/common/shim" -I "$ZP")
# -fno-pie / relocation-model=static BECAUSE THE KERNEL BUILDS THAT WAY, and
# because under the userspace default (PIC) a cross-crate call is an indirect
# GOT jump -- R_X86_64_GOTPCREL -- carrying no symbol name in the disassembly.
# The first run of this script looked for `call <inflate_fast>`, found none in
# EITHER arm, and reported "0 cross-crate call sites" for the arm that
# definitely makes the call.
CF=(-O2 -Wall -Wno-unused-parameter -Wno-sign-compare -fno-pie)
RSCRATES=(inflate_rs inffast_rs inftrees_rs)

build_arm() {    # $1 name  $2 rustc-extra  $3 cc-extra  $4 ld-extra
    local n=$1 d="$out/$1" c; mkdir -p "$d"
    for c in "${RSCRATES[@]}"; do
        # -C overflow-checks=y BECAUSE THE KERNEL DOES. Omitting it measures a
        # Rust we do not ship, faster on every arithmetic operation.
        # shellcheck disable=SC2086
        "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
            -C overflow-checks=y -C debug-assertions=n -C panic=abort \
            -C relocation-model=static $2 --crate-name "$c" -o "$d/lib$c.a" \
            "$root/port/tree/lib/zlib_inflate/$c.rs"
    done
    # shellcheck disable=SC2086
    clang "${CF[@]}" $3 "${INC[@]}" -c -o "$d/thunk.o" \
        "$root/port/tree/lib/zlib_inflate/inflate_thunk.c"
    # shellcheck disable=SC2086
    clang "${CF[@]}" $3 "${INC[@]}" -c -o "$d/prize.o" "$here/prize_zlib.c"
    clang "${CF[@]}" -c -o "$d/corpus.o" "$root/port/test/zlib_inflate/corpus.c"
    # shellcheck disable=SC2086
    clang "${CF[@]}" $3 $4 -no-pie -o "$d/prize" "$d/prize.o" "$d/thunk.o" \
        "$d/corpus.o" "$d/libinflate_rs.a" "$d/libinffast_rs.a" \
        "$d/libinftrees_rs.a" -lz 2>"$d/ld.log"
    [ -x "$d/prize" ] || { echo "arm $n: NO BINARY PRODUCED" >&2; exit 1; }
}

LTO_LD=(-flto=thin -fuse-ld=lld -fsplit-lto-unit)   # -fsplit-lto-unit: the kernel's flag
IMP="-Wl,-mllvm,-import-instr-limit=100000"
INL="-Wl,-mllvm,-inline-threshold=100000 -Wl,-mllvm,-inlinehint-threshold=100000"

echo "building arms (iters=$iters blocksize=${bs:-whole})..."
build_arm A "" "" ""
build_arm B "-C linker-plugin-lto" "-flto=thin" "${LTO_LD[*]} -Wl,-mllvm,-print-imports"
build_arm C "-C linker-plugin-lto" "-flto=thin" "${LTO_LD[*]} $IMP -Wl,-mllvm,-print-imports"
build_arm D "-C linker-plugin-lto" "-flto=thin" "${LTO_LD[*]} $IMP $INL"

# THE REAL LTO CONTROL. `file` saying "LLVM IR bitcode" proves only that rustc
# emitted bitcode; it cannot detect lld accepting it and doing no cross-module
# work. -print-imports lists every import lld actually made, so a nonzero count
# of C<->Rust imports is proof that cross-language ThinLTO ran.
echo
for a in B C; do
    n=$(grep -c 'Import .* from .*inflate_rs' "$out/$a/ld.log" 2>/dev/null || true)
    printf '  arm %s: %s cross-language imports (C <- Rust)\n' "$a" "$n"
    [ "$a" = B ] && [ "$n" = 0 ] && { echo "*** arm B did no cross-module work -- not measuring" >&2; exit 1; }
done
for a in B C; do
    printf '  arm %s: inflate_fast imported? %s\n' "$a" \
        "$(grep -qE 'Import inflate_fast' "$out/$a/ld.log" && echo yes || echo NO)"
done

echo
echo "=== cross-crate call sites remaining"
for a in A B C D; do
    printf '  arm %s: %s\n' "$a" \
      "$(llvm-objdump -d "$out/$a/prize" | grep -cE 'call.*<(inflate_fast|zlib_inflate_table)>' || true)"
done

echo
echo "=== correctness: all arms must agree"
ref=""
for a in A B C D; do
    o=$("$out/$a/prize" "$iters" "$bs")
    [ -z "$ref" ] && ref="$o"
    [ "$o" = "$ref" ] || { echo "*** arm $a disagrees: $o vs $ref" >&2; exit 1; }
done
echo "  all four agree: $ref   (iters blocksize crossings checksum)"

echo
echo "=== retired instructions (callgrind, deterministic)"
declare -A IR
for a in A B C D; do
    IR[$a]=$(valgrind --tool=callgrind --callgrind-out-file=/dev/null \
             "$out/$a/prize" "$iters" "$bs" 2>&1 | sed -n 's/.*I *refs: *//p' | tr -d ', ')
done
for a in A B C D; do
    awk -v n="$a" -v v="${IR[$a]}" -v base="${IR[A]}" 'BEGIN{
        printf "  arm %s  %15s   %+.4f%%\n", n, v, (v/base-1)*100 }'
done
echo "  A=no LTO  B=ThinLTO(as kernel)  C=B+bodies offered  D=C+inline forced"
