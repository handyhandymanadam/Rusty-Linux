#!/usr/bin/env bash
# Differential test for lib/xz/xz_dec_bcj.c -> xz_dec_bcj_rs.rs.
# Userspace, no kernel. Two arms in one binary; the only difference between
# them is which implementation is called.
#
#   run.sh [runs] [seed]
#
# Compiles the SAME .rs the kernel build compiles, via a #[path] wrapper in
# probe.rs -- not a copy. A stale copy tested here while the kernel built
# something else is the failure PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/xz-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

P="$root/port/pristine/lib/xz"
INC=(-I "$here/shim" -I "$P" -I "$root/src/linux/include")

echo "sources:"
for f in "$root/port/tree/lib/xz/xz_dec_bcj_rs.rs" "$P/xz_dec_bcj.c" \
         "$root/src/linux/include/linux/xz.h"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo "cc:    $(cc --version | head -1)"
echo

# The seven filters both kernel configs enable. They reach rustc in the kernel
# build through @include/generated/rustc_cfg; here they are spelled out, and
# ref_bcj.c #defines the matching XZ_DEC_* so the oracle builds the same seven.
CFG=(--cfg CONFIG_XZ_DEC_X86 --cfg CONFIG_XZ_DEC_POWERPC --cfg CONFIG_XZ_DEC_ARM
     --cfg CONFIG_XZ_DEC_ARMTHUMB --cfg CONFIG_XZ_DEC_SPARC
     --cfg CONFIG_XZ_DEC_ARM64 --cfg CONFIG_XZ_DEC_RISCV)

# Overflow checks and debug assertions ON, which is what makes the invariants
# in the port's comments load-bearing here even though the kernel compiles the
# assertions out. Every BCJ filter subtracts a position from a value read out
# of attacker-supplied data, so the wrapping is not incidental.
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
    "${CFG[@]}" \
    --crate-name xz_dec_bcj_rs -o "$out/libxz_dec_bcj_rs.a" "$here/probe.rs"

# ---------------------------------------------------------------------------
# CONFIG SWEEP -- floor.md's 2026-09-03 raise.
#
# Every CONFIG_* this file reads is `bool "..." if EXPERT / default y` in
# lib/xz/Kconfig, so switching one off is inside the supported config space,
# and CONFIG_WERROR=y turns rustc's "constant is never used" into a build
# failure. The port shipped in a commit that could not build with any single
# filter disabled, while the C built fine -- a C enum constant never warns.
# Neither of this project's two configs sets EXPERT, so nothing here saw it.
#
# The symbol list is READ OUT OF THE FILE, not written down here, so adding a
# filter extends the sweep automatically. ~3 s for all 127 subsets.
# ---------------------------------------------------------------------------
# ^[[:space:]]*#\[cfg -- an ATTRIBUTE at the start of a line, not a mention of
# one inside a //! doc comment. The doc names CONFIG_XZ_DEC_IA64 to explain why
# it is not ported, and a looser pattern swept a symbol no build can set.
mapfile -t CFGSYMS < <(grep -oE '^[[:space:]]*#\[cfg\(.*' \
                           "$root/port/tree/lib/xz/xz_dec_bcj_rs.rs" |
                       grep -oE 'CONFIG_[A-Z0-9_]+' | sort -u)
nsym=${#CFGSYMS[@]}
if [ "$nsym" -gt 12 ]; then
    echo "config sweep: $nsym symbols is too many to sweep exhaustively" >&2
    exit 2
fi
sweep_fail=0
for ((mask = 1; mask < (1 << nsym); mask++)); do
    sargs=()
    for ((i = 0; i < nsym; i++)); do
        (((mask >> i) & 1)) && sargs+=(--cfg "${CFGSYMS[$i]}")
    done
    if ! "$KB_RUSTC" --edition 2021 --crate-type rlib --emit=metadata \
            -C panic=abort -C overflow-checks=on \
            -D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs -W rust_2018_idioms -W unreachable_pub -A stable_features -A unused_features -D warnings \
            "${sargs[@]}" --crate-name sweep --out-dir "$out" \
            "$root/port/tree/lib/xz/xz_dec_bcj_rs.rs" 2>"$out/sweep.err"; then
        echo "CONFIG SWEEP FAILED with ${sargs[*]}"
        head -5 "$out/sweep.err"
        sweep_fail=$((sweep_fail + 1))
    fi
done
if [ "$sweep_fail" -ne 0 ]; then
    echo "config sweep: $sweep_fail of $(((1 << nsym) - 1)) subsets do not build"
    exit 1
fi
echo "config sweep: all $(((1 << nsym) - 1)) non-empty subsets of ${CFGSYMS[*]} build clean"
echo

CFLAGS=(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare)

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_bcj.o" "$here/ref_bcj.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"

cc -o "$out/difftest" "$out/main.o" "$out/ref_bcj.o" "$out/libxz_dec_bcj_rs.a"

cd "$root"
"$out/difftest" "${1:-200000}" "${2:-20260903}"
