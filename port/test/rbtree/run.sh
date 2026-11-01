#!/usr/bin/env bash
# Differential test for lib/rbtree.c -> port/tree/lib/rbtree_rs.rs.
#
#   run.sh [runs] [seed]
#   run.sh --selfcheck [runs] [seed]   # ref vs ref: proves the harness only
#
# Compiles the SAME .rs the kernel build compiles, out of port/tree/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/rbtree-difftest.$$"

self=0
if [ "${1:-}" = "--selfcheck" ]; then self=1; shift; fi

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

RBTREE="$root/port/pristine/lib/rbtree.c"
# Reused, not duplicated: this shim was built to compile lib/rbtree.c (and
# lib/interval_tree.c beside it) in userspace, and nothing here is specific
# to interval_tree.
INC=(-I "$root/port/test/interval_tree/shim" -I "$root/port/test/common/shim" -I "$root/port/pristine/include")

echo "sources:"
for f in "$root/port/tree/lib/rbtree_rs.rs" "$RBTREE"; do
    printf '  %s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

CFLAGS=(-O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -include linux/compiler.h)
LINTS=(-D non_ascii_idents -D unsafe_op_in_unsafe_fn -W missing_docs
       -W rust_2018_idioms -W unreachable_pub -A stable_features
       -A unused_features -D warnings)

if [ "$self" = 0 ]; then
    echo "config sweep: rbtree_rs.rs builds for x86_64 and aarch64"
    echo "              (no CONFIG_ fork, no DYNAMIC_BMI2 -- pure algorithm)"
    swept_nonx86=0
    for t in x86_64-unknown-linux-gnu aarch64-unknown-none; do
        # kernel::kabi_export!/kabi_rule! stand-ins, a REAL separate crate
        # (not a same-file module) -- see kernel_stub.rs's own comment.
        # rlibs are target-specific, so built once per target swept.
        RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -Z crate-attr=no_std --target "$t" \
            --crate-name kernel -o "$out/libkernel-$t.rlib" "$here/kernel_stub.rs"
        if RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
            -C panic=abort -Z crate-attr=no_std "${LINTS[@]}" \
            --extern kernel="$out/libkernel-$t.rlib" \
            --target "$t" --crate-name sweep --emit=metadata \
            -o "$out/sweep-$t.rmeta" \
            "$root/port/tree/lib/rbtree_rs.rs" \
            2>"$out/sweep.err"
        then
            echo "  ok  $t"
            case "$t" in *x86*) ;; *) swept_nonx86=1 ;; esac
        else
            sed -n '1,14p' "$out/sweep.err"; echo "  FAIL $t"; exit 1
        fi
    done
    [ "$swept_nonx86" = 1 ] || { echo "  UNSWEPT: no non-x86 target"; exit 1; }
    echo

    "$KB_RUSTC" --edition 2021 --crate-type rlib -O \
        --crate-name kernel -o "$out/libkernel-host.rlib" "$here/kernel_stub.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        "${LINTS[@]}" -A unreachable_pub \
        --extern kernel="$out/libkernel-host.rlib" \
        --crate-name rbtree_rs \
        -o "$out/librbtree_rs.a" "$here/probe.rs"
fi

cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/ref_rbtree.o" "$here/ref_rbtree.c"
cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/main.o" "$here/main.c"

if [ "$self" = 1 ]; then
    cc "${CFLAGS[@]}" "${INC[@]}" -c -o "$out/selfcheck.o" "$here/selfcheck.c"
    cc -o "$out/difftest" "$out"/*.o
else
    cc -o "$out/difftest" "$out"/*.o "$out/librbtree_rs.a"
fi

cd "$root"
"$out/difftest" "${1:-200}" "${2:-20260906}"
