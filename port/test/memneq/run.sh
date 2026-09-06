#!/usr/bin/env bash
# port/test/memneq/run.sh -- the userspace differential for lib/crypto/memneq.
#
# WHY IT EXISTS AT ALL. It was argued that it did not need to: the in-kernel
# vectors in lib/libtest.c are exhaustive over every length and offset that
# reaches a different code path, so a userspace arm would run the same paths
# against the same C for longer. An adversarial review built one anyway and
# it earned its keep -- not by finding a wrong answer (there is none, over
# 15 million cases) but by reaching two things the kernel arm cannot:
#
#   - the not(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) arm, which neither of
#     our kernel configurations compiles (logs/build-limits.md);
#   - CONFIG_RUST_DEBUG_ASSERTIONS=y, which adds a panic path the C has no
#     equivalent of.
#
# THE RUST IS NOT COPIED. It is generated here from the file the kernel
# builds, so it cannot drift from it. The only edits are a stub for the two
# kernel macros and turning `//!` into `//` -- the prelude cannot precede an
# inner doc comment.
#
# THE C IS port/pristine/, not the tree, for the usual reason: reading the
# oracle out of a tree we have edited is a test agreeing with itself.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/memneq"
out="${TMPDIR:-/tmp}/memneq-diff.$$"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/crypto/memneq.c"
RS="$root/port/tree/lib/crypto/memneq_rs.rs"
[ -f "$C" ]  || { echo "missing $C";  exit 2; }
[ -f "$RS" ] || { echo "missing $RS"; exit 2; }

# ---------------------------------------------------------------------------
# THE SHIM MUST MATCH THE KERNEL HEADER, NOT MERELY COMPILE. lib/lz4's harness
# spent hours on an oracle that compiled a different program because a shim
# was copied without checking which definition the new file actually needs.
# OPTIMIZER_HIDE_VAR is the whole subject of this port, so it is checked
# character for character against include/linux/compiler.h.
want=$(sed -n '/^#define OPTIMIZER_HIDE_VAR(var)/,/^$/p' \
       "$root/src/linux/include/linux/compiler.h" \
       | tr -d ' \t\\\n')
have=$(sed -n '/^#define OPTIMIZER_HIDE_VAR(var)/,/^$/p' \
       "$here/shim/crypto/algapi.h" | tr -d ' \t\\\n')
if [ "$want" != "$have" ]; then
    echo "SHIM MISMATCH -- the oracle would be a different program"
    echo "  kernel: $want"
    echo "  shim:   $have"
    exit 1
fi
echo "shim OPTIMIZER_HIDE_VAR matches include/linux/compiler.h"

# ---------------------------------------------------------------------------
gen_rs() {
    {
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        sed 's|^//!|//|' "$RS"
    } > "$out/probe.rs"
}
gen_rs

build_rs() {   # $1 = output archive, $2.. = extra rustc flags
    local o=$1; shift
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name memneq_rs "$@" -o "$o" "$out/probe.rs"
}

CF=(-O2 -g -Wall -I "$here/shim")
cc "${CF[@]}" -DCONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS -D__crypto_memneq=c_memneq -c -o "$out/c_eua.o"  "$C"
cc "${CF[@]}"                                          -D__crypto_memneq=c_memneq -c -o "$out/c_noeua.o" "$C"

build_rs "$out/librs_eua.a"   --cfg CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS -C debug-assertions=off
build_rs "$out/librs_noeua.a"                                              -C debug-assertions=off
build_rs "$out/librs_dbg.a"   --cfg CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS -C debug-assertions=on

cc "${CF[@]}" -c -o "$out/drv.o" "$here/drv.c"

link() { cc -o "$out/$1" "$out/drv.o" "$out/$2" "$out/$3"; }
link t_eua   c_eua.o   librs_eua.a
link t_noeua c_noeua.o librs_noeua.a
link t_dbg   c_eua.o   librs_dbg.a
link t_cross c_eua.o   librs_noeua.a      # deliberately mismatched, see below

rc=0
for arm in eua noeua dbg; do
    printf '%-8s ' "$arm"
    if "$out/t_$arm" | tail -1; then :; else rc=1; echo "  *** $arm FAILED"; fi
done

# ---------------------------------------------------------------------------
# THE ARRANGEMENT PROVES ITSELF FIRST. A differential that cannot disagree is
# not a differential, and this one has never disagreed. So the last arm pairs
# the C's word-at-a-time body against the Rust's byte-at-a-time body: same
# zero/non-zero answer every time, different VALUE whenever the difference is
# past byte 7. If this arm reports 0 mismatches the harness is not comparing
# anything and the three runs above mean nothing.
printf '%-8s ' cross
# `|| true`: the cross arm is SUPPOSED to exit non-zero, and this script runs
# under `set -o pipefail`, which would otherwise end it here with no message.
xm=$("$out/t_cross" 2>/dev/null | sed -n 's/.*mismatches=\([0-9]*\)/\1/p') || true
echo "mismatches=$xm  (expected: many)"
if [ "${xm:-0}" -eq 0 ]; then
    echo "*** THE HARNESS IS NOT COMPARING ANYTHING -- cross arm agreed"
    rc=1
fi
exit $rc
