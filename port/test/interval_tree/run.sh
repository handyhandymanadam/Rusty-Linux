#!/usr/bin/env bash
# port/test/interval_tree/run.sh -- the userspace differential for
# lib/interval_tree.c.
#
# THE RUST IS COMPILED FROM THE FILE THE KERNEL BUILDS, not copied. The C is
# port/pristine/, not the tree, and it is #include-free of any transcription:
# the oracle IS lib/interval_tree.c, compiled with every symbol it exports
# renamed c_* so both arms link into one binary.
#
# WHAT THIS HARNESS COMPILES THAT THE OTHERS DO NOT
#
#   port/pristine/lib/rbtree.c, once, SHARED BY BOTH ARMS. lib/rbtree.c is
#   not ported, and `nm -g` on the compiled oracle leaves exactly
#   __rb_insert_augmented, __rb_erase_color and rb_next undefined -- every
#   other rbtree primitive interval_tree uses is static inline in a header
#   and is reproduced inside interval_tree_rs.rs. Both arms calling one copy
#   is the same arrangement port/test/cmdline/ uses for simple_strtoull: the
#   comparison is between two interval trees over one rbtree, which is what
#   the kernel ships.
#
# CRITERION 8 (logs/floor.md RAISE 3): lib/interval_tree.c branches on
# exactly one Kconfig symbol, CONFIG_INTERVAL_TREE_SPAN_ITER, and a kernel
# can be built either way -- only CONFIG_IOMMUFD selects it. So this script
# takes the raise's second option: it BUILDS BOTH ARMS BOTH WAYS and runs
# the whole differential twice, rather than picking one and hoping.
#
# RAISE 1 (every combination of the Kconfig symbols the ported file reads):
# the cfg list is read OUT OF THE .rs, so adding a `#[cfg(CONFIG_...)]`
# extends the sweep instead of silently escaping it.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/interval_tree"
out="${TMPDIR:-/tmp}/interval_tree-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

# sabotage.sh --both points these at mutated copies so that BOTH arms carry
# the same defect. Nothing else may override them: the oracle is
# port/pristine/, never the tree, or the test agrees with itself.
C="${INTERVAL_TREE_C:-$root/port/pristine/lib/interval_tree.c}"
PINC="${INTERVAL_TREE_INC:-$root/port/pristine/include}"
RBTREE="$root/port/pristine/lib/rbtree.c"
# sabotage.sh points this at a mutated copy. Everything else -- the flags,
# the renames, the include order -- stays in ONE place, because
# logs/floor.md records run-be.sh duplicating each harness's build lines as
# a debt that "will drift".
RS="${INTERVAL_TREE_RS:-$root/port/tree/lib/interval_tree_rs.rs}"
for f in "$C" "$RBTREE" "$RS" \
         "$PINC/linux/interval_tree.h" \
         "$PINC/linux/interval_tree_generic.h" \
         "$PINC/linux/rbtree_augmented.h"; do
    [ -f "$f" ] || { echo "missing $f"; exit 2; }
done

# --- the probe: the ported file, plus a harness prelude and a geometry probe.
#
# The prelude stubs the three kernel:: macros the kernel build provides.
# `sed 's|^//!|//|'` demotes the module doc comment, because an inner doc
# comment cannot follow the `mod kernel` item -- so a placeholder crate doc
# goes in first and -Wmissing_docs stays meaningful for every item.
#
# The geometry probe is appended INSIDE the crate, which is the only place
# `offset_of!` can reach the mirrored structs' private fields. It gives
# logs/floor.md RAISE 6 -- "the part is inspected against the blueprint" --
# a userspace arm: drv.c compares these numbers against offsetof() on the
# real kernel headers. rig/layout-check.sh still does the authoritative
# check on the built kernel's DWARF; this one runs before there is a build.
mkprobe() {
    local dst=$1
    {
        echo '//! Harness probe. The real module documentation is in'
        echo '//! port/tree/lib/interval_tree_rs.rs; run.sh demotes it because'
        echo '//! an inner doc comment cannot follow the prelude below.'
        echo '#![allow(non_snake_case)]'
        echo '#[allow(unused_macros, unused_imports)]'
        echo 'mod kernel {'
        echo '    macro_rules! kabi_rule { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_export { ($($t:tt)*) => {} }'
        echo '    macro_rules! kabi_modinfo { ($($t:tt)*) => {} }'
        echo '    pub(crate) use {kabi_rule, kabi_export, kabi_modinfo};'
        echo '}'
        sed 's|^//!|//|' "$RS"
        cat <<'PROBE'

// ---- harness only, appended by port/test/interval_tree/run.sh ----------

/// Writes this crate's view of the mirrored C structs' geometry into
/// `out`, in the order drv.c's `GEOM_*` indices name. Harness only: the
/// kernel build never sees this function, because it is appended to a copy.
///
/// # Safety
/// `out` must point to at least `GEOM_N` `usize`s.
#[no_mangle]
pub unsafe extern "C" fn rs_geometry(out: *mut usize) {
    use core::mem::{align_of, offset_of, size_of};
    // SAFETY: caller guarantees `out` has room for every index written.
    unsafe {
        *out.add(0) = size_of::<IntervalTreeNode>();
        *out.add(1) = align_of::<IntervalTreeNode>();
        *out.add(2) = offset_of!(IntervalTreeNode, rb);
        *out.add(3) = offset_of!(IntervalTreeNode, start);
        *out.add(4) = offset_of!(IntervalTreeNode, last);
        *out.add(5) = offset_of!(IntervalTreeNode, subtree_last);
        *out.add(6) = size_of::<RbNode>();
        *out.add(7) = offset_of!(RbNode, rb_parent_color);
        *out.add(8) = offset_of!(RbNode, rb_right);
        *out.add(9) = offset_of!(RbNode, rb_left);
        *out.add(10) = size_of::<RbRoot>();
        *out.add(11) = size_of::<RbRootCached>();
        *out.add(12) = offset_of!(RbRootCached, rb_root);
        *out.add(13) = offset_of!(RbRootCached, rb_leftmost);
        #[cfg(CONFIG_INTERVAL_TREE_SPAN_ITER)]
        {
            *out.add(14) = size_of::<IntervalTreeSpanIter>();
            *out.add(15) = align_of::<IntervalTreeSpanIter>();
            *out.add(16) = offset_of!(IntervalTreeSpanIter, nodes);
            *out.add(17) = offset_of!(IntervalTreeSpanIter, first_index);
            *out.add(18) = offset_of!(IntervalTreeSpanIter, last_index);
            *out.add(19) = offset_of!(IntervalTreeSpanIter, start);
            *out.add(20) = offset_of!(IntervalTreeSpanIter, last);
            *out.add(21) = offset_of!(IntervalTreeSpanIter, is_hole);
        }
    }
}
PROBE
    } > "$dst"
}

# The kernel's own rustc lint set (logs/floor.md, the zstd harness gap):
#   -Dnon_ascii_idents -Dunsafe_op_in_unsafe_fn -Wmissing_docs
#   -Wrust_2018_idioms -Wunreachable_pub
# `-A unreachable_pub` stays because probe.rs nests nothing -- the lint would
# be an artefact of the harness rather than a property of the file.
RSFLAGS=(--edition 2021 -O -C panic=abort -C overflow-checks=on
         -D unsafe_op_in_unsafe_fn -D warnings -A unreachable_pub
         -Dnon_ascii_idents -Wmissing_docs -Wrust_2018_idioms)

# ---------------------------------------------------------------------------
# RAISE 1 -- every combination of the Kconfig symbols the ported file reads.
# The list is read out of the file, not carried here.
# ---------------------------------------------------------------------------
mapfile -t CFGS < <(grep -o 'cfg(CONFIG_[A-Z0-9_]*)' "$RS" \
                    | sed 's/cfg(\(.*\))/\1/' | sort -u)
n=${#CFGS[@]}
echo "RAISE 1 sweep: $n cfg symbol(s) -> $((1 << n)) subsets, --emit=metadata"
printf '  %s\n' "${CFGS[@]}"
mkprobe "$out/sweep.rs"
for ((mask = 0; mask < (1 << n); mask++)); do
    args=()
    for ((b = 0; b < n; b++)); do
        (( mask & (1 << b) )) && args+=(--cfg "${CFGS[b]}")
    done
    "$KB_RUSTC" "${RSFLAGS[@]}" --crate-type lib --emit=metadata \
        --crate-name interval_tree_rs -o "$out/sweep.rmeta" \
        "${args[@]}" "$out/sweep.rs"
done
echo "  all $((1 << n)) subsets type-check"

# ---------------------------------------------------------------------------
# The differential, run once per value of CONFIG_INTERVAL_TREE_SPAN_ITER --
# criterion 8's "compile both arms both ways" arm.
# ---------------------------------------------------------------------------
# `-include linux/compiler.h` mirrors kbuild, which puts
# `-include <linux/compiler_types.h>` in KBUILD_CPPFLAGS so that
# __always_inline and friends are defined before any header is read. Without
# it <linux/interval_tree.h> pulls <linux/rbtree.h> first and every
# `static __always_inline` in it is a syntax error -- which is a fact about
# how the kernel compiles this file, not a shim convenience.
CF=(-O2 -g -Wall -Wextra -Wno-unused-parameter
    -include linux/compiler.h
    -I "$here/shim" -I "$root/port/test/common/shim"
    -I "$PINC")

# Every symbol lib/interval_tree.c gives external linkage. The file's other
# functions are macro-generated statics and cannot collide.
REN=(
    -Dinterval_tree_insert=c_interval_tree_insert
    -Dinterval_tree_remove=c_interval_tree_remove
    -Dinterval_tree_iter_first=c_interval_tree_iter_first
    -Dinterval_tree_iter_next=c_interval_tree_iter_next
    -Dinterval_tree_span_iter_first=c_interval_tree_span_iter_first
    -Dinterval_tree_span_iter_next=c_interval_tree_span_iter_next
    -Dinterval_tree_span_iter_advance=c_interval_tree_span_iter_advance
)

build_and_run() {
    local span=$1 tag=$2 cfg=() def=() rsdef=()
    if [ "$span" = 1 ]; then
        cfg=(--cfg CONFIG_INTERVAL_TREE_SPAN_ITER)
        def=(-DCONFIG_INTERVAL_TREE_SPAN_ITER=1)
    fi

    mkprobe "$out/probe-$tag.rs"
    "$KB_RUSTC" "${RSFLAGS[@]}" --crate-type staticlib \
        --crate-name interval_tree_rs -o "$out/librs-$tag.a" \
        "${cfg[@]}" "$out/probe-$tag.rs"

    cc "${CF[@]}" "${def[@]}" -c -o "$out/rbtree-$tag.o" "$RBTREE"
    cc "${CF[@]}" "${def[@]}" "${REN[@]}" -c -o "$out/cref-$tag.o" "$C"
    cc "${CF[@]}" "${def[@]}" -c -o "$out/drv-$tag.o" "$here/drv.c"
    cc -o "$out/t-$tag" "$out/drv-$tag.o" "$out/cref-$tag.o" \
        "$out/rbtree-$tag.o" "$out/librs-$tag.a"

    # THE ARRANGEMENT PROVES ITSELF FIRST, before its clean run is believed.
    # One node's interval is one larger in the Rust arm only.
    #
    # WHAT COUNTS AS PROOF IS A REPORTED MISMATCH, NOT AN EXIT CODE, and this
    # check has now been wrong in both directions:
    #
    #   v1 accepted any nonzero exit. A sabotaged port SEGFAULTS, which is
    #   also a nonzero exit -- so "the poisoned run failed" was satisfied by
    #   a crash that had compared nothing.
    #
    #   v2 required exit code 1 exactly. That is wrong the other way: a
    #   poisoned run can report a mismatch and THEN crash, and v2 called
    #   that "the harness cannot disagree" -- a false statement about a log
    #   that has a mismatch in it. Demonstrated, not argued: sabotage slip 4
    #   produces exactly that.
    #
    # So: the evidence is the driver's own printed verdict. The exit code is
    # reported alongside it rather than gating on it.
    set +e
    INTERVAL_TREE_PROVE_CAN_FAIL=1 "$out/t-$tag" > "$out/poisoned-$tag.log" 2>&1
    prc=$?
    set -e
    if ! grep -q '^MISMATCH:\|^GEOMETRY:' "$out/poisoned-$tag.log"; then
        echo "*** THE HARNESS CANNOT DISAGREE ($tag): the poisoned run"
        echo "    (exit $prc) reported no mismatch. Last lines:"
        tail -5 "$out/poisoned-$tag.log" | sed 's/^/    /'
        exit 1
    fi
    echo "prove-can-fail ($tag): a poisoned Rust arm is reported (exit $prc)"

    "$out/t-$tag"
}

echo
echo "=== arm 1 of 2: CONFIG_INTERVAL_TREE_SPAN_ITER=y ==="
build_and_run 1 span

echo
echo "=== arm 2 of 2: CONFIG_INTERVAL_TREE_SPAN_ITER unset ==="
build_and_run 0 nospan

echo
echo "both configurations: 0 mismatches"
