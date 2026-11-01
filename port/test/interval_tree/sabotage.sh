#!/usr/bin/env bash
# port/test/interval_tree/sabotage.sh -- a SMOKE TEST ON THE HARNESS.
#
# READ logs/floor.md RULE T2 BEFORE QUOTING ANY NUMBER THIS PRINTS.
# The score is not a stopping rule and must not be cited as one, in a commit
# message, a status file, or a decision to stop testing. Absolute mutation
# scores are not interpretable (Just et al., FSE 2014, §2.5), the largest
# fault class mutation cannot represent is "the fix was to re-implement the
# algorithm" -- which is what a C-to-Rust port IS -- and a hand-picked list
# of twenty is not a systematic operator set. What this answers, and the
# only thing it answers, is: CAN THIS HARNESS SEE ANYTHING AT ALL?
#
# Each slip is one edit to a COPY of port/tree/lib/interval_tree_rs.rs; the
# real file is never touched. run.sh is then run against the copy, so there
# is exactly one set of build lines in this directory.
#
# A COMPILE ERROR IS NOT A CATCH (logs/hooks.md). Twice in this project a
# mutation was scored as caught on a nonzero exit that was rustc refusing
# the file under `-D warnings`, with not one line of the code under test
# run. Every result here is checked for that and counted as MISSED.
#
# AND A SEGFAULT IS A WEAKER CATCH THAN A REPORTED MISMATCH. A slip that
# corrupts the tree crashes the driver, which says the tree was broken
# without saying the comparison could see the difference. Both count as
# caught; the report distinguishes them, because only one of them is
# evidence about the instrument.
#
# THE SECOND HALF -- and it is the half that matters more.
#
# Mutating only the Rust can never exercise this harness's three INDEPENDENT
# stages (the __subtree_last/red-black invariant checker, the in-order match
# oracle, the coverage-bitmap span oracle). Those exist for the case both
# arms are wrong TOGETHER, and one-armed mutation cannot produce it. So
# `sabotage.sh --both` applies the SAME slip to the pristine C and to the
# Rust, leaving the two arms in agreement -- at which point only an
# independent check can notice anything at all. That is the demonstration
# that this harness is more than two copies of one macro comparing notes.
set -uo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/interval_tree"
RS="$root/port/tree/lib/interval_tree_rs.rs"
work="${TMPDIR:-/tmp}/interval_tree-sabotage.$$"
mkdir -p "$work"; trap 'rm -rf "$work"' EXIT

both=0
[ "${1:-}" = "--both" ] && both=1

caught=0; missed=0; compile=0; n=0

# What noticed, in order of strength: an independent check firing means the
# arms AGREED and something outside them still saw the defect. `grep -oE`
# picks the leftmost match in the line, not the first alternative, so the
# three patterns are tried in separate passes rather than as one alternation
# -- the first version did use one alternation and reported the independent
# oracle's own catches as ordinary arm-vs-arm mismatches.
verdict() {
    local log=$1 w
    if grep -q 'Segmentation fault\|core dumped' "$log"; then
        echo "SIGSEGV (tree corrupted)"; return
    fi
    w=$(grep -m1 -oE 'BOTH ARMS disagree with the [a-z-]+ [a-z]+' "$log")
    [ -n "$w" ] || w=$(grep -m1 -oE 'INVARIANT: [a-z]+ [^ ]+' "$log")
    [ -n "$w" ] || w=$(grep -m1 -oE 'GEOMETRY: [^:]+' "$log")
    [ -n "$w" ] || w=$(grep -m1 -oE 'MISMATCH: [^ ]+' "$log")
    echo "${w:-?}"
}

# name | sed expression | which stage should notice it first
run_slip() {
    local name=$1 expr=$2 predict=$3
    local copy="$work/mutant.rs" log="$work/log"

    n=$((n + 1))
    cp "$RS" "$copy"
    sed -i "$expr" "$copy"
    if cmp -s "$RS" "$copy"; then
        printf '%2d  %-38s *** SED MATCHED NOTHING -- the slip was never applied\n' \
            "$n" "$name"
        missed=$((missed + 1))
        return
    fi

    if INTERVAL_TREE_RS="$copy" "$here/run.sh" > "$log" 2>&1; then
        printf '%2d  %-38s NOT CAUGHT   (expected: %s)\n' "$n" "$name" "$predict"
        missed=$((missed + 1))
        return
    fi

    if grep -qE '^error(\[|:)|aborting due to' "$log"; then
        printf '%2d  %-38s COMPILE ERROR -- not a catch\n' "$n" "$name"
        compile=$((compile + 1))
        missed=$((missed + 1))
        return
    fi

    # What actually noticed, read back rather than assumed. Predicting it
    # first is hooks.md's "each sabotage should be caught at a DISTINCT
    # input and offset -- if many are caught in the same place, the harness
    # may be detecting one thing and attributing it to many."
    # A slip that
    # CRASHES the driver is reported as a crash, not as a comparison: a
    # segfault is a weaker signal than a reported mismatch, because it says
    # the tree was corrupt without saying the harness could see the
    # difference. Both count as caught; only one of them is evidence about
    # the comparison.
    printf '%2d  %-38s caught by %-40s (predicted %s)\n' \
        "$n" "$name" "$(verdict "$log")" "$predict"
    caught=$((caught + 1))
}

echo "sabotage suite for lib/interval_tree.c -- a smoke test on the harness,"
echo "NOT a stopping rule. See logs/floor.md RULE T2."
echo

# --- the augment callbacks: the part a query-only differential cannot see --
run_slip "augment: ignore the right child" \
    's|^        let right = (\*node).rb.rb_right;$|        let right: *mut RbNode = ptr::null_mut();|' \
    "invariant __subtree_last"
run_slip "augment: ignore the left child" \
    's|^        let left = (\*node).rb.rb_left;$|        let left: *mut RbNode = ptr::null_mut();|' \
    "invariant __subtree_last"
# Two SEPARATE slips, because the line appears twice: once in augment_copy()
# and once in augment_rotate(). The first version of this suite carried a
# dead leading expression and only ever mutated augment_copy's, leaving
# augment_rotate's copy untested by either half of the suite -- found by
# adversarial review, 2026-09-05.
run_slip "augment: copy() writes the wrong way" \
    '0,/(\*new).subtree_last = (\*old).subtree_last;/{s|(\*new).subtree_last = (\*old).subtree_last;|(*old).subtree_last = (*new).subtree_last;|}' \
    "invariant __subtree_last"
run_slip "augment: rotate() carries last, not subtree_last" \
    '/^unsafe extern "C" fn augment_rotate/,/^}/ s|(\*new).subtree_last = (\*old).subtree_last;|(*new).subtree_last = (*old).last;|' \
    "invariant __subtree_last"
run_slip "augment: rotate does not recompute old" \
    's|^        augment_compute_max(old, false);$|        let _ = old;|' \
    "invariant __subtree_last"
run_slip "augment: propagate stops one short" \
    's|^            if augment_compute_max(node, true) {$|            if true {|' \
    "invariant __subtree_last"

# --- insert -----------------------------------------------------------------
run_slip "insert: no subtree_last raise on descent" \
    's|^            if (\*parent).subtree_last < last {$|            if false {|' \
    "invariant __subtree_last"
run_slip "insert: ties go left" \
    's|^            if start < (\*parent).start {$|            if start <= (*parent).start {|' \
    "structure (tree shape)"
run_slip "insert: seeds subtree_last from start" \
    's|^        (\*node).subtree_last = last;$|        (*node).subtree_last = start;|' \
    "invariant __subtree_last"
run_slip "insert: forgets to clear leftmost" \
    's|^                leftmost = false;$|                leftmost = true;|' \
    "structure (rb_leftmost)"
run_slip "insert: never sets the leftmost cache" \
    's|^            (\*root).rb_leftmost = node;$|            let _ = node;|' \
    "structure (rb_leftmost)"

# --- erase ------------------------------------------------------------------
run_slip "erase: rebalance on the wrong colour" \
    's|rebalance = if pc_is_black(pc) { parent } else { ptr::null_mut() };|rebalance = if !pc_is_black(pc) { parent } else { ptr::null_mut() };|' \
    "invariant red-black"
run_slip "erase: child2 recoloured red" \
    's|rb_set_parent_color(child2, parent, 1 /\* RB_BLACK \*/);|rb_set_parent_color(child2, parent, 0);|' \
    "invariant red-black"
run_slip "erase: case 3 skips the propagate" \
    's|^                augment_propagate(parent, successor);$|                let _ = (parent, successor);|' \
    "invariant __subtree_last"
run_slip "erase: final propagate has no stop" \
    's|^        augment_propagate(tmp, ptr::null_mut());$|        let _ = tmp;|' \
    "invariant __subtree_last"
run_slip "erase: leftmost cache not advanced" \
    's|^        if (\*root).rb_leftmost == node {$|        if false {|' \
    "structure (rb_leftmost)"

# --- the searches -----------------------------------------------------------
run_slip "subtree_search: left bound is strict" \
    's|^                if start <= (\*left).subtree_last {$|                if start < (*left).subtree_last {|' \
    "query (match list)"
run_slip "subtree_search: Cond1 is strict" \
    's|^            if (\*node).start <= last {$|            if (*node).start < last {|' \
    "query (match list)"
run_slip "iter_first: fastpath rejects one too many" \
    's|^        if (\*node).subtree_last < start {$|        if (*node).subtree_last <= start {|' \
    "query (match list)"
run_slip "iter_first: leftmost test off by one" \
    's|^        if (\*leftmost).start > last {$|        if (*leftmost).start >= last {|' \
    "query (match list)"
run_slip "iter_next: right-subtree test is strict" \
    's|^                if start <= (\*right).subtree_last {$|                if start < (*right).subtree_last {|' \
    "query (match list)"
run_slip "iter_next: Cond1 off by one" \
    's|^            if last < (\*node).start {$|            if last <= (*node).start {|' \
    "query (match list)"

# --- the span iterator ------------------------------------------------------
run_slip "span: adjacency needs a two-gap" \
    's|n0_last + 1 == (\*cur).start|n0_last + 2 == (*cur).start|' \
    "span (coverage oracle)"
run_slip "span: gap keeps the first node, not the furthest" \
    's|^            if (\*cur).last > (\*(\*state).nodes\[0\]).last {$|            if false {|' \
    "span (nodes[0])"
run_slip "span: leading hole is one short" \
    's|^        if (\*(\*iter).nodes\[1\]).start > first_index {$|        if (*(*iter).nodes[1]).start >= first_index {|' \
    "span (coverage oracle)"
run_slip "span: trailing hole starts one late" \
    's|^            (\*iter).start.start_hole = (\*(\*iter).nodes\[0\]).last + 1;$|            (*iter).start.start_hole = (*(*iter).nodes[0]).last + 2;|' \
    "span (coverage oracle)"
run_slip "advance: past-the-end test is off by one" \
    's|^        if new_index > (\*iter).last_index {$|        if new_index >= (*iter).last_index {|' \
    "advance"
run_slip "advance: the ULONG_MAX wrap is + 2" \
    's|(\*iter).last.last_hole.wrapping_add(1)|(*iter).last.last_hole.wrapping_add(2)|' \
    "advance"

# ---------------------------------------------------------------------------
# --both: the same slip in BOTH arms. Only the independent checks can fire.
# ---------------------------------------------------------------------------
run_both() {
    local name=$1 rsexpr=$2 cexpr=$3 target=$4 expect=$5
    local rscopy="$work/mutant.rs" log="$work/log"
    local cdir="$work/c" inc="$work/inc"

    n=$((n + 1))
    rm -rf "$cdir" "$inc"; mkdir -p "$cdir"
    cp -r "$root/port/pristine/include" "$inc"
    cp "$root/port/pristine/lib/interval_tree.c" "$cdir/interval_tree.c"
    cp "$RS" "$rscopy"

    local cfile
    case $target in
    c)       cfile="$cdir/interval_tree.c" ;;
    generic) cfile="$inc/linux/interval_tree_generic.h" ;;
    augment) cfile="$inc/linux/rbtree_augmented.h" ;;
    esac
    local corig="$work/corig"
    cp "$cfile" "$corig"

    sed -i "$rsexpr" "$rscopy"
    sed -i "$cexpr" "$cfile"

    if cmp -s "$RS" "$rscopy"; then
        printf '%2d  %-38s *** RUST SED MATCHED NOTHING -- not applied\n' "$n" "$name"
        missed=$((missed + 1)); return
    fi
    if cmp -s "$corig" "$cfile"; then
        printf '%2d  %-38s *** C SED MATCHED NOTHING -- the arms are NOT both wrong\n' \
            "$n" "$name"
        missed=$((missed + 1)); return
    fi

    if INTERVAL_TREE_RS="$rscopy" INTERVAL_TREE_C="$cdir/interval_tree.c" \
       INTERVAL_TREE_INC="$inc" "$here/run.sh" > "$log" 2>&1; then
        printf '%2d  %-38s NOT CAUGHT   (only %s could have)\n' \
            "$n" "$name" "$expect"
        missed=$((missed + 1)); return
    fi
    if grep -qE '^error(\[|:)|aborting due to' "$log"; then
        printf '%2d  %-38s COMPILE ERROR -- not a catch\n' "$n" "$name"
        compile=$((compile + 1)); missed=$((missed + 1)); return
    fi

    printf '%2d  %-38s caught by %-40s (%s)\n' \
        "$n" "$name" "$(verdict "$log")" "$expect"
    caught=$((caught + 1))
}

if [ "$both" = 1 ]; then
    echo
    echo "--both: the SAME slip in the C and the Rust. The arms now agree, so"
    echo "only an independently-derived check can see anything."
    echo

    run_both "both: augment ignores the right child" \
        's|^        let right = (\*node).rb.rb_right;$|        let right: *mut RbNode = ptr::null_mut();|' \
        's|^	if (node->RBFIELD.rb_right) {					      \\$|	if (0) {							      \\|' \
        augment "the __subtree_last invariant checker"

    run_both "both: subtree_search Cond1 is strict" \
        's|^            if (\*node).start <= last {$|            if (*node).start < last {|' \
        's|if (ITSTART(node) <= last) {		/\* Cond1 \*/	      \\|if (ITSTART(node) < last) {		/* Cond1 */	      \\|' \
        generic "the in-order match oracle"

    run_both "both: span adjacency needs a two-gap" \
        's|n0_last + 1 == (\*cur).start|n0_last + 2 == (*cur).start|' \
        's|state->nodes\[0\]->last + 1 == cur->start));|state->nodes[0]->last + 2 == cur->start));|' \
        c "the coverage-bitmap span oracle"
fi

echo
echo "slips $n   caught $caught   missed $missed   (of the missed, $compile were compile errors)"
[ "$missed" -eq 0 ]
