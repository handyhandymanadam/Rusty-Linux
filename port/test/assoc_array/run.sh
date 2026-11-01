#!/usr/bin/env bash
# port/test/assoc_array/run.sh -- lib/assoc_array.c: pristine C vs assoc_array_rs.rs, random operation sequences, transcripts compared.
#   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/assoc_array"
out="${TMPDIR:-/tmp}/assoctest.$$"; mkdir -p "$out/shim/linux"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${AA_RS:-$root/port/tree/lib/assoc_array_rs.rs}"
G="${AA_GLUE:-$root/port/tree/lib/assoc_array_glue.c}"
C="${AA_C:-$root/port/pristine/lib/assoc_array.c}"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
cp -r "$here/shim/." "$out/shim/"
for h in assoc_array assoc_array_priv; do
    { echo '#include "kshim.h"'; sed '/^#include/d' "$root/src/linux/include/linux/$h.h"; } > "$out/shim/linux/$h.h"
done
sed -i 's/^#ifdef CONFIG_ASSOCIATIVE_ARRAY/#if 1/' "$out/shim/linux/assoc_array_priv.h" "$out/shim/linux/assoc_array.h"
sed -i '1a #include <linux/assoc_array.h>' "$out/shim/linux/assoc_array_priv.h"
REN=""; for fn in iterate find destroy insert insert_set_object delete clear apply_edit cancel_edit gc; do REN="$REN -Dassoc_array_$fn=c_assoc_array_$fn"; done
CF="-O2 -w -I $out/shim"
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name assoc_array_rs -o "$2/librs.a" "$1"
    cc $CF $REN -c -o "$2/ref.o" "$C"
    cc $CF -c -o "$2/glue.o" "$G"
    cc -O2 -Wall -Wno-unused-parameter -I "$out/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if AA_PROVE_CAN_FAIL=1 AA_N=10 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    # Dropped as (I think) EQUIVALENT: gc's `retained && nr_leaves_on_branch <= FAN_OUT` -> `<`: with exactly FAN_OUT leaves a retained
    # child (more leaves than free slots + 1) contradicts the slot arithmetic of the node; 1500 cases x 31 mutants never reached it.
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE"; head -8 "$out/build.log"; exit 1; }
        if AA_N=1500 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
walk-slot-mask~(segments >> (level & KEY_CHUNK_MASK)) & FAN_MASK;~(segments >> (level & KEY_CHUNK_MASK)) & 7;
shortcut-trim~dissimilarity &= !(c_ulong::MAX << shift);~dissimilarity &= !(c_ulong::MAX << (shift + 1));
next-sc-level~next_sc_level = round_down_chunk(sc_level + KEY_CHUNK_SIZE);~next_sc_level = sc_level + KEY_CHUNK_SIZE;
jump-test~if ((level ^ sc_level) & !KEY_CHUNK_MASK) != 0 {~if ((level ^ sc_level) & !KEY_CHUNK_MASK) == 0 {
iterate-null-leaf~if !ptr.is_null() && is_leaf(ptr) {~if is_leaf(ptr) {
dead-leaf~(*edit).dead_leaf = (*node).slots[i];~(*edit).dead_leaf = null_mut();
free-slot~free_slot = i as c_int;~free_slot = 0;
dissimilarity-xor~dissimilarity |= (*edit).segment_cache[i] as c_ulong ^ base_seg;~dissimilarity |= (*edit).segment_cache[i] as c_ulong;
cluster-check~if ((*edit).segment_cache[FAN_OUT] as c_ulong ^ base_seg) == 0 {~if ((*edit).segment_cache[FAN_OUT] as c_ulong ^ base_seg) != 0 {
keylen-roundup~let mut keylen = round_up_chunk(diff) as usize;~let mut keylen = round_up_chunk(diff + 1) as usize;
blank-shift~let blank = c_ulong::MAX << (level & KEY_CHUNK_MASK);~let blank = c_ulong::MAX << ((level & KEY_CHUNK_MASK) + 1);
mid-diff~let mut diff: c_int = dissimilarity.trailing_zeros() as c_int;~let mut diff: c_int = dissimilarity.trailing_zeros() as c_int + 1;
pre-shortcut~if diff > level {~if diff >= level {
sc-slot-shift~let sc_slot = ((sc_segments >> (diff & KEY_CHUNK_MASK)) & FAN_MASK) as usize;~let sc_slot = ((sc_segments >> ((diff & KEY_CHUNK_MASK) + 1)) & FAN_MASK) as usize;
post-shortcut~if level < (*shortcut).skip_to_level {~if level <= (*shortcut).skip_to_level {
leaf-p-choice~if sc_slot == 0 {~if sc_slot == 1 {
collapse-threshold~if (*node).nr_leaves_on_branch <= FAN_OUT as c_ulong + 1 {~if (*node).nr_leaves_on_branch <= FAN_OUT as c_ulong {
grandparent-threshold~if (*grandparent).nr_leaves_on_branch <= FAN_OUT as c_ulong + 1 {~if (*grandparent).nr_leaves_on_branch < FAN_OUT as c_ulong + 1 {
collapse-cond~if has_meta || parent != node {~if has_meta && parent != node {
last-leaf~if (*array).nr_leaves_on_tree == 1 {~if (*array).nr_leaves_on_tree == 2 {
adjust-count~(*node).nr_leaves_on_branch = (*node).nr_leaves_on_branch.wrapping_add((*edit).adjust_count_by as c_ulong);~(*node).nr_leaves_on_branch = (*node).nr_leaves_on_branch.wrapping_add(1);
gc-fold~if (*child).nr_leaves_on_branch <= (nr_free + 1) as c_ulong {~if (*child).nr_leaves_on_branch <= nr_free as c_ulong {
gc-excise~if nr_free == FAN_OUT as c_int - 1 {~if nr_free == FAN_OUT as c_int - 2 {
gc-excise-shortcut~if (*new_n).nr_leaves_on_branch <= FAN_OUT as c_ulong {<NL>                            (*new_n).back_pointer = new_parent;~if (*new_n).nr_leaves_on_branch < FAN_OUT as c_ulong {<NL>                            (*new_n).back_pointer = new_parent;
destroy-free~if !ops.is_null() {~if ops.is_null() {
cleanup-meta~rust_assoc_array_kfree(to_node((*edit).excised_meta[i]).cast());~let _ = i;
cancel-shortcut~rust_assoc_array_kfree(to_shortcut(ptr).cast());~let _ = ptr;
empty-leaf-p~(*edit).leaf_p = &raw mut (*new_n0).slots[0];<NL>        (*edit).adjust_count_on = new_n0;<NL>        (*edit).set[0].ptr~(*edit).leaf_p = &raw mut (*new_n0).slots[1];<NL>        (*edit).adjust_count_on = new_n0;<NL>        (*edit).set[0].ptr
iterate-meta~if has_meta & PTR_META_TYPE == 0 {~if has_meta & PTR_META_TYPE != 0 {
find-compare~if ((*ops).compare_object)(leaf, index_key_) {~if !((*ops).compare_object)(leaf, index_key_) {
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo PASS
