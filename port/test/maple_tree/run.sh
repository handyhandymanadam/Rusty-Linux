#!/usr/bin/env bash
# port/test/maple_tree/run.sh -- lib/maple_tree.c: pristine C vs maple_tree_rs.rs behind maple_tree_glue.c, random operation sequences,
# transcripts (return values, tracepoints, allocation sizes, structural dump of every tree) compared.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/maple_tree"
out="${TMPDIR:-/tmp}/mapletest.$$"; mkdir -p "$out/shim"; [ -n "${MT_KEEP:-}" ] || trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${MT_RS:-$root/port/tree/lib/maple_tree_rs.rs}"
G="${MT_GLUE:-$root/port/tree/lib/maple_tree_glue.c}"
C="${MT_C:-$root/port/pristine/lib/maple_tree.c}"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
cp -r "$here/shim/." "$out/shim/"
{ echo '#include "kshim.h"'; sed '/^#include/d' "$root/src/linux/include/linux/maple_tree.h"; } > "$out/shim/linux/maple_tree.h"
REN=""; for fn in mas_walk mas_empty_area mas_empty_area_rev mas_store mas_store_gfp mas_store_prealloc mas_preallocate mas_destroy mas_next \
  mas_next_range mt_next mas_prev mas_prev_range mt_prev mas_pause mas_find mas_find_range mas_find_rev mas_find_range_rev mas_erase mas_nomem \
  mtree_load mtree_store_range mtree_store mtree_insert_range mtree_insert mtree_alloc_range mtree_alloc_rrange mtree_alloc_cyclic \
  mas_alloc_cyclic mtree_erase __mt_dup mtree_dup __mt_destroy mtree_destroy mt_find mt_find_after maple_tree_init; do REN="$REN -D$fn=c_$fn"; done
CF="${MT_CFLAGS:--O2} -w -I $out/shim"
build() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -g -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn --crate-name maple_tree_rs -o "$2/librs.a" "$1"
    # reference C with the one upstream memory-corruption bug removed (see logs/hooks.md, maple_tree): mt_clear_meta() zeroes a dead full node's last child pointer
    python3 - "$C" "$2/ref.c" <<'PY'
import sys
s = open(sys.argv[1]).read()
old = "\t\t\tif (unlikely((mte_to_node(next) &&\n\t\t\t\t      mte_node_type(next))))\n\t\t\t\treturn; /* no metadata, could be node */"
assert old in s
open(sys.argv[2], "w").write(s.replace(old, "\t\t\treturn;"))
PY
    cc $CF $REN -c -o "$2/ref.o" "$2/ref.c"
    cc $CF -c -o "$2/glue.o" "$G"
    cc -O2 -Wall -Wno-unused-parameter -Wno-unused-variable -I "$out/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do timeout "${MT_TIMEOUT:-1500}" "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if MT_PROVE_CAN_FAIL=1 MT_N=10 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE"; head -8 "$out/build.log"; exit 1; }
        if MT_N=${MT_MUT_N:-150} MT_TIMEOUT=240 runall "$out/m$n/t" >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
sweep35~    xa_is_internal(entry) && (entry as usize) <= XA_RETRY_ENTRY~    xa_is_internal(entry) || (entry as usize) <= XA_RETRY_ENTRY
sweep53~            return ma_meta_end(node, type_);<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 1;<NL>        if *pivots.add(offset as usize) == 0 {~            return ma_meta_end(node, type_);<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 1;<NL>        if *pivots.add(offset as usize) != 0 {
sweep24~        if *bpiv((*mast).bn, (*(*mast).bn).b_end as usize - 1) >= (*(*mast).orig_r).max {~        if *bpiv((*mast).bn, (*(*mast).bn).b_end as usize - 2) >= (*(*mast).orig_r).max {
sweep25~            if !(i <= mab_end as c_int && *bpiv(b_node, i as usize) != 0) {~            if !(i <= mab_end as c_int || *bpiv(b_node, i as usize) != 0) {
sweep19~            return 0;<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 1;<NL>        if *pivots.add(offset as usize) == 0 {~            return 0;<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 1;<NL>        if *pivots.add(offset as usize) != 0 {
sweep20~            if *pivots >= (*mas).index {~            if *pivots > (*mas).index {
sweep26~            if node.is_null() || type_ == 0 {~            if node.is_null() || type_ != 0 {
sweep40~            while i < piv_end {~            while i <= piv_end {
sweep67~        let end = (j - 1) as u8;<NL>        if !ma_is_leaf(mt) && mt_is_alloc((*mas).tree) {~        let end = (j - 1) as u8;<NL>        if !ma_is_leaf(mt) || mt_is_alloc((*mas).tree) {
sweep62~            (*mas).min = (*pivots.add((*mas).offset as usize - 1)).wrapping_add(1);~            (*mas).min = (*pivots.add((*mas).offset as usize - 0)).wrapping_add(1);
sweep65~            if piv.wrapping_add(1) < (*mas).index {~            if piv.wrapping_add(1) <= (*mas).index {
sweep45~                if !empty {<NL>                    if (*mas).last >= max {~                if !empty {<NL>                    if (*mas).last > max {
sweep17~                if offset_end != slot {~                if offset_end == slot {
sweep1~        /* !mas->offset implies that parent node min == mas->min. mas->offset > 0 implies that we need to walk up to find the implied pivot min. */<NL>        if (*mas).offset == 0 {~        /* !mas->offset implies that parent node min == mas->min. mas->offset > 0 implies that we need to walk up to find the implied pivot min. */<NL>        if (*mas).offset != 0 {
sweep69~        bug_on(p_type == maple_leaf_64);~        bug_on(p_type != maple_leaf_64);
sweep32~                min = (*pivots.add(offset as usize - 1)).wrapping_add(1);~                min = (*pivots.add(offset as usize - 0)).wrapping_add(1);
sweep21~        if (*mas).last != ULONG_MAX {~        if (*mas).last == ULONG_MAX {
sweep61~            if (*mas).index > max || size.wrapping_sub(1) > max.wrapping_sub((*mas).index) {~            if (*mas).index > max && size.wrapping_sub(1) > max.wrapping_sub((*mas).index) {
sweep37~            i = i.wrapping_sub(1);<NL>            if was == 0 {~            i = i.wrapping_sub(1);<NL>            if was != 0 {
sweep46~                    if mas_prev_node(mas, min) != 0 {~                    if mas_prev_node(mas, min) == 0 {
sweep60~            return ma_meta_end(node, type_);<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 1;~            return ma_meta_end(node, type_);<NL>        }<NL><NL>        let offset = mt_pivots[type_ as usize] - 0;
sweep30~                if !wr_mas.content.is_null() || (*mas).last > wr_mas.r_max {~                if !wr_mas.content.is_null() && (*mas).last > wr_mas.r_max {
sweep5~            && (*r_mas).last < (*r_mas).max~            && (*r_mas).last <= (*r_mas).max
sweep49~            rcu_assign(slots.add(end as usize + 1), (*wr_mas).entry);~            rcu_assign(slots.add(end as usize + 2), (*wr_mas).entry);
sweep28~            if !entry.is_null() || last == ULONG_MAX {~            if !entry.is_null() && last == ULONG_MAX {
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo PASS
