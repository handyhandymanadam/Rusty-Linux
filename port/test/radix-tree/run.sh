#!/usr/bin/env bash
# port/test/radix-tree/run.sh -- lib/radix-tree.c: pristine C vs radix-tree_glue.c over radix_tree_rs.rs, with the IDR half of pristine lib/idr.c on top of each; random operations on two
# radix trees and an IDR, with the raw tree structure printed after every op.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/radix-tree"
out="${TMPDIR:-/tmp}/rttest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${RT_RS:-$root/port/tree/lib/radix_tree_rs.rs}"; G="$root/port/tree/lib/radix-tree_glue.c"; C="$root/port/pristine/lib/radix-tree.c"; P="$root/port/pristine/lib/idr.c"
for f in "$RS" "$C" "$G" "$P"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the IDR half of the pristine idr.c: everything before the IDA description
e=$(($(grep -n 'DOC: IDA description' "$P" | cut -d: -f1) - 2)); sed -n "1,${e}p" "$P" > "$out/idr_half.c"
SH="-I $here/shim -I $root/port/test/xarray/shim -I $root/port/test/common/shim -I $root/src/linux/include -I $root/src/linux/arch/x86/include"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-sign-compare -Wno-pointer-sign -Wno-address-of-packed-member $SH"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRC=\"$C\"" "-DIDRSRC=\"$out/idr_half.c\"" -o "$1/t" "$here/main.c" "$here/rust_stub.c"; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on --cfg radix_harness_small_chunk_off -D unsafe_op_in_unsafe_fn -D warnings --crate-name radix_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$G\"" "-DIDRSRC=\"$out/idr_half.c\"" -o "$2/t" "$here/main.c" "$here/rust_stub.c" "$2/librs.a"; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 600000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    RT_PROVE=1 RT_N=50 "$out/rs/t" 0 > "$out/p.out"; RT_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | grep -c '^[0-9]')"; echo PASS; exit
fi
runone "$out/ref/t" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; head -6 "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n" "$out"/m$n.?  "$out"/m$n.?.err "$out"/m$n.?.rc
done < "${MUTANTS:-$here/mutants.txt}"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# EQUIVALENT or not reachable single-threaded (kept in mutants.txt so they stay visible; the run reports them NOT CAUGHT):
#  retry_const, shrink_retry, shrink_count0, chunk_retry, gang_retry: the RETRY entry and the zeroed count of a dropped node only matter to a reader still inside it -- the concurrency bar (libstress "radix_tree").
#  is_node_4096: no node pointer is 4096.   free_shift: a leaf slot never holds a node pointer.   shrink_count: a head node with count 0 would already have been deleted.
#  itertags_single / chunk_single_next: for the single-slot tree the next step ends the chunk either way (tags 1 shifted is 0; next_index 0 or 1 both stop).
#  chunk_tag_next: the bit at `offset` is clear at that point, so searching from offset or offset+1 finds the same bit.   getfree_next: same.
#  nextslot_contig: radix_tree_next_slot() with the CONTIG flag is only run by header inlines in callers, never by this file's Rust.
#  getfree_start (`|| start == 0`): needs next_index to wrap past ULONG_MAX, unreachable from a u32 start.   getfree_nexti / getfree_single: iter->next_index after idr_get_free() is read by no caller.
#  delete_tags: root_tag_clear_all() in delete_node is redundant, the tag deletes already cleared the root's tags.
#  replace_delete: replacing with NULL through the replace API leaves the entry's tags behind (misuse the kernel BUGs on later), so delete_node() after a replace only ever sees a node it cannot free.
#  extend_early (`entry.is_null()` without the IDR conditions): differs only for an empty IDR that lacks its IDR_FREE root tag, a state idr_destroy()/delete_node() never leave.
#  delete_shrink: the "tree shrank" result of delete_node() only sets iter->index = next_index in radix_tree_iter_delete(); without it the iteration steps through the dropped node's slots, which are all empty after the delete, and reaches the same next chunk.
