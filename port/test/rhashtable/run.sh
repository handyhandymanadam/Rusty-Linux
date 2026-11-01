#!/usr/bin/env bash
# port/test/rhashtable/run.sh -- lib/rhashtable.c: pristine C vs rhashtable_glue.c over rhashtable_rs.rs. The same main.c is linked against each;
# it prints one digest per case (everything observable folded in) and the two outputs must be identical.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/rhashtable"
out="${TMPDIR:-/tmp}/rhttest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${RHT_RS:-$root/port/tree/lib/rhashtable_rs.rs}"
G="$root/port/tree/lib/rhashtable_glue.c"; C="$root/port/pristine/lib/rhashtable.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
CF="-O1 -g -fno-strict-aliasing -I $here/shim"
buildref() {
    mkdir -p "$1"
    cc $CF -w -c -o "$1/ref.o" "$C"
    cc $CF -Wall -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable -c -o "$1/main.o" "$here/main.c"
    cc -o "$1/t" "$1/main.o" "$1/ref.o" -lpthread
}
buildrs() {    # buildrs <rs> <dir>
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name rhashtable_rs -o "$2/librs.a" "$1"
    cc $CF -w -c -o "$2/glue.o" "$G"
    cc $CF -Wall -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable -DARM_RS -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/glue.o" "$2/librs.a" -lpthread
}
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; timeout 300 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() {    # compare <reftag> <rstag>  -> 0 when all four shards are identical
    local s rc=0
    for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs: $(diff "$out/$1.$s" "$out/$2.$s" | head -3 | tr '\n' ' ')"; }; done
    return $rc
}
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    RHT_PROVE=1 RHT_N=20 "$out/rs/t" 0 > "$out/p.out" 2>/dev/null || true; RHT_N=20 "$out/ref/t" 0 > "$out/p.ref" 2>/dev/null || true
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"
    runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc | grep -qx 0 && ! cat "$out"/rs.?.rc | grep -qv '^0$' || { echo "  a Rust shard exited non-zero"; exit 1; }
    ncases=$(cat "$out"/ref.? | wc -l); nerr=$(cat "$out"/*.err | grep -c . || true)
    echo "cases compared: $ncases, stderr lines (BUG/LEAK/BAD FREE): $nerr"
    [ "$nerr" -eq 0 ]
    echo PASS
    exit
fi
runone "$out/ref/t" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    [ -z "${RHT_ONLY:-}" ] || [[ "$name" =~ $RHT_ONLY ]] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; head -8 "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    # caught = different digests, or a crash / BAD FREE / LEAK / BUG line on stderr
    if compare ref "m$n" >/dev/null 2>&1 && [ "$(cat "$out"/m$n.?.err | grep -c . || true)" -eq 0 ] && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
done < "$here/mutants.txt"
# Dropped as EQUIVALENT: init_maxsize_cmp (equal only at max_size 2^30, where both give max_elems 2^31), nins_leaf (leaf only stores NULL into a zeroed page), s30_min (at min_size the shrink returns 0 either way), nulls_marker (differs only for non-canonical addresses), try_sched75 (the extra schedule only fires when the table is above 75% and not inserted; the worker that grows it was already scheduled, or the cap/allocation failure keeps it pending anyway), shrink_cmp (`<=` vs `<` in rhashtable_shrink only changes which nonzero error code the worker gets, and every nonzero code reschedules the work), rone_assign_locked (when it runs, next is the nulls marker, which rht_assign_locked turns into NULL anyway), rtable_cond_resched (scheduling only), shrink_min (the equal case assigns the same value), nalloc_leaf and alloc_nulls_loop (INIT_RHT_NULLS_HEAD is a store of NULL into memory that kmalloc/kvmalloc already zeroed with __GFP_ZERO).
# Not reachable single-threaded (the libstress target covers them): the cmpxchg-lost races in nested_table_alloc() and rhashtable_rehash_attach(), and
# the release/acquire orderings (st_release / fence), which are equivalent on one thread.
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
