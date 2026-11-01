#!/usr/bin/env bash
# port/test/sbitmap/run.sh -- lib/sbitmap.c: pristine C vs sbitmap_glue.c over sbitmap_rs.rs; random get/put/resize/shallow/batch/clear/wake-up/wait-queue ops on a bitmap and a
# queue of random depth, shift and round-robin setting, with allocation failure in init and 4 "CPUs".   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/sbitmap"
out="${TMPDIR:-/tmp}/sbtest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${SB_RS:-$root/port/tree/lib/sbitmap_rs.rs}"; G="$root/port/tree/lib/sbitmap_glue.c"; C="$root/port/pristine/lib/sbitmap.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
CF="-O1 -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -I $here/shim"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRC=\"$C\"" -o "$1/t" "$here/main.c"; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name sbitmap_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$G\"" -o "$2/t" "$here/main.c" "$2/librs.a"; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 60 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    SB_PROVE=1 SB_N=50 "$out/rs/t" 0 > "$out/p.out"; SB_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.?  | wc -l)"; echo PASS; exit
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
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Dropped as EQUIVALENT:
#  dc_depth0 (depth == 0 reaches sbitmap_deferred_clear() only from sbitmap_resize() and the batch allocator, which ignore its result; find_bit_in_word() passes depth >= 1),
#  dc_hintmask (the mask only matters after get_word() found no free bit at or above the hint, so every bit it covers is set either way),
#  word_wrap (get_word()'s later "hint != 0 && wrap" test repeats the entry test: when the entry hint is 0 the inner hint is 0 as well).
# Not mutated (single-threaded, unobservable): the memory orderings (Acquire on test_and_set_bit_lock, SeqCst on the cmpxchg loops, Relaxed on the andnots) and the
# lost-race retry paths; the concurrency bar covers them.
