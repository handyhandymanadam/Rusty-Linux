#!/usr/bin/env bash
# port/test/idr/run.sh -- lib/idr.c (IDA half): pristine C vs idr_glue.c's wrappers over idr_rs.rs, both on the pristine lib/xarray.c; random alloc / find / free / destroy
# with boundary ranges, negative arguments, GFP_NOWAIT and injected allocation failures, the whole array printed after every op.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/idr"
out="${TMPDIR:-/tmp}/idtest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${IDA_RS:-$root/port/tree/lib/idr_rs.rs}"; G="$root/port/tree/lib/idr_glue.c"; P="$root/port/pristine/lib/idr.c"
for f in "$RS" "$P" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the IDA half of the pristine file (from the DOC comment to the userspace-only tail), and the wrapper + thunk text of the glue
s=$(($(grep -n 'DOC: IDA description' "$P" | cut -d: -f1) - 1)); e=$(($(grep -n '^#ifndef __KERNEL__' "$P" | cut -d: -f1) - 1))
sed -n "${s},${e}p" "$P" > "$out/ida_ref.c"
{ sed -n '/^static_assert(sizeof(struct xa_state)/,/^void rust_ida_warn_not_allocated(unsigned int id) {/p' "$G"
  for f in ida_alloc_range ida_find_first_range ida_free ida_destroy; do sed -n "/^[a-z].* $f(/,/^}/p" "$G"; done; } > "$out/ida_rs.c"
[ "$(grep -c rust_ida_ "$out/ida_rs.c")" -gt 20 ] || { echo "glue extraction failed"; exit 2; }
SH="-I $here -I $here/shim -I $root/port/test/xarray/shim -I $root/port/test/common/shim -I $root/src/linux/include"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-sign-compare -Wno-pointer-sign $SH"
cc $CF -c -o "$out/xarray.o" "$here/xarray_plain.c"; cc $CF -c -o "$out/rts.o" "$here/radix_tree_stub.c"; cc $CF -c -o "$out/rhs.o" "$root/port/test/xarray/rust_helpers_stub.c"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRC=\"$out/ida_ref.c\"" -o "$1/t" "$here/main.c" "$out"/xarray.o "$out"/rts.o "$out"/rhs.o; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name idr_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$out/ida_rs.c\"" -o "$2/t" "$here/main.c" "$out"/xarray.o "$out"/rts.o "$out"/rhs.o "$2/librs.a"; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 120 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    IDA_PROVE=1 IDA_N=50 "$out/rs/t" 0 > "$out/p.out"; IDA_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(grep -hc ' -> \| free \| destroy' "$out"/ref.? | paste -sd+ | bc)"; echo PASS; exit
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
    rm -rf "$out/m$n"
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# EQUIVALENT / not reachable (kept in mutants.txt so they stay visible; the run reports them NOT CAUGHT):
#  err_cmp: `>` for `>=` in the xa_err() range test differs only for the errno -MAX_ERRNO-1 .. exactly XA_ERROR(-4095) which xarray never stores.
#  nomem_retry: not resetting xa_index after xas_nomem(): the failed store happened at a chunk above min's only when every lower chunk is full, and bit is reset to 0 by the
#    `xa_index > min/BITS` test, so the retry lands on the same chunk.
#  nospc_free: not freeing `alloc` on the no-space exit: single-threaded, the retry after a blocking allocation sees the state it saw before, so it never ends in no-space.
#  ff_size: 64 for 63 bits of a value entry: bit 63 of a value entry is never set.   free_vbit: `>` for `>=`: bit 63 is never set in a value entry, so the test below it fails the same way.
#  err_clear: resetting bitmap[0] to 1 instead of 0 after a failed xas_store of a fresh bitmap only shows when that same bitmap is reused by the retry (alloc != NULL) AND the node
#    allocation fails inside one op: seen 0 times in 4 x 6000 ops (not proven unreachable).
#  gfp passed to the blocking kzalloc is not observable here (the userspace kzalloc ignores it); the kernel build is where it counts, and the libtest exercises GFP_KERNEL.
