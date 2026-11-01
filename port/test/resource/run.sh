#!/usr/bin/env bash
# port/test/resource/run.sh -- kernel/resource.c: the pristine tree algorithms vs resource_rs.rs + the glue wrappers; random request / insert / release / adjust / find / region / space / reallocate streams over a 40-node pool (4 shards).   run.sh [--sabotage]
# Mutants not caught, all equivalent or unreachable (89 of 96 caught; the other 7): next_skip -- next_resource() is only called with skip_children set for nodes whose whole subtree
# the caller's `continue` would skip anyway; next_root_stop -- the walk past the subtree root only reaches the root's later siblings, which sit after every address the caller's
# break test (d.start > o_start) accepts, so it ends the loop the same way; cl_min / cl_max -- clipping at equality writes the same value; ra_contains_old -- shrinking in place
# and release + request leave the same tree when the old resource has no children; rl_einval -- a node not in its parent's list (-EINVAL) cannot occur in a consistent tree;
# ra_bug -- the request after a successful search cannot conflict.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/resource"
out="${TMPDIR:-/tmp}/rstest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${RS_RS:-$root/port/tree/kernel/resource_rs.rs}"; C="$root/port/pristine/kernel/resource.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-unused-label -Wno-incompatible-pointer-types -Wno-gnu-statement-expr -Wno-implicit-function-declaration -I $here -I $out"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name resource_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    RS_PROVE=1 RS_N=300 "$out/rs/t" 0 > "$out/p.out"; RS_N=300 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | grep -c "^[0-9]")"; echo PASS; exit
fi
runone "$out/ref/t" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" "-A dead_code -A unused" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; grep -m3 -E "error|Error|cannot|undefined" "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n"; rm -f "$out"/m$n.?*
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
