#!/usr/bin/env bash
# port/test/user_namespace/run.sh -- kernel/user_namespace.c: the pristine id-map slice (lookups, mappings_overlap, insert_extent, sort_idmaps, the parse / remap phases of map_write) vs
# user_namespace_rs.rs; random /proc/PID/*_map texts, parent translation, sort, 400 lookups per map, allocation failures (4 shards).   run.sh [--sabotage]
# Mutants not caught, all equivalent (65 of 75 caught; the other 10): cmp_neg_and / cmp_neg_idonly -- a range that wraps or straddles the start of an element cannot lie inside any extent, so
# the direction of the search never changes the (empty) answer; parse_sp1 / sp2 / sp3 -- each isspace() check after a number is repeated by the next check (the same character is looked at
# again: the next number parses to 0, or the trailing-junk test fires); parse_max_first_only / max_lower_only -- id -1 with any count wraps, so the wrap checks already refuse it;
# parse_wrap_first / wrap_lower -- `<=` differs from `<` only for count 0, which the other field's check refuses; parse_empty_ok -- the loop always runs once and each pass either
# returns or inserts, so nr_extents == 0 after it is unreachable.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/user_namespace"
out="${TMPDIR:-/tmp}/untest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${UN_RS:-$root/port/tree/kernel/user_namespace_rs.rs}"; C="$root/port/pristine/kernel/user_namespace.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-unused-label -I $here -I $out"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name user_namespace_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    UN_PROVE=1 UN_N=50 "$out/rs/t" 0 > "$out/p.out"; UN_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | grep -c ' parse=')"; echo PASS; exit
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
