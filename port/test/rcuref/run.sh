#!/usr/bin/env bash
# port/test/rcuref/run.sh -- lib/rcuref.c: pristine C vs rcuref_glue.c over rcuref_rs.rs, get / put sequences over hostile counter values with races
# injected between a put's decrement and its slow path.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/rcuref"
out="${TMPDIR:-/tmp}/rcutest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${RCU_RS:-$root/port/tree/lib/rcuref_rs.rs}"; G="$root/port/tree/lib/rcuref_glue.c"; C="$root/port/pristine/lib/rcuref.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
CF="-O1 -Wall -Wno-unused-parameter -I $here/shim"
buildref() { mkdir -p "$1"; cc $CF -w -c -o "$1/ref.o" "$C"; cc $CF -c -o "$1/main.o" "$here/main.c"; cc -o "$1/t" "$1/main.o" "$1/ref.o"; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name rcuref_rs -o "$2/librs.a" "$1"
    cc $CF -w -c -o "$2/glue.o" "$G"; cc $CF -DARM_RS -c -o "$2/main.o" "$here/main.c"; cc -o "$2/t" "$2/main.o" "$2/glue.o" "$2/librs.a"; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; timeout 300 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    RCU_PROVE=1 RCU_N=50 "$out/rs/t" 0 > "$out/p.out"; RCU_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; exit 1; }
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
# Dropped as EQUIVALENT: get_warn and put_sat (">" vs ">=" MAXREF: the slow paths are only entered with a negative counter, so cnt == RCUREF_MAXREF cannot reach them).
