#!/usr/bin/env bash
# port/test/timer/run.sh -- kernel/time/timer.c: the pristine wheel-index and jiffies-rounding functions vs timer_rs.rs + the glue wrappers; HZ is compiled in as in the kernel, so there is one binary per
# HZ (100, 250, 300, 1000) and side, one shard each.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/timer"
out="${TMPDIR:-/tmp}/twtest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${TW_RS:-$root/port/tree/kernel/time/timer_rs.rs}"; C="$root/port/pristine/kernel/time/timer.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" "$C" "$out/glue.c"
python3 "$here/extract.py" "$C" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -I $here"
HZS="100 250 300 1000"
buildref() { mkdir -p "$1"; local hz; for hz in $HZS; do cc $CF -DHZ=$hz "-DSRCFILE=\"$out/ref.c\"" -o "$1/t.$hz" "$here/main.c"; done; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name timer_rs -o "$2/librs.a" "$1"
    local hz; for hz in $HZS; do cc $CF -DHZ=$hz "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t.$hz" "$here/main.c" "$2/librs.a" -lpthread; done; }
runone() { local d=$1 tag=$2 s=0 hz; for hz in $HZS; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$d/t.$hz" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & s=$((s+1)); done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    TW_PROVE=1 TW_N=60 "$out/rs/t.1000" 0 > "$out/p.out"; TW_N=60 "$out/ref/t.1000" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref" ref; runone "$out/rs" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | grep -c '^[0-9]')"; echo PASS; exit
fi
runone "$out/ref" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" "-A dead_code -A unused" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; grep -m3 -E "error|Error|cannot|undefined" "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n"; rm -f "$out"/m$n.?*
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Equivalent mutants left out of mutants.txt (34 are listed, all caught): dropping `lvl_depth > 8` (for depth 8 a non-negative delta below LVL_START(8) reaches calc_index(expires, 7) through the
# last branch anyway: no cut-off applies); `delta <= 0` for the past-expiry test (delta 0 is taken by the first level's test).
