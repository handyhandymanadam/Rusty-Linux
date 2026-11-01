#!/usr/bin/env bash
# port/test/loadavg/run.sh -- kernel/sched/loadavg.c: the pristine fixed_power_int() / calc_load_n() vs loadavg_rs.rs (4 shards).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/loadavg"
out="${TMPDIR:-/tmp}/ldtest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${EB_RS:-$root/port/tree/kernel/sched/loadavg_rs.rs}"; C="$root/port/pristine/kernel/sched/loadavg.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" "$C" "$out/glue.c"
python3 "$here/extract.py" "$C" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -Wno-sign-compare -I $here"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRCFILE=\"$out/ref.c\"" -o "$1/t" "$here/main.c"; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name loadavg_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${VG:-}" = 1 ]; then EB_N=5000 valgrind -q --error-exitcode=9 "$out/rs/t" 1 >/dev/null && echo "valgrind clean"; exit; fi
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    EB_PROVE=1 EB_N=60 "$out/rs/t" 0 > "$out/p.out"; EB_N=60 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | grep -c .)"; echo PASS; exit
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
# Equivalent mutant left out of mutants.txt (15 are listed, all caught): load_active (active == load gives load * 2048 + 2047 over 2048, which is load, with or without the rounding term).
