#!/usr/bin/env bash
# port/test/clocksource/run.sh -- kernel/time/clocksource.c: the pristine conversion functions vs clocksource_rs.rs + the glue (thunks and __clocksource_update_freq_scale), random and edge arguments,
# five WATCHDOG_MAX_SKEW values (one per shard, 4 shards + the fifth in a second pass).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/clocksource"
out="${TMPDIR:-/tmp}/cstest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${CS_RS:-$root/port/tree/kernel/time/clocksource_rs.rs}"; C="$root/port/pristine/kernel/time/clocksource.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" "$C" "$out/glue.c"
python3 "$here/extract.py" "$C" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -I $here"
buildref() { mkdir -p "$1"; cc $CF "-DSRCFILE=\"$out/ref.c\"" -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name clocksource_rs -o "$2/librs.a" "$1"
    cc $CF "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3 4; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3 4; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    CS_PROVE=1 CS_N=50 "$out/rs/t" 0 > "$out/p.out"; CS_N=50 "$out/ref/t" 0 > "$out/p.ref"
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
    buildrs "$out/mut.rs" "$out/m$n" "-A dead_code -A unused" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; grep -m3 -E "error|Error|cannot|undefined" "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n"; rm -f "$out"/m$n.?*
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Mutants that are equivalent and left out of mutants.txt (47 are listed, all caught): sec > 599 / sec >= 600 (a sec of 600 is set to 600 anyway); mask > UINT_MAX vs >= (for a mask up to
# UINT_MAX, sec * scale * freq is below 2^32, so maxsec never reaches the shift factor); dropping `scale != 0` in the margin test (the freq block has already divided by scale);
# dropping `mult - maxadj > mult` (maxadj is 11 % of mult, never more); sec = 2 instead of 1 (with sec 1 or 2 the conversion accepts the same shift for every freq below 2^32).
