#!/usr/bin/env bash
# port/test/clockevents/run.sh -- kernel/time/clockevents.c: the pristine arithmetic-bearing functions vs clockevents_rs.rs + the glue, with and without CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST and at HZ
# 100 / 250 / 1000 (six shards: shard / 2 picks HZ, shard % 2 picks the MIN_ADJUST arm); fake devices with scripted set_next_event results.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/clockevents"
out="${TMPDIR:-/tmp}/cetest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${CE_RS:-$root/port/tree/kernel/time/clockevents_rs.rs}"; C="$root/port/pristine/kernel/time/clockevents.c"; CS="$root/port/pristine/kernel/time/clocksource.c"
for f in "$RS" "$C" "$CS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" "$C" "$out/glue.c"
python3 "$here/extract.py" "$C" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
python3 - "$CS" "$out/clocksrc.c" <<'PY'
import sys
s = open(sys.argv[1]).read(); i = s.index("void\nclocks_calc_mult_shift("); j = s.index("\n}\n", i) + 3
open(sys.argv[2], "w").write(s[i:j])
PY
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -I $here -I $out"
buildref() { mkdir -p "$1"; for v in adj plain; do cc $CF $( [ $v = adj ] && echo -DMIN_ADJUST ) "-DSRCFILE=\"$out/ref.c\"" -o "$1/t.$v" "$here/main.c"; done; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name clockevents_rs -o "$2/librs.a" "$1"
    for v in adj plain; do cc $CF $( [ $v = adj ] && echo -DMIN_ADJUST ) "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t.$v" "$here/main.c" "$2/librs.a" -lpthread; done; }
runone() { local d=$1 tag=$2 s v; for s in 0 1 2 3 4 5; do v=plain; [ $((s % 2)) = 0 ] && v=adj; ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$d/t.$v" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3 4 5; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    CE_PROVE=1 CE_N=60 "$out/rs/t.adj" 0 > "$out/p.out"; CE_N=60 "$out/ref/t.adj" 0 > "$out/p.ref"
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
# Equivalent mutants left out of mutants.txt (33 are listed, all caught): `n >= limit + 1` is `n > limit`; `clc >= 1000` returns 1000 either way; `sec == 1` instead of `sec == 0` (a maxsec of 0
# or 1 against NSEC_PER_SEC gives the same shift factor, as does anything up to 4); `mult < 1 << shift` against `<=` (for mult = 1 << shift the clc is a multiple of mult, so adding mult - 1
# changes nothing); sec = 2 instead of 1, sec = 601 instead of 600 and a threshold of 601 (all give the same factor, which needs a maxsec of 5 or 1100+ to change).
