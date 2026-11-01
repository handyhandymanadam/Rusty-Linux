#!/usr/bin/env bash
# port/test/ntp/run.sh -- kernel/time/ntp.c: the pristine discipline arithmetic vs ntp_rs.rs + the glue wrappers at HZ 100, 250, 300 and 1000 (one per shard); random adjtimex / second_overflow / clear / next_leap streams from random states.   run.sh [--sabotage]
# Mutants not caught, all equivalent (114 of 117 caught; the 3 others): uo_clamp1 -- a value of 10^6 + 1 microseconds times 1000 is clamped to MAXPHASE by the next line anyway;
# uo_limcmp -- `secs >= lim + 1` is `secs > lim`; st_unsync -- the status written when PLL is switched off is masked to the read-only bits on the next lines.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/ntp"
out="${TMPDIR:-/tmp}/nptest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${NP_RS:-$root/port/tree/kernel/time/ntp_rs.rs}"; C="$root/port/pristine/kernel/time/ntp.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract_ref.py" "$C" "$out/ref.c" "$out/ntpstruct.h"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-unused-label -Wno-incompatible-pointer-types -Wno-unused-parameter -Wno-gnu-statement-expr -I $here -I $out"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name ntp_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    NP_PROVE=1 NP_N=300 "$out/rs/t" 0 > "$out/p.out"; NP_N=300 "$out/ref/t" 0 > "$out/p.ref"
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
