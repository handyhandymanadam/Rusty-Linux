#!/usr/bin/env bash
# port/test/iov_iter/run.sh -- the ported part of lib/iov_iter.c: the original functions (extracted from the pristine file) vs iov_iter_rs.rs.
# The same main.c is linked against each; it prints one digest per case and the two outputs must be identical.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/iov_iter"
out="${TMPDIR:-/tmp}/iovtest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${IOV_RS:-$root/port/tree/lib/iov_iter_rs.rs}"; C="$root/port/pristine/lib/iov_iter.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
( echo '#include "kshim.h"'; python3 "$here/extract.py" "$C" ) > "$out/ref.c"
buildref() { mkdir -p "$1"; cc -O1 -w -I "$here/shim" -c -o "$1/ref.o" "$out/ref.c"; cc -O1 -Wall -Wno-unused-function -I "$here/shim" -c -o "$1/main.o" "$here/main.c"; cc -o "$1/t" "$1/main.o" "$1/ref.o"; }
buildrs() {
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name iov_iter_rs -o "$2/librs.a" "$1"
    cc -O1 -Wall -Wno-unused-function -DARM_RS -I "$here/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/librs.a"
}
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; timeout 300 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs: $(diff "$out/$1.$s" "$out/$2.$s" | head -3 | tr '\n' ' ')"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    IOV_PROVE=1 IOV_N=200 "$out/rs/t" 0 > "$out/p.out"; IOV_N=200 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"
    runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; exit 1; }
    echo "cases compared: $(cat "$out"/ref.? | wc -l)"
    echo PASS; exit
fi
runone "$out/ref/t" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    [ -z "${IOV_ONLY:-}" ] || [[ "$name" =~ $IOV_ONLY ]] || continue
    n=$((n+1))
    FROM=${from//<NL>/$'\n'} TO=${to//<NL>/$'\n'} python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; head -6 "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Dropped as EQUIVALENT: folioq_adv_slotstore (the upper bytes of the slot union are zero in every iterator), folioq_adv_dowhile (a stop at size 1 vs 0 ends at the same place), rev_folioq_zero (folioq_revert sets iov_offset itself), al_iovec_len (len == size either way),
# np_max / np_bvec_max (the cap is reached either way), restore_ubuf (an ubuf has no nr_segs to move), restore_bvec (iovec and bio_vec are both 16 bytes here).
