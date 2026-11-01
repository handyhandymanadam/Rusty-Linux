#!/usr/bin/env bash
# port/test/scatterlist/run.sh -- lib/scatterlist.c: pristine C vs scatterlist_glue.c over scatterlist_rs.rs. The same main.c is linked against
# each; it prints one hash per case (everything observable folded in) and the two outputs must be identical. Built for both struct layouts
# (32-byte scatterlist with dma_length/dma_flags, 16-byte without).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/scatterlist"
out="${TMPDIR:-/tmp}/sgtest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${SG_RS:-$root/port/tree/lib/scatterlist_rs.rs}"
G="$root/port/tree/lib/scatterlist_glue.c"; C="$root/port/pristine/lib/scatterlist.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
sed -n '1,1083p' "$C" > "$out/ref.c"          # upstream up to and including sg_zero_buffer(); extract_*_to_sg() (iov_iter users) are not in the oracle
buildref() {   # buildref <dir> <extra cflags>
    mkdir -p "$1"
    cc -O1 -w $2 -I "$here/shim" -c -o "$1/ref.o" "$out/ref.c"
    cc -O1 -Wall -Wno-unused-parameter -Wno-unused-function $2 -I "$here/shim" -c -o "$1/main.o" "$here/main.c"
    cc -o "$1/t" "$1/main.o" "$1/ref.o"
}
buildrs() {    # buildrs <rs> <dir> <extra cflags>
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name scatterlist_rs -o "$2/librs.a" "$1"
    cc -O1 -w $3 -I "$here/shim" -c -o "$2/glue.o" "$G"
    cc -O1 -Wall -Wno-unused-parameter -Wno-unused-function $3 -DARM_RS -I "$here/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/glue.o" "$2/librs.a"
}
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do timeout 60 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err" & done; wait; }
compare() {    # compare <reftag> <rstag>  -> 0 when all four shards are identical
    local s rc=0
    for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs: $(diff "$out/$1.$s" "$out/$2.$s" | head -3 | tr '\n' ' ')"; }; done
    return $rc
}
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/refdma" ""; buildref "$out/refnodma" "-DNODMA"
buildrs "$RS" "$out/dma" ""; buildrs "$RS" "$out/nodma" "-DNODMA"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    SG_PROVE=1 SG_N=20 "$out/dma/t" 0 > "$out/p.out" 2>/dev/null; SG_N=20 "$out/refdma/t" 0 > "$out/p.ref" 2>/dev/null
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential (32-byte scatterlist, then 16-byte):"
    runone "$out/refdma/t" refdma; runone "$out/dma/t" dma; compare refdma dma
    runone "$out/refnodma/t" refnodma; runone "$out/nodma/t" nodma; compare refnodma nodma
    ncases=$(cat "$out"/refdma.? "$out"/refnodma.? | wc -l); nerr=$(cat "$out"/*.err | grep -c . || true)
    echo "cases compared: $ncases, stderr lines (BUG/LEAK/BAD FREE): $nerr"
    [ "$nerr" -eq 0 ]
    echo PASS
    exit
fi
runone "$out/refdma/t" refdma
n=0; caught=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" "" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE"; head -8 "$out/build.log"; exit 1; }
    runone "$out/m$n/t" "m$n"
    if compare refdma "m$n" >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
