#!/usr/bin/env bash
# port/test/mls/run.sh -- security/selinux/ss/mls.c: the pristine file vs mls_rs.rs + the glue wrapper, with the pristine ebitmap, hashtab and symtab C on both sides (4 shards).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/mls"
out="${TMPDIR:-/tmp}/mlstest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
P="$root/port/pristine/security/selinux/ss"; T="$root/port/tree/security/selinux/ss"; TT="$root/port/test"
RS="${EB_RS:-$T/mls_rs.rs}"
for f in "$RS" "$P/mls.c" "$P/ebitmap.c" "$P/hashtab.c" "$P/symtab.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" "$P/mls.c" "$out/glue.c"
python3 "$here/extract.py" "$P/mls.c" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
python3 "$TT/ebitmap/extract.py" "$P/ebitmap.c" "$out/heb.c"; python3 "$TT/hashtab/extract.py" hashtab "$P/hashtab.c" "$out/hht.c"; python3 "$TT/hashtab/extract.py" symtab "$P/symtab.c" "$out/hst.c"
W="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -Wno-sign-compare -Wno-misleading-indentation"
cc $W -c -I "$TT/ebitmap/shim" -I "$P" -I "$root/port/pristine/include" -I "$TT/ebitmap" -o "$out/heb.o" "$out/heb.c"
cc $W -c -I "$TT/hashtab/shim" -I "$TT/hashtab" -I "$P" -o "$out/hht.o" "$out/hht.c"
cc $W -c -I "$TT/hashtab/shim" -I "$TT/hashtab" -I "$P" -o "$out/hst.o" "$out/hst.c"
CF="$W -I $here -I $here/shim -I $TT/ebitmap/shim -I $P -I $root/port/pristine/include -I $out"
OBJS="$out/heb.o $out/hht.o $out/hst.o"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRCFILE=\"$out/ref.c\"" -o "$1/t" "$here/main.c" $OBJS; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name mls_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t" "$here/main.c" $OBJS "$2/librs.a" -lpthread; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${VG:-}" = 1 ]; then EB_N=2000 valgrind -q --error-exitcode=9 "$out/rs/t" 1 >/dev/null && echo "valgrind clean"; exit; fi
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    EB_PROVE=1 EB_N=300 "$out/rs/t" 0 > "$out/p.out"; EB_N=300 "$out/ref/t" 0 > "$out/p.ref"
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
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs" 2>"$out/mut.err" || { echo "mutant $name: PATTERN MISSING (mutant list bug)"; invalid=$((invalid+1)); continue; }
    buildrs "$out/mut.rs" "$out/m$n" "-A dead_code -A unused" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; grep -m3 -E "error|Error|cannot|undefined" "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n"; rm -f "$out"/m$n.?*
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Equivalent mutants left out of mutants.txt (141 are listed, all caught): bits_start_reset (Bits::new already points the cursor at the first node); lv_null (every value in 1..nprim has a name that is
# also in the table: the two are built together); sid_defnull (a SID of 0 has no entry in the table, so sidtab_search() refuses it with the same -EINVAL); sid_break (the second part of a range is
# the last loop pass, so `continue` ends the loop as `break` does); cs_glb (the greatest lower bound / least upper bound is symmetric in its two contexts).
