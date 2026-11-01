#!/usr/bin/env bash
# port/test/hashtab/run.sh -- security/selinux/ss/hashtab.c and symtab.c: the pristine functions vs hashtab_rs.rs + symtab_rs.rs + the glue wrappers (4 shards).   run.sh [--sabotage]
# mutants.txt lines: NAME~FILE~FROM~TO  with FILE h (hashtab_rs.rs) or s (symtab_rs.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/hashtab"
out="${TMPDIR:-/tmp}/htest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
P="$root/port/pristine/security/selinux/ss"; T="$root/port/tree/security/selinux/ss"
RSH="${EB_RSH:-$T/hashtab_rs.rs}"; RSS="${EB_RSS:-$T/symtab_rs.rs}"
for f in "$RSH" "$RSS" "$P/hashtab.c" "$P/symtab.c"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/mkglue.py" hashtab "$P/hashtab.c" "$out/hglue.c"; python3 "$here/mkglue.py" symtab "$P/symtab.c" "$out/sglue.c"
python3 "$here/extract.py" hashtab "$P/hashtab.c" "$out/href.c"; python3 "$here/extract.py" symtab "$P/symtab.c" "$out/sref.c"
python3 "$here/extract.py" hashtab "$out/hglue.c" "$out/hrs.c"; python3 "$here/extract.py" symtab "$out/sglue.c" "$out/srs.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -Wno-sign-compare -I $here/shim -I $P -I $here"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRCFILE_H=\"$out/href.c\"" "-DSRCFILE_S=\"$out/sref.c\"" -o "$1/t" "$here/main.c"; }
rsc() { "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name "$2" -o "$4" "$1"; }
buildrs() {  # buildrs HFILE SFILE DIR [extra rustc flags]
    mkdir -p "$3"; rsc "$1" hashtab_rs "${4:-}" "$3/libh.a"; rsc "$2" symtab_rs "${4:-}" "$3/libs.a"
    cc $CF -DARM_RS "-DSRCFILE_H=\"$out/hrs.c\"" "-DSRCFILE_S=\"$out/srs.c\"" -o "$3/t" "$here/main.c" "$3/libh.a" "$3/libs.a" -lpthread -Wl,--allow-multiple-definition; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RSH" "$RSS" "$out/rs"
if [ "${VG:-}" = 1 ]; then EB_N=5000 valgrind -q --error-exitcode=9 "$out/rs/t" 1 >/dev/null && echo "valgrind clean"; exit; fi
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
while IFS='~' read -r name file from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    src=$RSH; [ "$file" = s ] && src=$RSS
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$src" > "$out/mut.rs"
    if [ "$file" = s ]; then h=$RSH; s=$out/mut.rs; else h=$out/mut.rs; s=$RSS; fi
    buildrs "$h" "$s" "$out/m$n" "-A dead_code -A unused" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; grep -m3 -E "error|Error|cannot|undefined" "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    rm -rf "$out/m$n"; rm -f "$out"/m$n.?*
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Equivalent mutants left out of mutants.txt (49 are listed, all caught): h_des_null (the slot is freed right after), s_ins_break and s_srch_cmp (`cmp <= 0` after the `cmp == 0` return is the same
# test as `cmp < 0`).
