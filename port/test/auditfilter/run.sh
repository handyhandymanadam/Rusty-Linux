#!/usr/bin/env bash
# port/test/auditfilter/run.sh -- kernel/auditfilter.c: the pristine pure checks vs auditfilter_rs.rs + the glue thunks (4 shards; shard 0 also runs every field-validity combination).   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/auditfilter"
out="${TMPDIR:-/tmp}/aftest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${AF_RS:-$root/port/tree/kernel/auditfilter_rs.rs}"; C="$root/port/pristine/kernel/auditfilter.c"; H="$root/src/linux/include/uapi/linux/audit.h"
for f in "$RS" "$C" "$H"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 - "$H" "$out/audit_consts.h" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
defs = "\n".join(l for l in s.split("\n") if re.match(r"#define\s+AUDIT_\w+\s+\S", l) and "(" not in l.split(None, 2)[1])
a = s.index("enum {\n\tAudit_equal"); b = s.index("};", a) + 2
open(sys.argv[2], "w").write(defs + "\n" + s[a:b] + "\n")
PY
python3 "$here/mkglue.py" "$C" "$out/glue.c"
python3 "$here/extract.py" "$C" "$out/ref.c"; python3 "$here/extract.py" "$out/glue.c" "$out/rsglue.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -Wno-format -Wno-sign-compare -Wno-macro-redefined -I $here -I $out"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRCFILE=\"$out/ref.c\"" -o "$1/t" "$here/main.c"; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name auditfilter_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRCFILE=\"$out/rsglue.c\"" -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${VG:-}" = 1 ]; then AF_N=5000 valgrind -q --error-exitcode=9 "$out/rs/t" 1 >/dev/null && echo "valgrind clean"; exit; fi
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    AF_PROVE=1 AF_N=60 "$out/rs/t" 0 > "$out/p.out"; AF_N=60 "$out/ref/t" 0 > "$out/p.ref"
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
