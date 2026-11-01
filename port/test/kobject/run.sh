#!/usr/bin/env bash
# port/test/kobject/run.sh -- lib/kobject.c: pristine C vs kobject_glue.c over kobject_rs.rs; random kobject/kset lifecycle, paths, rename/move, namespace registry, with sysfs/uevent/allocator stubs
# taking injected failures and the whole pool printed after every op (4 shards).   run.sh [--sabotage]
# Mutants expected NOT caught (equivalent or unreachable without a second thread / a BUG()), by name in mutants.txt:
#   create_err         `error != 0` vs `error < 0`: sysfs errors are negative, same set of values.
#   create_bug_valid   BUG_ON(!valid type) can only fire for an ops table with an invalid type that child_ns_type returned: the C BUG()s, the harness cannot.
#   path_len_zero      `len == 1` vs `len == 0`: get_kobj_path_length() returns 0, or 1 plus at least one byte and a '/' per level, so never 1.
#   init_internal_null / add_internal_null   the NULL tests are dead: every caller (kobject_init, kset_init, kobject_add_varg, kset_register) has dereferenced or checked the pointer first.
#   find_null_name     a member of a kset's list always has a name (add_internal refuses an empty one and sysfs needs it), so the NULL test never matters.
#   kset_unreg_null    clang folds `ks_kobj(NULL)` (an inbounds pointer add) so that the NULL test inside kobject_del() becomes the test of k itself: the mutant behaves like the original.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/kobject"
out="${TMPDIR:-/tmp}/kotest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${KO_RS:-$root/port/tree/lib/kobject_rs.rs}"; G="$root/port/tree/lib/kobject_glue.c"; C="$root/port/pristine/lib/kobject.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -I $here/shim"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRC=\"$C\"" -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name kobject_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$G\"" -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    KO_PROVE=1 KO_N=50 "$out/rs/t" 0 > "$out/p.out"; KO_N=50 "$out/ref/t" 0 > "$out/p.ref"
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
