#!/usr/bin/env bash
# port/test/kobject_uevent/run.sh -- lib/kobject_uevent.c: kobject_synth_uevent() and zap_modalias_env() of the pristine file vs kobject_uevent_glue.c's thunks/wrappers over kobject_uevent_rs.rs;
# random synthetic-uevent strings and random environment blocks, everything printed (4 shards).   run.sh [--sabotage]
# Mutants expected NOT caught (equivalent), by name in mutants.txt:
#   strncmp_nul / strnchr_nul / exact_len   differ only for a string with an embedded NUL before its end; there the C reads past a string literal (kobject_actions[a][count_first]), so main.c leaves those out.
#   type_empty / args_empty   a one-byte string is no action and is shorter than a UUID: -EINVAL either way.
#   uuid_add           the first add_uevent_var() on an empty environment cannot fail.
#   key_end / key_eq / key_next_end   the branches they change are followed by a check that fails the same way (a key with no '=' after it, or '=' as the last byte).
#   zap_j              the loop's first assignment (envp[i] = envp[i+1] - len) rewrites the value envp[i] already has, because add_uevent_var() lays the strings out back to back.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/kobject_uevent"
out="${TMPDIR:-/tmp}/kutest.$$"; mkdir -p "$out"; trap '[ -n "${KEEP:-}" ] || rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${KU_RS:-$root/port/tree/lib/kobject_uevent_rs.rs}"; GS="$root/port/tree/lib/kobject_uevent_glue.c"; CS="$root/port/pristine/lib/kobject_uevent.c"
for f in "$RS" "$CS" "$GS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
python3 "$here/extract.py" "$CS" "$GS" "$out/ref.c" "$out/rs.c"; C="$out/ref.c"; G="$out/rs.c"
CF="-O1 -g -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -I $here/shim"
buildref() { mkdir -p "$1"; cc $CF -DARM_REF "-DSRC=\"$C\"" -o "$1/t" "$here/main.c" ; }
buildrs() { mkdir -p "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings ${3:-} --crate-name kobject_uevent_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$G\"" -o "$2/t" "$here/main.c" "$2/librs.a" -lpthread ; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 25 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    KU_PROVE=1 KU_N=50 "$out/rs/t" 0 > "$out/p.out"; KU_N=50 "$out/ref/t" 0 > "$out/p.ref"
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
