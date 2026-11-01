#!/usr/bin/env bash
# port/test/group_cpus/run.sh -- lib/group_cpus.c: pristine C vs group_cpus_glue.c over group_cpus_rs.rs, random machines x group counts x
# allocation failures, with and without CONFIG_CPUMASK_OFFSTACK.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/group_cpus"
out="${TMPDIR:-/tmp}/gctest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${GC_RS:-$root/port/tree/lib/group_cpus_rs.rs}"
G="$root/port/tree/lib/group_cpus_glue.c"; C="$root/port/pristine/lib/group_cpus.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
build() {   # build <rs> <dir> <extra cflags>
    mkdir -p "$2"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name group_cpus_rs -o "$2/librs.a" "$1"
    cc -O2 -w $3 -I "$here/shim" -Dgroup_cpus_evenly=c_group_cpus_evenly -c -o "$2/ref.o" "$C"
    cc -O2 -w $3 -I "$here/shim" -Dgroup_cpus_evenly=rs_group_cpus_evenly -c -o "$2/glue.o" "$G"
    cc -O2 -Wall -Wno-unused-parameter $3 -I "$here/shim" -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/on" "-DOFFSTACK"; build "$RS" "$out/off" ""
echo "prove-can-fail:"
if GC_PROVE_CAN_FAIL=1 GC_N=50 "$out/off/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    # Dropped as EQUIVALENT: sibling scan starting at 0 instead of -1 (cpu 0 is always taken first or already cleared); `cpu >= nr_cpu_ids` -> `>` in
    # grp_spread_init_one (only reachable with an empty node mask, which ngroups <= ncpus rules out); a node with no CPU in the mask being skipped by its UINT_MAX marker or by ncpus == 0 (same effect); the -ENOMEM value (glue tests only < 0).
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" "" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE"; head -8 "$out/build.log"; exit 1; }
        if GC_N=3000 runall "$out/m$n/t" >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
sibling-first~if !rust_gc_cpumask_test_and_clear_cpu(sibl, nmsk) {~if rust_gc_cpumask_test_and_clear_cpu(sibl, nmsk) {
nodes-le~if numgrps <= nodes {~if numgrps < nodes {
min-groups~core::cmp::max(1, numgrps.wrapping_mul(ncpus) / remaining_ncpus)~core::cmp::max(0, numgrps.wrapping_mul(ncpus) / remaining_ncpus)
numgrps-min~numgrps = core::cmp::min(remaining_ncpus, numgrps);~numgrps = core::cmp::max(remaining_ncpus, numgrps);
sort-dir~ln.v.wrapping_sub(rn.v) as c_int~rn.v.wrapping_sub(ln.v) as c_int
extra~let mut extra_grps = ncpus.wrapping_sub(nv.v.wrapping_mul(ncpus / nv.v));~let mut extra_grps = 0;
extra-dec~extra_grps -= 1;~extra_grps = 0;
wrap-cur~if curgrp >= last_grp {<NL>                    curgrp = 0;<NL>                }<NL>                grp_spread~if curgrp > last_grp {<NL>                    curgrp = 0;<NL>                }<NL>                grp_spread
wrap-nodes~if curgrp == last_grp {<NL>                    curgrp = 0;~if curgrp > last_grp {<NL>                    curgrp = 0;
done~done = done.wrapping_add(nv.v);~done = done.wrapping_add(1);
skip-empty~if ncpus == 0 {<NL>                continue;~if ncpus == 1 {<NL>                continue;
rem-sub~remaining_ncpus = remaining_ncpus.wrapping_sub(ncpus);~remaining_ncpus = remaining_ncpus.wrapping_sub(ng.v);
empty-ret~if rust_gc_cpumask_empty(cpu_mask) {<NL>            return 0;~if rust_gc_cpumask_empty(cpu_mask) {<NL>            return 1;
free~rust_gc_kfree(node_groups.cast());~rust_gc_kfree(core::ptr::null_mut());
nodecount~nodes += 1;~nodes += 2;
or-overwrites~rust_gc_cpumask_or(group(curgrp), group(curgrp), nmsk);~rust_gc_cpumask_or(group(curgrp), nmsk, nmsk);
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential (CPUMASK_OFFSTACK off, then on):"
runall "$out/off/t"; runall "$out/on/t"
echo PASS
