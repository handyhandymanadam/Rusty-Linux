#!/usr/bin/env bash
# port/test/misc/run.sh -- exhaustive differential for arch/x86/lib/misc.c.
#
# num_digits(int) is a pure function of one 32-bit argument, so the whole input
# space (2^32) is compared: pristine C vs the Rust the kernel builds, and both
# against an independent power-of-ten oracle, plus snprintf on a sample. This is
# a PROOF over the input space (for these two binaries), not a sample.
#
# The Rust is generated from port/tree (the file the kernel compiles); the C is
# port/pristine (not the tree: reading the oracle out of an edited tree is a
# test agreeing with itself).
#
#   run.sh            full run, 4 shards in parallel
#   run.sh --sabotage prove the harness can fail: 6 mutants of the Rust, each
#                     must be caught (each over the full 2^32 space, 1 shard)
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/misc"
out="${TMPDIR:-/tmp}/misc-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/arch/x86/lib/misc.c"
RS="$root/port/tree/arch/x86/lib/misc_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

want=$(grep -E '^int num_digits' "$root/src/linux/arch/x86/include/asm/misc.h" | tr -d ' \t')
have=$(grep -E '^int num_digits' "$here/shim/asm/misc.h" | tr -d ' \t')
[ "$want" = "$have" ] || { echo "SHIM MISMATCH asm/misc.h: kernel '$want' shim '$have'"; exit 1; }
echo "shim asm/misc.h matches arch/x86/include/asm/misc.h ($want)"

build() {   # build <rs-source> <outdir>
    local rs=$1 o=$2
    mkdir -p "$o"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name misc_rs -o "$o/librs.a" "$rs"
    # -fwrapv: the kernel builds with -fno-strict-overflow (INT_MIN negation wraps)
    cc -O2 -fwrapv -Wall -I "$here/shim" -Dnum_digits=c_num_digits -c -o "$o/c.o" "$C"
    cc -O2 -Wall -c -o "$o/main.o" "$here/main.c"
    cc -o "$o/t" "$o/main.o" "$o/c.o" "$o/librs.a"
}

runall() {  # runall <bin> -> 0 if all shards pass
    local t=$1 pids=() rc=0 s
    for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done
    for p in "${pids[@]}"; do wait "$p" || rc=1; done
    return $rc
}

echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"

echo "prove-can-fail (poisoned Rust result for one value must be caught):"
if NUM_FAILFAST=1 NUM_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then
    echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned run reported a mismatch"

if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='|' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 -c 'import os,sys; s=open(sys.argv[1]).read(); f=os.environ["FROM"]; sys.stdout.write(s.replace(f, os.environ["TO"], 1))' "$RS" > "$out/mut.rs"
        cmp -s "$RS" "$out/mut.rs" && { echo "mutant $name: pattern not found"; exit 1; }
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE (not a catch)"; exit 1; }
        if NUM_FAILFAST=1 "$out/m$n/t" 0 1 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
sign-edge|if val < 0 {|if val < -1 {
loop-off-by-one|while (val as i64) >= m|while (val as i64) > m
radix-9|m *= 10;|m *= 9;
start-at-2|let mut d: c_int = 1;|let mut d: c_int = 2;
cap-at-9|while (val as i64) >= m|while (val as i64) >= m && d < 9
no-abs|val = val.wrapping_neg();|val = val.wrapping_add(0);
MUT
    echo "$caught of $n mutants caught"
    [ "$caught" = "$n" ]
    exit
fi

start=$(date +%s)
runall "$out/real/t" | sort
echo "exhaustive: 2^32 = 4294967296 inputs, 4 shards, $(( $(date +%s) - start )) s"
