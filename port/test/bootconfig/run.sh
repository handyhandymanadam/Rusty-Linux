#!/usr/bin/env bash
# port/test/bootconfig/run.sh -- lib/bootconfig.c: pristine C vs bootconfig_glue.c over bootconfig_rs.rs; xbc_init over a fixed corpus and grammar-generated / byte-damaged texts,
# every result, error message and position, node and data hash, finder, leaf iteration and command-line rendering compared, plus allocation failure and re-init.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); here="$root/port/test/bootconfig"
out="${TMPDIR:-/tmp}/bcftest.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${BCF_RS:-$root/port/tree/lib/bootconfig_rs.rs}"; G="$root/port/tree/lib/bootconfig_glue.c"; C="$root/port/pristine/lib/bootconfig.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
CF="-O1 -Wall -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-pointer-sign -I $here/shim"
buildctype() { cc $CF -c -o "$1/ctype.o" "$root/src/linux/lib/ctype.c"; }
buildref() { mkdir -p "$1"; buildctype "$1"; cc $CF -DARM_REF "-DSRC=\"$C\"" -o "$1/t" "$here/main.c" "$1/ctype.o"; }
buildrs() { mkdir -p "$2"; buildctype "$2"; "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings --crate-name bootconfig_rs -o "$2/librs.a" "$1"
    cc $CF -DARM_RS "-DSRC=\"$G\"" -o "$2/t" "$here/main.c" "$2/librs.a" "$2/ctype.o"; }
runone() { local t=$1 tag=$2 s; for s in 0 1 2 3; do ( ulimit -v 3000000; ulimit -f 400000; timeout 60 "$t" "$s" > "$out/$tag.$s" 2> "$out/$tag.$s.err"; echo $? > "$out/$tag.$s.rc" ) 2>/dev/null & done; wait; }
compare() { local s rc=0; for s in 0 1 2 3; do cmp -s "$out/$1.$s" "$out/$2.$s" || { rc=1; echo "  shard $s differs"; }; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
buildref "$out/ref"; buildrs "$RS" "$out/rs"
if [ "${1:-}" != "--sabotage" ]; then
    echo "prove-can-fail:"
    BCF_PROVE=1 BCF_N=50 "$out/rs/t" 0 > "$out/p.out"; BCF_N=50 "$out/ref/t" 0 > "$out/p.ref"
    if cmp -s "$out/p.out" "$out/p.ref"; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
    echo "  ok, poisoned Rust result detected"
    echo "differential:"; runone "$out/ref/t" ref; runone "$out/rs/t" rs; compare ref rs
    cat "$out"/rs.?.rc "$out"/ref.?.rc | grep -qv '^0$' && { echo "  a shard exited non-zero"; head -3 "$out"/rs.?.err; exit 1; }
    echo "cases compared: $(cat "$out"/ref.?  | wc -l)"; echo PASS; exit
fi
runone "$out/ref/t" ref
n=0; caught=0; invalid=0
while IFS='~' read -r name from to; do
    [ -n "$name" ] || continue
    n=$((n+1))
    FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
    buildrs "$out/mut.rs" "$out/m$n" >"$out/build.log" 2>&1 || { echo "mutant $name: DID NOT COMPILE (mutant list bug)"; head -6 "$out/build.log"; invalid=$((invalid+1)); continue; }
    runone "$out/m$n/t" "m$n"
    if compare ref "m$n" >/dev/null 2>&1 && ! cat "$out"/m$n.?.rc | grep -qv '^0$'; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
done < "$here/mutants.txt"
echo "sabotage: $caught of $n mutants caught ($invalid invalid)"; [ "$caught" -eq "$n" ] && [ "$invalid" -eq 0 ]
# Survivors accounted for (each run of this list reports them as NOT CAUGHT; none is a gap in the port):
#  parity_k    parity() is only called on solver rows < 2^16, so the nibble the mutated multiplier drops is always zero.
#  sol_fake    in the fake parameter row the mutated bit (m-r+1) can never meet a set bit of tmp: rows are processed with m-r increasing, so tmp only holds bits below m-r.
#  sol_nsol    "nsol > (1<<k)" differs from "!=" only for k > 2, and the kernel of X^4+aX^2+bX has dimension <= 2.
#  b2_sum      i*(2<<j) for j = 0..m-1 walks the same Frobenius orbit as i*(1<<j) (2^m = 1 mod n), so the trace is the same.
#  b2_x        the loop never needs x = n (all-ones) to find the m values it is looking for.
#  gen_root    the mutated generator polynomial has coefficients g_j * a^(deg-j): the same non-zero pattern, and only that is stored.
#  init_mt     m*t == 2^m - 1 is impossible (m never divides 2^m - 1 for m > 1).
#  dec_err     nroots never exceeds the locator degree (the BTA factors' degrees add up), so "err > nroots" equals "err != nroots".
#  bm_last     at i = t-1 the value computed under "i < t-1" is never used again (the loop ends).
#  trace_last  the extra squaring at the last step of compute_trace_bk_mod only changes z, which is dead afterwards.
#  fac_lt      gcd.deg == f.deg splits f into (f scaled, constant), and the recursion on the scaled copy finds the same roots as on f itself.
#  d2_cond     a degree-2 locator with c1 == 0 has a repeated root; none arose in ~600k trials with random and structured syndromes.
#  bm_gt       tmp == elp.deg did not occur in the same ~600k trials (the equality case would replace the saved polynomial without a degree change).
# The alignment handling in bootconfig_encode (the "& 3" test, the head/tail byte loops) is performance only: reading 32-bit words from any address gives the same
# parity, so mutants there are equivalent and none is listed.
# Equivalent or unreachable (reported as NOT CAUGHT; none is a gap in the port):
#  fs_key, fv_key  a sibling chain reached from get_subkey() / the root holds only key nodes (a value node is always the first child), so is_key() is always true there.
#  cb_neg          "brace_index < 0" with a non-NULL last_parent cannot happen: last_parent is only non-NULL inside an open brace or while a key=value is being parsed,
#                  and a '}' ending a value restores it to the saved (NULL at top level) parent before closing.
#  vt_next         a node's next index is always < node_num, so ">" and ">=" agree.
#  xi_zero         the zeroing of the node array is hygiene: every node is fully written by xbc_init_node() / __xbc_add_sibling() before it is read.
