#!/usr/bin/env bash
# port/test/lockref/run.sh -- lib/lockref.c: single-thread differential + multi-thread stress, pristine C vs thunk-shaped lockref.c + lockref_rs.rs.
#   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/lockref"
out="${TMPDIR:-/tmp}/lockref.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${LR_RS:-$root/port/tree/lib/lockref_rs.rs}"
C="$root/port/pristine/lib/lockref.c"
G="$root/port/tree/lib/lockref.c"
for f in "$RS" "$C" "$G"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
REN=""; for fn in lockref_get lockref_put_return lockref_get_not_zero lockref_put_or_lock lockref_mark_dead lockref_get_not_dead; do REN="$REN -D$fn=c_$fn"; done
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on --cfg CONFIG_SMP \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name lockref_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w $REN -I "$here/shim" -DLOCKREF_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -w -I "$here/shim" -DLOCKREF_GLUE="\"$G\"" -c -o "$2/glue.o" "$here/glue.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/glue.o" "$2/librs.a" -lpthread
}
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if LR_PROVE_CAN_FAIL=1 LR_N=100 LR_SECONDS=0 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if LR_N=300000 LR_SECONDS=2 timeout 120 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
non-atomic-get~word.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)~word.compare_exchange(word.load(Ordering::Relaxed), new, Ordering::Relaxed, Ordering::Relaxed)
ignore-lock~while (old as u32) == 0 {~while (old >> 63) == 0 {
get-plus2~Step::Update(c.wrapping_add(1))) }, Outcome::Done(_))~Step::Update(c.wrapping_add(2))) }, Outcome::Done(_))
get-not-zero-bound~if c <= 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {<NL>        Outcome::Done(_) => 1,~if c < 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {<NL>        Outcome::Done(_) => 1,
put-return-bound~if c <= 0 { Step::Return(-1) } else { Step::Update(c.wrapping_sub(1)) }~if c < 0 { Step::Return(-1) } else { Step::Update(c.wrapping_sub(1)) }
put-return-value~Outcome::Done(n) => n,~Outcome::Done(n) => n + 1,
put-or-lock-bound~if c <= 1 { Step::Fallback } else { Step::Update(c.wrapping_sub(1)) }~if c <= 0 { Step::Fallback } else { Step::Update(c.wrapping_sub(1)) }
get-not-dead-bound~if c < 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {<NL>        Outcome::Done(_) => 1,<NL>        Outcome::Early(v) => v,<NL>        Outcome::Slow => -1,<NL>    }<NL>}~if c <= 0 { Step::Return(0) } else { Step::Update(c.wrapping_add(1)) }) } {<NL>        Outcome::Done(_) => 1,<NL>        Outcome::Early(v) => v,<NL>        Outcome::Slow => -1,<NL>    }<NL>}
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential + stress:"
LR_THREADS=${LR_THREADS:-4} "$out/real/t" 0
