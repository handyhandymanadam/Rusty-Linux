#!/usr/bin/env bash
# port/test/x86_cpu/run.sh -- exhaustive 2^32 differential for arch/x86/lib/cpu.c.
#   run.sh            full run, 4 shards
#   run.sh --sabotage prove the harness fails on mutants of the Rust (each over a full 2^32 shard-set until the first mismatch)
# C arm = port/pristine/arch/x86/lib/cpu.c (unmodified); Rust arm = port/tree/arch/x86/lib/cpu_rs.rs.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/x86_cpu"
out="${TMPDIR:-/tmp}/x86cpu.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh"
C="${CPU_PRISTINE:-$root/port/pristine/arch/x86/lib/cpu.c}"
RS="${CPU_RS:-$root/port/tree/arch/x86/lib/cpu_rs.rs}"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
# the prototypes the shim asm/cpu.h carries must be the kernel's
for fn in x86_family x86_model x86_stepping; do
    grep -q "^unsigned int $fn(unsigned int sig);" "$root/src/linux/arch/x86/include/asm/cpu.h" \
      || grep -q "$fn(unsigned int sig)" "$root/src/linux/arch/x86/include/asm/cpu.h" \
      || { echo "SHIM MISMATCH: $fn not declared in asm/cpu.h as (unsigned int sig)"; exit 1; }
done
build() {   # build <rs> <dir>
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort \
        -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
        --crate-name x86_cpu_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -Wall -I "$here/shim" -Dx86_family=c_x86_family -Dx86_model=c_x86_model -Dx86_stepping=c_x86_stepping -c -o "$2/c.o" "$C"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/c.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3; do "$t" "$s" 4 & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if CPU_PROVE_CAN_FAIL=1 "$out/real/t" 0 1 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    mutate() {
        n=$((n+1))
        python3 - "$RS" "$out/mut.rs" "$2" "$3" <<'PY'
import sys
s = open(sys.argv[1]).read(); a, b = sys.argv[3:5]
assert a in s, "pattern missing: " + a
open(sys.argv[2], "w").write(s.replace(a, b, 1))
PY
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $1: DID NOT COMPILE"; exit 1; }
        if "$out/m$n/t" 0 64 >/dev/null 2>&1 && "$out/m$n/t" 1 64 >/dev/null 2>&1 && "$out/m$n/t" 63 64 >/dev/null 2>&1; then echo "mutant $1: *** NOT CAUGHT"; else echo "mutant $1: caught"; caught=$((caught+1)); fi
    }
    mutate fam-base-shift     '(sig >> 8) & 0xf' '(sig >> 9) & 0xf'
    mutate fam-base-mask      '(sig >> 8) & 0xf' '(sig >> 8) & 0x7'
    mutate fam-f-test         'if x86 == 0xf {' 'if x86 >= 0xe {'
    mutate fam-ext-shift      'x86 += (sig >> 20) & 0xff;' 'x86 += (sig >> 21) & 0xff;'
    mutate fam-ext-mask       'x86 += (sig >> 20) & 0xff;' 'x86 += (sig >> 20) & 0x7f;'
    mutate model-shift        'let mut model = (sig >> 4) & 0xf;' 'let mut model = (sig >> 5) & 0xf;'
    mutate model-fam-bound    'if fam >= 0x6 {' 'if fam > 0x6 {'
    mutate model-fam-bound-lo 'if fam >= 0x6 {' 'if fam >= 0x5 {'
    mutate model-ext-shift    '((sig >> 16) & 0xf) << 4' '((sig >> 16) & 0xf) << 3'
    mutate model-ext-field    '((sig >> 16) & 0xf) << 4' '((sig >> 17) & 0xf) << 4'
    mutate model-fam-from-ext   'let fam = x86_family(sig);' 'let fam = (sig >> 20) & 0xff;'
    mutate step-mask          'sig & 0xf' 'sig & 0x7'
    echo "$caught of $n mutants caught"; [ "$caught" = "$n" ]; exit
fi
start=$(date +%s)
runall "$out/real/t" | sort
echo "exhaustive: 2^32 = 4294967296 signatures x 3 functions, 4 shards, $(( $(date +%s) - start )) s"
