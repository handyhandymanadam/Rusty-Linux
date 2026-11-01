#!/usr/bin/env bash
# port/test/x86_scattered/run.sh -- differential for arch/x86/kernel/cpu/scattered.c.   run.sh [--sabotage]
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/x86_scattered"
out="${TMPDIR:-/tmp}/x86scat.$$"; mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
source "$root/kbuild-env.sh" >/dev/null
RS="${SC_RS:-$root/port/tree/arch/x86/kernel/cpu/scattered_rs.rs}"
C="$root/port/pristine/arch/x86/kernel/cpu/scattered.c"
for f in "$RS" "$C"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done
mkdir -p "$out/shim"; cp -r "$here/shim/." "$out/shim/"
python3 "$here/gen_features.py" "$root/src/linux/arch/x86/include/asm/cpufeatures.h" "$out/shim/x86features.h"
build() {
    mkdir -p "$2"
    { echo '#[allow(unused_macros, unused_imports)]'
      echo 'mod kernel { macro_rules! kabi_export { ($($t:tt)*) => {} } pub(crate) use kabi_export; macro_rules! kabi_rule { ($($t:tt)*) => {} } pub(crate) use kabi_rule; }'
      sed 's|^//!|//|' "$1"; } > "$2/probe.rs"
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O -C panic=abort -C overflow-checks=on --cfg userspace_test \
        -D unsafe_op_in_unsafe_fn -D warnings --crate-name scattered_rs -o "$2/librs.a" "$2/probe.rs"
    cc -O2 -w -Dinit_scattered_cpuid_features=c_init_scattered_cpuid_features -I "$out/shim" -DSCATTERED_C="\"$C\"" -c -o "$2/ref.o" "$here/ref.c"
    cc -O2 -Wall -c -o "$2/main.o" "$here/main.c"
    cc -o "$2/t" "$2/main.o" "$2/ref.o" "$2/librs.a"
}
runall() { local t=$1 pids=() rc=0 s; for s in 0 1 2 3 4 5 6 7; do "$t" "$s" & pids+=($!); done; for p in "${pids[@]}"; do wait "$p" || rc=1; done; return $rc; }
echo "rustc: $("$KB_RUSTC" --version)"
build "$RS" "$out/real"
echo "prove-can-fail:"
if SC_PROVE_CAN_FAIL=1 SC_N=100 "$out/real/t" 0 >/dev/null 2>&1; then echo "*** HARNESS CANNOT DISAGREE"; exit 1; fi
echo "  ok, poisoned Rust result detected"
if [ "${1:-}" = "--sabotage" ]; then
    n=0; caught=0
    while IFS='~' read -r name from to; do
        n=$((n+1))
        FROM=$from TO=$to python3 "$root/port/test/mutate.py" "$RS" > "$out/mut.rs"
        build "$out/mut.rs" "$out/m$n" >/dev/null 2>&1 || { echo "mutant $name: DID NOT COMPILE"; exit 1; }
        if SC_N=200000 timeout 300 "$out/m$n/t" 0 >/dev/null 2>&1; then echo "mutant $name: *** NOT CAUGHT"; else echo "mutant $name: caught"; caught=$((caught+1)); fi
    done <<'MUT'
cap-offset~const CI_CAP: usize = 48;~const CI_CAP: usize = 52;
level-mask~cb.level & 0xffff0000~cb.level & 0x7fff0000
level-lo~max_level < cb.level~max_level <= cb.level
level-hi~max_level > (cb.level | 0xffff)~max_level >= (cb.level | 0xffff)
subleaf~let regs = cpuid_count(cb.level, cb.sub_leaf);~let regs = cpuid_count(cb.level, cb.sub_leaf.wrapping_add(1));
bit~regs[cb.reg] & (1u32 << cb.bit) != 0~regs[cb.reg] & (1u32 << (cb.bit ^ 1)) != 0
word~(bit / 64) as usize).wrapping_mul(8)~(bit / 32) as usize).wrapping_mul(4)
feature-set~set_cpu_cap(c, cb.feature as u32)~set_cpu_cap(c, cb.feature as u32 + 1)
row-apx~X86_FEATURE_APX: u16 = 681;~X86_FEATURE_APX: u16 = 680;
row-reg~CpuidBit { feature: X86_FEATURE_EPB, reg: CPUID_ECX,~CpuidBit { feature: X86_FEATURE_EPB, reg: CPUID_EDX,
row-level~CpuidBit { feature: X86_FEATURE_CAT_L3, reg: CPUID_EBX, bit: 1, level: 0x00000010,~CpuidBit { feature: X86_FEATURE_CAT_L3, reg: CPUID_EBX, bit: 1, level: 0x00000011,
row-last~X86_FEATURE_AMD_HTR_CORES, reg: CPUID_EAX, bit: 30,~X86_FEATURE_AMD_HTR_CORES, reg: CPUID_EAX, bit: 29,
MUT
    echo "sabotage: $caught of $n mutants caught"; [ "$caught" -eq "$n" ]
    exit
fi
echo "differential:"
runall "$out/real/t"
echo "PASS"
