#!/usr/bin/env bash
# Userspace differential for common_rs.rs vs the real C cut out of the pristine common.c.  cpu_cmp.sh [--sabotage|--sabotage-only]   env: N cases per build, SEED
# Builds: REG_N (entries of the cpu_dev registration array: 5 = the real kernel, 12 = exactly X86_VENDOR_NUM, 16 = more than fit) x PROCESSOR_SELECT (the pr_info
# arm of early_cpu_init) x NOSLDMCA (config-fast: no sld_setup/mca_bsp_init) = 12 runs of N cases each.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); here="$root/rig/phase-e"
source "$root/kbuild-env.sh" >/dev/null 2>&1
RS=${CPU_RS:-$root/port/tree/arch/x86/kernel/cpu/common_rs.rs}
K="$root/src/linux"
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
python3 "$here/cpu_gen.py" "$root/port/pristine/arch/x86/kernel/cpu/common.c" "$out/cpu.inc" --bugs --kernel "$K" --prelude "$out/prelude.inc" --match "$out/match.inc"
sh "$K/arch/x86/kernel/cpu/mkcapflags.sh" "$out/capflags.c" "$K/arch/x86/include/asm/cpufeatures.h" "$K/arch/x86/include/asm/vmxfeatures.h"
echo "rustc: $("$KB_RUSTC" --version); cc: $(cc --version | head -1); C cut from the pristine file (only 'static' removed from 3 data objects): $(wc -l < "$out/cpu.inc") lines; x86_cap_flags from the kernel's own mkcapflags.sh: $(grep -c '\[X86_FEATURE' "$out/capflags.c") names"
for b in build-full build-fast; do g="$root/$b/arch/x86/include/generated/asm/cpufeaturemasks.h"; [ -f "$g" ] || g="/home/adam/Claude/rusty-linux-private/$b/arch/x86/include/generated/asm/cpufeaturemasks.h"
  if [ -f "$g" ]; then for m in 0 1 3; do want=$(grep "define REQUIRED_MASK$m\b" "$g" | awk '{print $3}'); have=$(grep "define REQUIRED_MASK$m " "$here/cpu_shim.h" | awk '{print $3}'); [ "$want" = "$have" ] || { echo "REQUIRED_MASK$m differs: $b $want shim $have"; exit 1; }; done; echo "REQUIRED masks 0/1/3 of $b equal the shim's"; fi; done
# the real x86_family/x86_model/x86_stepping (pristine arch/x86/lib/cpu.c)
cc -O2 -fwrapv -I"$here/cpu_stub" -DEXPORT_SYMBOL_GPL\(x\)= -c -o "$out/x86cpu.o" "$root/port/pristine/arch/x86/lib/cpu.c"
build() {  # build <rs> <exe> <reg_n> <psel 0|1> <nosldmca 0|1>
    local d="-DREG_N=$3 -DCONFIG_PROCESSOR_SELECT_V=$4" c="--cfg CONFIG_CPU_SUP_INTEL" extra=""
    [ "$4" = 1 ] && c="$c --cfg CONFIG_PROCESSOR_SELECT"
    if [ "$5" = 1 ]; then d="$d -DNOSLDMCA"; else c="$c --cfg CONFIG_X86_BUS_LOCK_DETECT --cfg CONFIG_X86_MCE"; fi
    cc -O1 -fwrapv -fno-strict-aliasing -w -I"$here" -I"$K/arch/x86/include" -I"$K/arch/x86/kernel/cpu" -DCPUINC="\"$out/cpu.inc\"" -DCAPFLAGS="\"$out/capflags.c\"" -DPRELUDE="\"$out/prelude.inc\"" -DMATCHINC="\"$out/match.inc\"" -DWITH_BUGS $d -c -o "$2.ref.o" "$here/cpu_ref.c"
    sed "s|CPURS|$1|" "$here/cpu_cmp.rs" > "$2.cmp.rs"
    "$KB_RUSTC" --edition 2021 -O -C panic=abort -C overflow-checks=on --cfg userspace_test --cfg CONFIG_X86_VMX_FEATURE_NAMES $c \
        -C relocation-model=static -C link-arg=-no-pie -C link-arg="$2.ref.o" -C link-arg="$out/x86cpu.o" --crate-name cpucmp -o "$2" "$2.cmp.rs" 2>&1 | grep -E "^error" -A8 || true
}
if [ -n "${ONLY:-}" ]; then   # ONLY="reg psel nsm": one build (used by cpu_mutants.py)
    set -- $ONLY; build "$RS" "$out/t" $1 $2 $3; [ -x "$out/t" ] || { echo "COMPILE-FAIL"; exit 3; }; timeout ${CASE_TIMEOUT:-120} "$out/t"; rc=$?; [ $rc = 124 ] && echo "HANG (the mutant loops forever: detected)"; exit $rc
fi
if [ "${1:-}" != "--sabotage-only" ]; then
for reg in 5 12 16; do for psel in 0 1; do for nsm in 0 1; do
    echo "== REG_N=$reg PROCESSOR_SELECT=$psel NOSLDMCA=$nsm"; build "$RS" "$out/t" $reg $psel $nsm; "$out/t"
done; done; done
fi
if [ "${1:-}" = "--sabotage" ] || [ "${1:-}" = "--sabotage-only" ]; then
python3 -u "$here/cpu_mutants.py" "$RS" "$out" "$KB_RUSTC" "$here" "$K"
fi
