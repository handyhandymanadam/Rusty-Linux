#!/usr/bin/env bash
# run-cpu-diff.sh [scenarios-per-variant] [seed] -- lockstep differential of cpu_rs.rs + cpucheck_rs.rs against the original
# arch/x86/boot/cpu.c + cpucheck.c, both built for the HOST against the device model of cpu-diff.c (random CPU, MSRs, console).
# Variants (build configurations): v0 = this tree's real build (X86_64, real REQUIRED masks, real cpustr table); v1..v5 = other
# configurations with random REQUIRED masks (i386 non-PAE: the Xeon Phi text; i386 PAE; x86-64; unnamed required bits ->
# "%d:%d " words; required bits in words the check does not test). For each variant the Rust is built from the same
# cpucheck_gen.rs.in / cpustr recipe as the Makefile, the C from the original sources.
# Changes to the C copies (each asserted): cpucheck.c's `asm("cpuid" ...)` statement -> mock_cpuid1(); the three CONFIG_* uses ->
# V_* macros (so 32-bit variants can be built); cpu.c gets c_show_cap_strs() appended (the static walker, for direct testing).
# Env: SABOTAGE=<sed expr> applies to copies of both Rust files (the tree is untouched); VARIANTS="v0 v1 .." selects variants.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
N=${1:-20000}; SEED=${2:-1}
SRC=$root/src/linux-6.18.49; B=$root/build-fast; P=$root/port/tree/arch/x86/boot
T=$(mktemp -d); trap 'rm -rf $T' EXIT
KINC="-I$SRC/arch/x86/include -I$SRC/include -I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$SRC/tools/include -I$B/arch/x86/include/generated -I$B/include/generated/uapi -I$B/arch/x86/include/generated/uapi"
# --- C copies with the documented edits
cp "$SRC/arch/x86/boot/cpucheck.c" "$T/cpucheck_c.c"; cp "$SRC/arch/x86/boot/cpu.c" "$T/cpu_c.c"
python3 - "$T" <<'PY'
import re,sys
t=sys.argv[1]; p=t+'/cpucheck_c.c'; s=open(p).read(); o=s
s,n=re.subn(r'asm\("cpuid"[^;]*;', 'mock_cpuid1(level, &cpu.flags[0]);', s); assert n==1
s,n=re.subn(r'IS_ENABLED\(CONFIG_X86_64\) \|\| IS_ENABLED\(CONFIG_X86_PAE\)', '(V_X86_64 || V_X86_PAE)', s); assert n==1
s,n=re.subn(r'CONFIG_X86_MINIMUM_CPU_FAMILY', 'V_MINFAM', s); assert n==1
s=s.replace('int check_cpu(','unsigned mock_cpuid1(unsigned, unsigned *);\nint check_cpu(',1)
s+='\n_Static_assert(sizeof(cpu) == 12 + 4 * NCAPINTS, "struct cpu_features layout");\n'
open(p,'w').write(s)
p=t+'/cpu_c.c'; s=open(p).read(); s+='\nvoid c_show_cap_strs(const u32 *p) { show_cap_strs((u32 *)p); }\n'; open(p,'w').write(s)
PY
cp "$P"/{cpu_rs.rs,cpucheck_rs.rs} "$T/"
if [ -n "${SABOTAGE:-}" ]; then
  sed -i "$SABOTAGE" "$T/cpu_rs.rs" "$T/cpucheck_rs.rs"
  cmp -s "$T/cpu_rs.rs" "$P/cpu_rs.rs" && cmp -s "$T/cpucheck_rs.rs" "$P/cpucheck_rs.rs" && { echo "SABOTAGE changed nothing"; exit 3; }
  echo "SABOTAGE applied: $SABOTAGE"
fi
# --- variants: name x86_64 pae minfam maskseed
VARIANTS_ALL="v0|1|0|64|0 v1|0|0|5|11 v2|0|1|6|12 v3|1|0|64|13 v4|1|0|64|14 v5|0|0|6|15"
rc=0
for spec in $VARIANTS_ALL; do
  IFS='|' read -r V X64 PAE MINF MSEED <<< "$spec"
  case " ${VARIANTS:-v0 v1 v2 v3 v4 v5} " in *" $V "*) ;; *) continue;; esac
  D=$T/$V; mkdir -p $D/asm
  if [ "$MSEED" = 0 ]; then cp "$B/arch/x86/include/generated/asm/cpufeaturemasks.h" $D/asm/
  else python3 - "$D/asm/cpufeaturemasks.h" "$MSEED" <<'PY'
import random,sys
r=random.Random(int(sys.argv[2])); out=['#ifndef _ASM_X86_CPUFEATUREMASKS_H','#define _ASM_X86_CPUFEATUREMASKS_H']
for w in range(22):
    dens=0.4 if w in (0,1,4,6,16) else 0.2
    m=0
    for b in range(32):
        if r.random()<dens: m|=1<<b
    if w==0:
        for b in (25,26,8,6):
            if r.random()<0.7: m|=1<<b
    if w==1 and r.random()<0.7: m|=1<<29
    if int(sys.argv[2]) in (11,15):   # these variants: LM not required, PAE required (Pentium M branch reachable)
        if w==1: m&=~(1<<29)
        if w==0: m|=1<<6
    out.append('#define REQUIRED_MASK%d\t0x%08xU'%(w,m))
out.append('#endif'); open(sys.argv[1],'w').write('\n'.join(out)+'\n')
PY
  fi
  CFG="-DCONFIG_X86_MINIMUM_CPU_FAMILY=$MINF"; [ $X64 = 1 ] && CFG="$CFG -DCONFIG_X86_64=1"; [ $PAE = 1 ] && CFG="$CFG -DCONFIG_X86_PAE=1"
  # cpucheck_gen.rs: same recipe as the Makefile (cpp, keep `pub const` lines, strip C suffixes)
  clang -I$D $KINC $CFG -D__KERNEL__ -E -P -x c "$P/cpucheck_gen.rs.in" 2>/dev/null | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > $D/cpucheck_gen.rs
  # cpustr.bin: the real mkcpustr output compiled with this variant's masks, .rodata -> raw bytes (as cpustr_blob.o + objcopy)
  "$B/arch/x86/boot/mkcpustr" > $D/cpustr.h
  printf '#define static\n#include "cpustr.h"\n' > $D/blob.c
  clang -I$D $KINC -D__KERNEL__ -O1 -w -c $D/blob.c -o $D/blob.o && objcopy -O binary -j .rodata $D/blob.o $D/cpustr.bin
  if [ "$V" = v0 ]; then
    cmp "$D/cpustr.bin" "$B/arch/x86/boot/cpustr.bin" && echo "v0: cpustr.bin identical to the build's ($(stat -c %s $D/cpustr.bin) bytes)"
    cmp "$D/cpucheck_gen.rs" "$B/arch/x86/boot/cpucheck_gen.rs" && echo "v0: cpucheck_gen.rs identical to the build's"
  fi
  R0=$(sed -n 's/.*RM_REQUIRED_MASK0: u32 = \(.*\);/\1/p' $D/cpucheck_gen.rs); R1=$(sed -n 's/.*RM_REQUIRED_MASK1: u32 = \(.*\);/\1/p' $D/cpucheck_gen.rs)
  R4=$(sed -n 's/.*RM_REQUIRED_MASK4: u32 = \(.*\);/\1/p' $D/cpucheck_gen.rs); R6=$(sed -n 's/.*RM_REQUIRED_MASK6: u32 = \(.*\);/\1/p' $D/cpucheck_gen.rs)
  R16=$(sed -n 's/.*RM_REQUIRED_MASK16: u32 = \(.*\);/\1/p' $D/cpucheck_gen.rs); NC=$(sed -n 's/.*RM_NCAPINTS: usize = \(.*\);/\1/p' $D/cpucheck_gen.rs)
  CC1="clang -O1 -w -fwrapv -ffreestanding -D__KERNEL__ -D_SETUP -DV_X86_64=$X64 -DV_X86_PAE=$PAE -DV_MINFAM=$MINF -Dcheck_cpu=c_check_cpu -Dcheck_knl_erratum=c_check_knl_erratum -Dvalidate_cpu=c_validate_cpu -I$here/inc-cpu -I$D -I$SRC/arch/x86/boot $KINC"
  $CC1 -c $T/cpucheck_c.c -o $D/cpucheck_c.o; $CC1 -c $T/cpu_c.c -o $D/cpu_c.o
  for f in cpucheck_rs cpu_rs; do
    RM_GEN_DIR=$D RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=lib --emit=obj -C opt-level=2 -C panic=abort -C debug-assertions=off -C overflow-checks=off \
      -Zcrate-attr=no_std --cfg host_mock --crate-name=$f -o $D/$f.o $T/$f.rs 2>&1 | grep -E "^error" -A8 || true
  done
  clang -O2 -w -DRIG_NCAPINTS=$NC -DRIG_X86_64=$X64 -DRIG_R0=$R0 -DRIG_R1=$R1 -DRIG_R4=$R4 -DRIG_R6=$R6 -DRIG_R16=$R16 "$here/cpu-diff.c" \
    $D/cpu_c.o $D/cpucheck_c.o $D/cpu_rs.o $D/cpucheck_rs.o -o $D/h
  echo "=== $V: X86_64=$X64 PAE=$PAE min family=$MINF masks 0=$R0 1=$R1 4=$R4 6=$R6 16=$R16"
  "$D/h" "$N" "$((SEED * 7919 + MSEED))" "$D/cpustr.bin" || rc=1
done
[ $rc = 0 ] && echo "CPU-DIFF OK" || echo "CPU-DIFF MISMATCHES"
exit $rc
