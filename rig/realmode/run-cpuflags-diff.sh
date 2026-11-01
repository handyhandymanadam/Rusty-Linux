#!/usr/bin/env bash
# run-cpuflags-diff.sh [scenarios-per-variant] [seed] -- lockstep differential of cpuflags_rs.rs against the original
# arch/x86/boot/cpuflags.c, both built for the HOST against one device model (cr0, x87 probe, EFLAGS, cpuid; cpuflags-diff.c).
# Variants: x64 (this build: has_eflag is the inline `true`) and i386 (CONFIG_X86_32: the real has_eflag, driven by a modelled EFLAGS).
# Changes to the C copy (each asserted): the five asm statements (mov cr0 x2, fninit/fnstsw/fnstcw, the has_eflag pushf/popf block,
# cpuid) -> calls of the device model; `static bool loaded_flags` -> a global, so the rig can reset it. Names are prefixed c_ by -D.
# The Rust is built with --cfg host_mock (the same asm points as extern hooks) and, for i386, --cfg rm_x86_32 + a gen file with
# CONFIG_X86_64 off. Env: SABOTAGE=<sed expr> on a copy of the Rust (tree untouched); VARIANTS="x64 i386".
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
N=${1:-20000}; SEED=${2:-1}
SRC=$root/src/linux-6.18.49; B=$root/build-fast; P=$root/port/tree/arch/x86/boot
T=$(mktemp -d); trap 'rm -rf $T' EXIT
KINC="-I$SRC/arch/x86/include -I$SRC/include -I$SRC/arch/x86/include/uapi -I$SRC/include/uapi -I$SRC/tools/include -I$B/arch/x86/include/generated -I$B/include/generated/uapi -I$B/arch/x86/include/generated/uapi"
python3 - "$SRC/arch/x86/boot/cpuflags.c" "$T/cpuflags_c.c" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
def sub(pat,rep):
    global s
    s,n=re.subn(pat,rep,s,flags=re.S); assert n==1,(pat,n)
sub(r'asm volatile\("mov %%cr0,%0" : "=r" \(cr0\)\);','cr0 = mock_read_cr0();')
sub(r'asm volatile\("mov %0,%%cr0" : : "r" \(cr0\)\);','mock_write_cr0(cr0);')
sub(r'asm volatile\("fninit ; fnstsw %0 ; fnstcw %1"\s*: "\+m" \(fsw\), "\+m" \(fcw\)\);','mock_fpu(&fsw, &fcw);')
sub(r'asm volatile\("pushfl\t\\n\\t".*?: "ri" \(mask\)\);','f0 = mock_eflags_get(); mock_eflags_set(f0 ^ mask); f1 = mock_eflags_get(); mock_eflags_set(f0);')
sub(r'asm volatile\("cpuid"\s*: "=a" \(\*a\), "=b" \(\*b\), "=c" \(\*c\), "=d" \(\*d\)\s*: "0" \(id\), "2" \(count\)\s*\);','mock_cpuid(id, count, a, b, c, d);')
sub(r'static bool loaded_flags;','bool loaded_flags;')
open(sys.argv[2],'w').write(s)
PY
printf '%s\n' '#include <linux/types.h>' \
  'unsigned mock_read_cr0(void); void mock_write_cr0(unsigned); void mock_fpu(unsigned short *, unsigned short *);' \
  'unsigned mock_eflags_get(void); void mock_eflags_set(unsigned); void mock_cpuid(u32,u32,u32*,u32*,u32*,u32*);' > $T/mock.h
cp "$P/cpuflags_rs.rs" "$T/cpuflags_rs.rs"
if [ -n "${SABOTAGE:-}" ]; then
  sed -i "$SABOTAGE" "$T/cpuflags_rs.rs"
  cmp -s "$T/cpuflags_rs.rs" "$P/cpuflags_rs.rs" && { echo "SABOTAGE changed nothing"; exit 3; }
  echo "SABOTAGE applied: $SABOTAGE"
fi
rc=0
for V in x64 i386; do
  case " ${VARIANTS:-x64 i386} " in *" $V "*) ;; *) continue;; esac
  D=$T/$V; mkdir -p $D
  if [ $V = i386 ]; then I3=1; CC32="-DCONFIG_X86_32=1"; RCFG="--cfg rm_x86_32"; else I3=0; CC32=""; RCFG=""; fi
  # gen file: same recipe as the Makefile; i386 flips the config switch (autoconf of this tree is x86-64)
  clang $KINC -include $B/include/generated/autoconf.h -D__KERNEL__ -E -P -x c "$P/cpucheck_gen.rs.in" 2>/dev/null | sed -n -e 's/\(0x[0-9a-fA-F]*\|[0-9][0-9]*\)\(UL\|U\|L\)\b/\1/g' -e '/^pub const/p' > $D/cpucheck_gen.rs
  if [ $V = i386 ]; then sed -i 's/IS_X86_64: bool = true/IS_X86_64: bool = false/' $D/cpucheck_gen.rs; fi
  NC=$(sed -n 's/.*RM_NCAPINTS: usize = \(.*\);/\1/p' $D/cpucheck_gen.rs)
  clang -O1 -w -fwrapv -ffreestanding -D__KERNEL__ -D_SETUP $CC32 -include $T/mock.h \
     -Dcpu=c_cpu -Dcpu_vendor=c_cpu_vendor -Dget_cpuflags=c_get_cpuflags -Dcpuid_count=c_cpuid_count -Dhas_eflag=c_has_eflag -Dloaded_flags=c_loaded_flags \
     -I$SRC/arch/x86/boot $KINC -c $T/cpuflags_c.c -o $D/c.o
  RM_GEN_DIR=$D RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=lib --emit=obj -C opt-level=2 -C panic=abort -C debug-assertions=off -C overflow-checks=off \
    -Zcrate-attr=no_std --cfg host_mock $RCFG --crate-name=cpuflags_rs -o $D/rs.o $T/cpuflags_rs.rs 2>&1 | grep -E "^error" -A8 || true
  clang -O2 -w -DRIG_NCAPINTS=$NC -DRIG_I386=$I3 "$here/cpuflags-diff.c" $D/c.o $D/rs.o -o $D/h
  echo "=== $V: i386=$I3 NCAPINTS=$NC"
  "$D/h" "$N" "$((SEED * 7919 + I3))" || rc=1
done
[ $rc = 0 ] && echo "CPUFLAGS-DIFF OK" || echo "CPUFLAGS-DIFF MISMATCHES"
exit $rc
