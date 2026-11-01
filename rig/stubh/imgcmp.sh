#!/usr/bin/env bash
# imgcmp.sh BUILD_DIR [-jN] -- link-level proof: the stub ELF (compressed/vmlinux) and bzImage built with the
# STUBH Rust asm objects vs. with the original .S objects (make boot_asm_rust=), everything else equal.
# Leaves BUILD_DIR rebuilt with STUBH ON. Prints cmp results + a section/symbol diff of the two ELFs.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
b=$1; j=${2:--j4}; D=$root/tmp-stubh/img-$(basename "$b"); mkdir -p "$D"
C=$b/arch/x86/boot/compressed
rm -f $C/vmlinux
kmake O="$root/$b" $j >"$D/on.log" 2>&1; echo "build STUBH-on rc=$?"
cp $C/vmlinux $D/vmlinux.on; cp $b/arch/x86/boot/bzImage $D/bzImage.on
rm -f $C/vmlinux
kmake O="$root/$b" $j boot_asm_rust= >"$D/off.log" 2>&1; echo "build STUBH-off (.S objects) rc=$?"
cp $C/vmlinux $D/vmlinux.off; cp $b/arch/x86/boot/bzImage $D/bzImage.off
rm -f $C/vmlinux
kmake O="$root/$b" $j >"$D/on2.log" 2>&1; echo "restore STUBH-on rc=$?"
for f in vmlinux bzImage; do
  if cmp -s $D/$f.on $D/$f.off; then echo "$f: BYTE-IDENTICAL on/off"; else echo "$f: differ ($(cmp $D/$f.on $D/$f.off | head -1))"; fi
done
for x in on off; do
  llvm-readelf -S -W $D/vmlinux.$x | sed 's/^ *\[ *[0-9]*\]//' | grep -vE 'section headers|\.symtab|\.strtab|\.shstrtab|\.debug_|\.comment' > $D/sec.$x   # the string/symbol tables differ only by the Rust objects' FILE symbols
  llvm-nm -n $D/vmlinux.$x > $D/nm.$x
  llvm-objdump -d -r $D/vmlinux.$x | grep -v 'file format' > $D/dis.$x
done
for k in sec nm dis; do cmp -s $D/$k.on $D/$k.off && echo "$k (sections / nm -n / objdump -d -r of stub ELF): IDENTICAL" || { echo "$k: DIFFERENT"; diff $D/$k.on $D/$k.off | head -20; }; done
