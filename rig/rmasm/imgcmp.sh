#!/usr/bin/env bash
# imgcmp.sh BUILD_DIR [-jN] -- link-level proof: setup.elf, setup.bin and bzImage built with the RMASM Rust asm objects vs. with the
# original .S objects (`make boot_rmasm_rust=`), everything else equal. Leaves BUILD_DIR rebuilt with RMASM ON.
# The setup objects are removed before each build (only setup.elf's inputs, not the kernel proper) so the swap is really rebuilt.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
# A relink of vmlinux bumps the build number and timestamp inside the kernel (and so the payload size in the header): pin both so
# any byte that differs between the two builds is caused by the swap and not by the clock.
export KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP='Sun Oct  4 00:00:00 UTC 2026'
b=$1; j=${2:--j4}; D=$root/tmp-rmasm/img-$(basename "$b"); mkdir -p "$D"
S=$b/arch/x86/boot
clean() { rm -f $S/setup.elf $S/setup.bin $S/bzImage $S/copy.o $S/bioscall.o $S/pmjump.o $S/header.o $S/copy_rs.o $S/bioscall_rs.o $S/pmjump_rs.o $S/header_rs.o $S/header_zo.rs; }
clean; kmake O="$root/$b" $j >"$D/on.log" 2>&1; echo "build RMASM-on rc=$?"
echo "  rust asm objects in the link: $(ls $S/copy_rs.o $S/bioscall_rs.o $S/pmjump_rs.o $S/header_rs.o 2>/dev/null | xargs -n1 basename | tr '\n' ' ')"
cp $S/setup.elf $D/setup.elf.on; cp $S/setup.bin $D/setup.bin.on; cp $S/bzImage $D/bzImage.on
clean; kmake O="$root/$b" $j boot_rmasm_rust= >"$D/off.log" 2>&1; echo "build RMASM-off (.S objects) rc=$?"
echo "  .S objects in the link: $(ls $S/copy.o $S/bioscall.o $S/pmjump.o $S/header.o 2>/dev/null | xargs -n1 basename | tr '\n' ' ')"
cp $S/setup.elf $D/setup.elf.off; cp $S/setup.bin $D/setup.bin.off; cp $S/bzImage $D/bzImage.off
clean; kmake O="$root/$b" $j >"$D/on2.log" 2>&1; echo "restore RMASM-on rc=$?"
for f in setup.bin bzImage; do
  if cmp -s $D/$f.on $D/$f.off; then echo "$f: BYTE-IDENTICAL on/off ($(stat -c %s $D/$f.on) bytes, sha256 $(sha256sum < $D/$f.on | cut -c1-16))"; else echo "$f: differ ($(cmp $D/$f.on $D/$f.off | head -1))"; fi
done
for x in on off; do
  llvm-readelf -S -W $D/setup.elf.$x | sed 's/^ *\[ *[0-9]*\]//' | grep -vE 'section headers|\.symtab|\.strtab|\.shstrtab|\.debug_|\.comment' > $D/sec.$x
  llvm-nm -n $D/setup.elf.$x > $D/nm.$x
  llvm-objdump --mattr=+16bit-mode -d -r $D/setup.elf.$x | grep -v 'file format' > $D/dis.$x
  js=$(llvm-readelf -S -W $D/setup.elf.$x | sed -n 's/^ *\[ *[0-9]*\] \(\.[a-z0-9_.]*\) .*/\1/p' | grep -vE '^\.(debug|comment|symtab|strtab|shstrtab)' | sed 's/^/-j /' | tr '\n' ' ')
  llvm-objdump -s $js $D/setup.elf.$x | grep -v 'file format' > $D/dump.$x   # contents of every non-debug section
done
for k in sec nm dis dump; do cmp -s $D/$k.on $D/$k.off && echo "$k (sections / nm -n / objdump -d -r / objdump -s of the non-debug sections of setup.elf): IDENTICAL ($(wc -l < $D/$k.on) lines)" || { echo "$k: DIFFERENT"; diff $D/$k.on $D/$k.off | head -20; }; done
