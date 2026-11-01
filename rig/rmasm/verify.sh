#!/usr/bin/env bash
# verify.sh -- the RMASM merge verification, for a worktree (the rig/session-tools/verify2.sh sequence with paths made relative):
#   1. codec-check 7/7 (BIOS boot, Rust path)   2. CONFIG_RUST=n builds + boots per codec, with the link inspected for the .S objects
#   3. gate: build-fast + build-full build, boot, crc-check (CRC CHANGED 0)   4. EFI (OVMF) 7/7   [parity.sh is run separately]
# Never more than -j4 (OMP_NUM_THREADS makes `nproc` say 4 for codec-check.sh).
cd "$(dirname "$0")/../.."
source ./kbuild-env.sh
export OMP_NUM_THREADS=4
rm -f logs/apply-check-*.log
rig/apply.sh 2>&1 | tail -1
echo "== codec-check (all 7, Rust path)"; rig/codec-check.sh 2>&1 | grep -v objtool
echo "== CONFIG_RUST=n for each codec: .S objects must be in the link, no *_rs.o of the setup asm"
for c in GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD; do
  b=build-codec
  cp build-fast/.config $b/.config
  for o in GZIP BZIP2 LZMA XZ LZO LZ4 ZSTD; do sed -i "/^CONFIG_KERNEL_$o=/d;/^# CONFIG_KERNEL_$o is not set/d" $b/.config; done
  echo "CONFIG_KERNEL_$c=y" >> $b/.config; echo "CONFIG_RD_$c=y" >> $b/.config
  src/linux/scripts/config --file $b/.config --disable RUST
  kmake O="$PWD/$b" olddefconfig >/dev/null 2>&1
  r=$(grep -c '^CONFIG_RUST=y' $b/.config)
  kmake O="$PWD/$b" -j4 > $b/norust-$c.log 2>&1; rc=$?
  S=$b/arch/x86/boot
  objs="S-objs: $(ls -1 $S/copy.o $S/bioscall.o $S/pmjump.o $S/header.o 2>/dev/null | wc -l)/4 rs-objs: $(ls -1 $S/copy_rs.o $S/bioscall_rs.o $S/pmjump_rs.o $S/header_rs.o 2>/dev/null | wc -l)"
  if [ $rc != 0 ]; then v="BUILD FAILED (not booting a stale image)"; else v=$(rig/boot.sh $b 200 2>&1 | grep -E 'init |userspace ' | tr -s ' ' | tr '\n' ';'); fi
  echo "norust $c: RUST=y lines=$r build rc=$rc $objs $v"
done
echo "== gate"
for b in build-fast build-full; do
  kmake O="$PWD/$b" -j4 2>&1 | grep -E 'error|Kernel:' | tail -3
  echo "$b build rc=${PIPESTATUS[0]}"
  rig/boot.sh $b 180 2>&1 | grep -E 'init|userspace|rust-ran|faults'
  rig/crc-check.sh $b 2>&1 | tail -5
done
echo "== EFI (OVMF) all 7, restored"
CODEC_BASE=build-efi BOOT_EFI=1 CODEC_DIR=build-codec-efi rig/codec-check.sh 2>&1 | grep -v objtool
echo RMASM-VERIFY-DONE
