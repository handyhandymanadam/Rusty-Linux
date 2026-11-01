#!/usr/bin/env bash
# verify.sh STAGE... -- the STUBH boot evidence for one step (all builds -j4, one build per dir at a time).
#   fast    apply, build build-fast, boot (KVM), image-level compare on/off (imgcmp.sh)
#   tcg     boot build-fast under TCG (BOOT_TCG=1)
#   la57    boot under TCG with -cpu max (LA57 present): the stub runs its 4->5-level paging trampoline (la57toggle)
#   codec   codec-check 7/7 (Rust stub path), nproc pinned to 4
#   efi     codec-check 7/7 as EFI stub under OVMF (build-efi config)
#   norust  CONFIG_RUST=n GZIP build + boot in build-norust (STUBH block is inside ifdef CONFIG_RUST: must be unchanged)
#   parity  corrupted-payload serial matrix, C stub vs Rust stub (flip payload+14)
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; source ./kbuild-env.sh
for s in "$@"; do
  echo "=== stage $s ($(date +%T), load $(cut -d' ' -f1 /proc/loadavg))"
  case $s in
  fast)
    rig/apply.sh --check >/dev/null 2>&1 || rig/apply.sh | tail -1
    kmake O="$root/build-fast" -j4 >logs/stubh-fast.log 2>&1; echo "build-fast rc=$?"
    rig/boot.sh build-fast 200 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit'
    rig/stubh/imgcmp.sh build-fast ;;
  tcg)
    BOOT_TCG=1 rig/boot.sh build-fast 900 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit|wall' ;;
  la57)
    BOOT_TCG=1 BOOT_CPU=max rig/boot.sh build-fast 900 2>&1 | grep -E 'init|userspace |rust-ran|faults|qemu-exit|wall'
    echo "kernel log: $(grep -m2 -iE '5-level|la57|paging' logs/boot-build-fast.log | tr '\n' '|')"
    echo "cpuid la57 in guest: $(grep -c -i la57 logs/boot-build-fast.log) lines mention la57" ;;
  codec)
    taskset -c 0-3 rig/codec-check.sh 2>&1 | grep -v objtool ;;
  efi)
    mkdir -p build-codec-efi; CODEC_BASE=build-efi BOOT_EFI=1 CODEC_DIR=build-codec-efi taskset -c 0-3 rig/codec-check.sh 2>&1 | grep -v objtool ;;
  norust)
    b=build-norust; mkdir -p $b; cp build-fast/.config $b/.config
    src/linux/scripts/config --file $b/.config --disable RUST; kmake O="$root/$b" olddefconfig >/dev/null 2>&1
    echo "CONFIG_RUST=y lines: $(grep -c '^CONFIG_RUST=y' $b/.config)"
    kmake O="$root/$b" -j4 >logs/stubh-norust.log 2>&1; echo "norust build rc=$?"
    rig/boot.sh $b 200 2>&1 | grep -E 'init|userspace |faults|qemu-exit'
    echo "stub objects with STUBH rs: $(ls $b/arch/x86/boot/compressed/*_rs.o 2>/dev/null | wc -l)" ;;
  parity)
    b=build-fast; D=$root/tmp-stubh/par; rm -rf $D; mkdir -p $D
    kmake O="$root/$b" -j4 >/dev/null 2>&1; echo "rust-stub build rc=$?"
    python3 rig/stubc-parity/corrupt.py $b/arch/x86/boot/bzImage $b/arch/x86/boot/compressed/vmlinux $D/bad-rust.bz 14
    rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
    kmake O="$root/$b" -j4 boot_rust_ok= >/dev/null 2>&1; echo "C-stub build rc=$?"
    echo "C-stub rust syms: $(nm $b/arch/x86/boot/compressed/vmlinux | grep -cE '_rs|rust_')"
    python3 rig/stubc-parity/corrupt.py $b/arch/x86/boot/bzImage $b/arch/x86/boot/compressed/vmlinux $D/bad-c.bz 14
    rig/stubc-parity/matrix.sh $D; echo "matrix rc=$?"
    rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
    kmake O="$root/$b" -j4 >/dev/null 2>&1; echo "restored build rc=$?" ;;
  esac
done
echo "VERIFY-DONE $*"
