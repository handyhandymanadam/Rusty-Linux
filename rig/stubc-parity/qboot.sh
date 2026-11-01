#!/usr/bin/env bash
# qboot.sh <bzImage> <log> <append...> : boot with custom cmdline, serial to log (scratch tool)
BZ=$1; LOG=$2; shift 2
RIG=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); mkdir -p $TMP/{bin,proc,sys,dev}
cp $RIG/busybox $TMP/bin/busybox; cp $RIG/init $TMP/init; ln -sf busybox $TMP/bin/sh; chmod +x $TMP/init $TMP/bin/busybox
( cd $TMP && find . | cpio -o -H newc --quiet | gzip -9 ) > $TMP.cpio.gz
KVM=""; [ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"
# BOOT_TCG=1: no KVM, QEMU's software CPU (TCG) -- stricter about some instruction semantics (STUBH).
[ -n "${BOOT_TCG:-}" ] && KVM="-accel tcg"
EFI=""
if [ -n "${BOOT_EFI:-}" ]; then O=/usr/share/edk2/ovmf; V=$(mktemp); cp $O/OVMF_VARS.fd $V
 EFI="-machine q35 -drive if=pflash,format=raw,unit=0,readonly=on,file=$O/OVMF_CODE.fd -drive if=pflash,format=raw,unit=1,file=$V"; fi
timeout ${LIMIT:-40} qemu-system-x86_64 $KVM $EFI -m 1024 -smp 2 -no-reboot -display none -kernel $BZ -initrd $TMP.cpio.gz -append "$*" -serial mon:stdio < /dev/null > $LOG 2>&1
echo "qemu-exit $?"; rm -rf $TMP $TMP.cpio.gz ${V:-}
