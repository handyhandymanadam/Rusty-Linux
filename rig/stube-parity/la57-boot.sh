#!/usr/bin/env bash
# la57-boot.sh <bzImage> [log]: boot under QEMU TCG with a CPU that HAS LA57 (this host's CPU does not, so
# no KVM), which makes the stub's configure_5level_paging() run its 32-bit trampoline for real
# (4- to 5-level switch). Prints what the serial log shows. ~1-3 minutes under TCG.
BZ=$1; LOG=${2:-$(mktemp)}
RIG=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); mkdir -p $TMP/{bin,proc,sys,dev}
cp $RIG/busybox $TMP/bin/busybox; cp $RIG/init $TMP/init; ln -sf busybox $TMP/bin/sh; chmod +x $TMP/init $TMP/bin/busybox
( cd $TMP && find . | cpio -o -H newc --quiet | gzip -9 ) > $TMP.cpio.gz
timeout ${LIMIT:-300} qemu-system-x86_64 -accel tcg -cpu max,la57=on -m 1024 -smp 1 -no-reboot -display none \
   -kernel $BZ -initrd $TMP.cpio.gz -append "console=ttyS0 panic=-1 loglevel=7 ${APPEND:-}" -serial mon:stdio < /dev/null > $LOG 2>&1
echo "qemu-exit $?"; rm -rf $TMP $TMP.cpio.gz
for k in "RIG: done" "RIG: rust-ran YES" "Kernel panic" "5-level"; do printf '%-22s %s\n' "$k" "$(grep -c "$k" $LOG)"; done
grep -i "5-level\|la57" $LOG | head -3
