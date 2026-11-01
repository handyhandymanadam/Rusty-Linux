#!/usr/bin/env bash
# la57boot.sh BUILD_DIR [extra kernel cmdline...] -- boot under TCG with -cpu max (CPUID has LA57) on a private initramfs
# that prints what the RUNNING kernel says about its paging mode: /proc/cpuinfo "la57" flag and "address sizes".
# The kernel only reports la57 if the boot stub switched it into 5-level paging, i.e. if the stub's 32-bit trampoline
# (la57toggle: trampoline_32bit_src) really ran. With `no5lvl` on the command line the stub must NOT run it.
set -u
root=$(cd "$(dirname "$0")/../.." && pwd); b=${1:?build dir}; shift
T=$(mktemp -d); mkdir -p $T/{bin,proc,sys,dev}
cp $root/rig/busybox $T/bin/busybox; ln -sf busybox $T/bin/sh
cat > $T/init <<'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc; mount -t sysfs sysfs /sys
echo "LA57-RIG: init reached"
echo "LA57-RIG: cmdline: $(cat /proc/cmdline)"
echo "LA57-RIG: cpuinfo la57 flag lines: $(grep -c ' la57' /proc/cpuinfo)"
echo "LA57-RIG: $(grep -m1 'address sizes' /proc/cpuinfo)"
echo "LA57-RIG: done"
echo o > /proc/sysrq-trigger 2>/dev/null
INIT
chmod +x $T/init $T/bin/busybox
( cd $T && find . | cpio -o -H newc --quiet | gzip -9 ) > $T.cpio.gz
LOG=$root/tmp-stubh/la57boot-$(basename $b).log
timeout ${LIMIT:-300} qemu-system-x86_64 -accel tcg -cpu max -m 1024 -smp 1 -no-reboot -display none -kernel $b/arch/x86/boot/bzImage \
  -initrd $T.cpio.gz -append "console=ttyS0 panic=-1 $*" -serial mon:stdio < /dev/null > $LOG 2>&1
echo "qemu-exit $?"; grep -a "LA57-RIG" $LOG; rm -rf $T $T.cpio.gz
