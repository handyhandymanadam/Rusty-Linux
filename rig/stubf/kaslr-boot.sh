#!/usr/bin/env bash
# kaslr-boot.sh <builddir> <runs> [extra kernel args...]
# Boots the kernel <runs> times under qemu/KVM (legacy -kernel protocol, so the stub's extract_kernel -> choose_random_location
# runs) with a tiny initramfs that prints the kernel's physical load address (/proc/iomem "Kernel code") and virtual _text,
# then prints the distinct values. earlyprintk=ttyS0 makes the stub's own messages visible (needs X86_VERBOSE_BOOTUP for the
# "Physical KASLR using RDRAND RDTSC..." lines).
set -u
root=$(cd "$(dirname "$0")/../.." && pwd)
b=$root/$1; n=$2; shift 2
tmp=$(mktemp -d); mkdir -p $tmp/{bin,proc,sys,dev}
cp $root/rig/busybox $tmp/bin/busybox; ln -s busybox $tmp/bin/sh
cat > $tmp/init <<'EOI'
#!/bin/busybox sh
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc; mount -t sysfs sysfs /sys
echo "KASLR-PHYS $(grep -m1 'Kernel code' /proc/iomem | tr -d ' ')"
echo "KASLR-VIRT $(grep -m1 ' _text$' /proc/kallsyms)"
echo "KASLR-DONE"
poweroff -f
EOI
chmod +x $tmp/init $tmp/bin/busybox
( cd $tmp && find . | cpio -o -H newc --quiet | gzip -9 ) > $tmp.cpio.gz
KVM=""; [ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"
[ -n "${QEMU_CPU:-}" ] && KVM="-enable-kvm -cpu $QEMU_CPU"
if [ -n "${BOOT_EFI:-}" ]; then O=/usr/share/edk2/ovmf; V=$(mktemp); cp $O/OVMF_VARS.fd $V
  KVM="$KVM -machine q35 -drive if=pflash,format=raw,unit=0,readonly=on,file=$O/OVMF_CODE.fd -drive if=pflash,format=raw,unit=1,file=$V"; fi
for i in $(seq 1 $n); do
  timeout 60 qemu-system-x86_64 $KVM ${QEMU_ARGS:--m 1024 -smp 2} -no-reboot -display none -kernel $b/arch/x86/boot/bzImage -initrd $tmp.cpio.gz \
     -append "console=ttyS0 earlyprintk=ttyS0 panic=-1 $*" -serial mon:stdio < /dev/null > $tmp/log.$i 2>&1 &
  qp=$!
  for _ in $(seq 1 120); do grep -aq 'KASLR-DONE' $tmp/log.$i 2>/dev/null && break; kill -0 $qp 2>/dev/null || break; sleep 0.5; done
  kill $qp 2>/dev/null; wait $qp 2>/dev/null
  printf 'run %d: %s | %s\n' $i "$(grep -a -m1 KASLR-PHYS $tmp/log.$i)" "$(grep -a -m1 KASLR-VIRT $tmp/log.$i | cut -c1-60)"
done
cp $tmp/log.1 /tmp/kaslr-boot-log1.txt; echo "--- stub messages of run 1:"; grep -a -E 'KASLR|nokaslr|Physical|Virtual' $tmp/log.1 | head -6
echo "--- distinct physical: $(grep -ah KASLR-PHYS $tmp/log.* | sort -u | wc -l) of $n runs; distinct virtual: $(grep -ah KASLR-VIRT $tmp/log.* | sort -u | wc -l)"
rm -rf $tmp $tmp.cpio.gz
