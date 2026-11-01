#!/usr/bin/env bash
# bigmem-boot.sh <bzImage> [N]: N legacy-protocol KVM boots with 12 GiB of RAM. With CONFIG_RANDOMIZE_BASE the
# stub then picks the physical load address anywhere in RAM, often above 4 GiB, where the startup page tables do not
# reach: kernel_add_identity_map() has to build NEW page-table pages (kernpg_flag, page_flag, alloc_pgt_page).
# Prints how many of the N boots reached userspace.
BZ=$1; N=${2:-10}; ok=0
RIG=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); mkdir -p $TMP/{bin,proc,sys,dev}
cp $RIG/busybox $TMP/bin/busybox; cp $RIG/init $TMP/init; ln -sf busybox $TMP/bin/sh; chmod +x $TMP/init $TMP/bin/busybox
( cd $TMP && find . | cpio -o -H newc --quiet | gzip -9 ) > $TMP.cpio.gz
for i in $(seq $N); do
  L=$(mktemp)
  timeout ${LIMIT:-40} qemu-system-x86_64 -enable-kvm -cpu host -m 12G -smp 2 -no-reboot -display none -kernel $BZ -initrd $TMP.cpio.gz \
      -append "console=ttyS0 panic=-1 loglevel=7" -serial mon:stdio < /dev/null > $L 2>&1
  grep -q "RIG: done" $L && ok=$((ok+1)); rm -f $L
done
rm -rf $TMP $TMP.cpio.gz
echo "bigmem boots reaching userspace: $ok / $N"
