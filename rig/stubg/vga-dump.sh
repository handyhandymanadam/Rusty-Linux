#!/usr/bin/env bash
# vga-dump.sh <bzImage> <out-prefix> <cmdline...>  -- boot (legacy -kernel protocol, std VGA), wait until the serial log shows the
# stub halted ("System halted") or LIMIT seconds, then dump the 80x25 text buffer (0xb8000, 4000 bytes) through the QEMU monitor
# and print it as text. Used on the crafted bad-ELF images, where the stub stops with its message on screen.
BZ=$1; OUT=$2; shift 2
RIG=$(cd "$(dirname "$0")/.." && pwd); TMP=$(mktemp -d); mkdir -p $TMP/{bin,proc,sys,dev}
cp $RIG/busybox $TMP/bin/busybox; cp $RIG/init $TMP/init; ln -sf busybox $TMP/bin/sh; chmod +x $TMP/init $TMP/bin/busybox
( cd $TMP && find . | cpio -o -H newc --quiet | gzip -9 ) > $TMP.cpio.gz
KVM=""; [ -w /dev/kvm ] && KVM="-enable-kvm -cpu host"
rm -f $OUT.vga $OUT.serial
qemu-system-x86_64 $KVM -m 1024 -smp 2 -no-reboot -display none -vga std -kernel $BZ -initrd $TMP.cpio.gz -append "$*" \
   -serial file:$OUT.serial -monitor unix:$TMP/mon,server,nowait < /dev/null > /dev/null 2>&1 &
qp=$!
for _ in $(seq 1 ${LIMIT:-40}); do grep -aq "System halted" $OUT.serial 2>/dev/null && break; sleep 0.5; done
sleep 1
( sleep 1; printf 'pmemsave 0xb8000 4000 \"%s.vga\"\n' $OUT; sleep 2; printf 'quit\n'; sleep 1 ) | ncat -U $TMP/mon > /dev/null 2>&1
sleep 1; kill $qp 2>/dev/null; wait $qp 2>/dev/null
python3 - "$OUT.vga" <<'PY'
import sys
b = open(sys.argv[1], 'rb').read()
for r in range(25):
    line = bytes(b[(r * 80 + c) * 2] for c in range(80)).decode('latin1').rstrip()
    if line.strip(): print(f'{r:2}|{line}')
PY
rm -rf $TMP $TMP.cpio.gz
