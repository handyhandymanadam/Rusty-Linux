#!/usr/bin/env bash
# vga.sh <bzImage> <out> <wait-s> "<keys comma-sep or ->" <cmdline...>
# Env DUMP_BASE (default 0x10000): guest-physical base of the 64 KiB setup dump (<out>.mem); a protocol 2.00/2.01 header makes QEMU load the setup at 0x90000.
# Env QEMU_CPU_ARGS replaces "-enable-kvm -cpu host"; QEMU_EXTRA_ARGS (word-split) is appended at the END of the qemu command line, after the first -serial (so "-serial null" = a second UART at 0x2f8).
BZ=$1; OUT=$2; W=$3; KEYS=$4; shift 4
TMP=$(mktemp -d); mkdir -p $TMP/{bin,proc,sys,dev}
RIG=$(cd "$(dirname "$0")/.." && pwd)
cp $RIG/busybox $TMP/bin/busybox; cp $RIG/init $TMP/init; ln -sf busybox $TMP/bin/sh; chmod +x $TMP/init $TMP/bin/busybox
( cd $TMP && find . | cpio -o -H newc --quiet | gzip -9 ) > $TMP.cpio.gz
rm -f $OUT.mem $OUT.vga $OUT.serial
qemu-system-x86_64 ${QEMU_CPU_ARGS:--enable-kvm -cpu host} -m 1024 -smp 2 -no-reboot -display none -vga std -kernel $BZ -initrd $TMP.cpio.gz -append "$*" \
  -serial file:$OUT.serial -monitor unix:$TMP/mon,server,nowait ${QEMU_EXTRA_ARGS:-} </dev/null >/dev/null 2>&1 &
qp=$!
python3 - $TMP/mon $W "$KEYS" $OUT <<'PY'
import socket,sys,time
path,w,keys,out=sys.argv[1],float(sys.argv[2]),sys.argv[3],sys.argv[4]
for _ in range(50):
    try:
        s=socket.socket(socket.AF_UNIX); s.connect(path); break
    except Exception: time.sleep(0.2)
def cmd(c):
    s.sendall((c+"\n").encode()); time.sleep(0.5)
time.sleep(w)
if keys!='-':
    for k in keys.split(','):
        cmd("sendkey "+k); time.sleep(1)
    time.sleep(1)
try:
  pass
except Exception: pass
import os
cmd('pmemsave %s 0x10000 "%s.mem"'%(os.environ.get('DUMP_BASE','0x10000'),out))
cmd('pmemsave 0xb8000 4000 "%s.vga"'%out)
time.sleep(1)
cmd('quit')
PY
sleep 1; kill $qp 2>/dev/null; wait $qp 2>/dev/null
python3 - $OUT.vga <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
for r in range(25):
    line=bytes(b[(r*80+c)*2] for c in range(80)).decode('latin1').rstrip()
    if line.strip(): print(f'{r:2}|{line}')
PY
rm -rf $TMP $TMP.cpio.gz
