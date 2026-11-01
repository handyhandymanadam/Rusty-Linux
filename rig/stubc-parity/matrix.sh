#!/usr/bin/env bash
# matrix.sh <dirwithbad-c.bz,bad-rust.bz> : serial output of the corrupted-payload boot, C vs Rust stub, per cmdline
D=$1; SP=$(dirname $0); i=0; fail=0
while IFS= read -r cl; do
  i=$((i+1))
  for v in c rust; do LIMIT=${LIMIT:-12} $SP/qboot.sh $D/bad-$v.bz $D/m$i-$v.log "$cl" >/dev/null; done
  for v in c rust; do sed -i "s/qemu-system-x86_64: terminating on signal 15 from pid [0-9]* (timeout)//" $D/m$i-$v.log; done; if cmp -s $D/m$i-c.log $D/m$i-rust.log; then r=IDENTICAL; else r=DIFFERENT; fail=1; fi
  printf '%-10s %4s bytes (C) %4s (Rust)  cmdline: %s\n' $r $(stat -c%s $D/m$i-c.log) $(stat -c%s $D/m$i-rust.log) "$cl"
done <<'CL'
earlyprintk=serial,ttyS0,115200 console=ttyS0 panic=-1
earlyprintk=serial,0x3f8,115200 panic=-1
earlyprintk=ttyS0,115200 panic=-1
earlyprintk=serial,ttyS0 panic=-1
earlyprintk=serial,ttyS0,0 panic=-1
earlyprintk=serial,0x3f8 panic=-1
earlyprintk=serial panic=-1
console=uart8250,io,0x3f8,115200n8 panic=-1
console=uart,io,0x3f8,9600 panic=-1
console=uart,io,0x3f8 panic=-1
console=ttyS0 panic=-1
earlyprintk=serial,ttyS1,115200 panic=-1
CL
exit $fail
