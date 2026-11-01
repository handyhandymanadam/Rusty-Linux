#!/usr/bin/env bash
# uart-cmp.sh <C.bzImage> <R.bzImage> <outdir>  -- for each scenario boot the C-setup and Rust-setup images (KVM, SeaBIOS, parked at the
# vga=ask prompt) with uart-trace.sh and compare the complete sequence of UART-range port accesses (dir, port, size, value, ORDER):
# the baud divisor / LCR / DLAB / MCR programming that the serial log (QEMU ignores the baud) cannot show. Poll runs are collapsed (see below).
# Scenarios: env SCEN="name|cmdline" lines (default list below). Env QEMU_EXTRA_ARGS defaults to "-serial null" (a real second UART at
# 0x2f8). Env UART_PORTS adds port ranges to the trace filter. Env DET=1 first runs C twice to prove the trace is deterministic.
set -u
here=$(cd "$(dirname "$0")" && pwd); C=$1; R=$2; O=$3; mkdir -p "$O"; rc=0
export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS--serial null}"
export UART_PORTS="${UART_PORTS:-0x0-0x7 0x1230-0x123f}"
DEFAULT='e-ttyS0|earlyprintk=ttyS0,115200
e-serial3f8|earlyprintk=serial,0x3f8,115200
e-serial2f8|earlyprintk=serial,0x2f8,38400
e-ttyS1|earlyprintk=ttyS1,57600
e-serial-ttyS1|earlyprintk=serial,ttyS1,1200
e-default-baud|earlyprintk=serial
e-serial-only-comma|earlyprintk=serial,
e-0x-only|earlyprintk=serial,0x
e-0x-junk|earlyprintk=serial,0xg3f8,9600
e-0x0|earlyprintk=serial,0x0,9600
e-nocomma-baud|earlyprintk=serial,0x3f8
e-baud-hex|earlyprintk=serial,0x3f8,0x1c200
e-baud-octal|earlyprintk=ttyS0,011
e-baud-junk|earlyprintk=ttyS0,junk
e-baud-0|earlyprintk=ttyS0,0
e-baud-200000|earlyprintk=ttyS0,200000
e-baud-1|earlyprintk=ttyS0,1
e-baud-2|earlyprintk=ttyS0,2
e-baud-4294967297|earlyprintk=ttyS0,4294967297
e-baud-neg1|earlyprintk=ttyS0,0xffffffff
e-baud-intmin|earlyprintk=ttyS0,0x80000000
e-baud-trunc0|earlyprintk=ttyS0,0x100000000
e-baud-64bit|earlyprintk=ttyS0,0xffffffffffffffffff
e-ttyS|earlyprintk=ttyS
e-ttyS-comma|earlyprintk=ttyS,,115200
e-ttyS2|earlyprintk=ttyS2,4800
e-ttyS9|earlyprintk=ttyS9,4800
e-bare-0x3f8|earlyprintk=0x3f8,115200
e-bare-comma|earlyprintk=,serial,115200
e-vga|earlyprintk=vga
e-xdbg|earlyprintk=dbgp
e-port-2e8|earlyprintk=serial,0x2e8,115200
e-port-1234|earlyprintk=serial,0x1234,19200
e-port-ffff|earlyprintk=serial,0xffff,115200
e-port-10000|earlyprintk=serial,0x10000,115200
e-port-neg|earlyprintk=serial,0xffffffff,115200
e-port-0X3F8|earlyprintk=serial,0X3F8,115200
e-port-0x3f8z|earlyprintk=serial,0x3f8z,115200
e-SERIAL|earlyprintk=SERIAL,0x3f8
e-long|earlyprintk=serial,0x3f8,115200,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
e-long-trunc|earlyprintk=serial,0x3f8,11520000000000000000000000000000000000
e-trunc31|earlyprintk=ttyS1,0000000000000000000000019200
e-twice|earlyprintk=ttyS1,9600 earlyprintk=serial,0x3f8,115200
e-empty|earlyprintk=
c-uart8250-3f8|console=uart8250,io,0x3f8,115200n8
c-uart-2f8|console=uart,io,0x2f8,57600
c-probe-3f8|console=uart8250,io,0x3f8
c-probe-2f8|console=uart,io,0x2f8
c-probe-absent|console=uart,io,0x2e8
c-probe-1234|console=uart,io,0x1234
c-probe-port0|console=uart,io,0
c-probe-nonum|console=uart,io,zz
c-comma-nobaud|console=uart,io,0x3f8,
c-baud-0|console=uart,io,0x3f8,0
c-baud-big|console=uart,io,0x3f8,4294967297
c-baud-neg|console=uart,io,0x3f8,0xffffffff
c-baud-n8|console=uart8250,io,0x3f8,9600n8r
c-port-dec|console=uart,io,1016,115200
c-port-oct|console=uart,io,01770,115200
c-ttyS0|console=ttyS0,115200
c-uart8250-mmio|console=uart8250,mmio,0xfe000000,115200n8
c-uart-short|console=uart,io
c-uart-short2|console=uart8250,io,
c-prefix-case|console=UART,io,0x3f8,9600
c-long|console=uart,io,0x3f8,115200n8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
c-long-trunc|console=uart,io,0x3f8,1152000000000000000000000000000000000000000000000000000000
c-twice|console=ttyS0 console=uart,io,0x2f8,9600
c-two-uart|console=uart,io,0x2f8,9600 console=uart,io,0x3f8,19200
both|earlyprintk=ttyS1,9600 console=uart,io,0x3f8,19200
e-none-c-set|earlyprintk=vga console=uart,io,0x2f8,19200
none|quiet'
if [ "${DET:-}" = 1 ]; then
  $here/uart-trace.sh "$C" "$O/det1" 5 "vga=ask debug earlyprintk=serial,0x3f8,115200" >/dev/null
  $here/uart-trace.sh "$C" "$O/det2" 5 "vga=ask debug earlyprintk=serial,0x3f8,115200" >/dev/null
  cmp -s "$O/det1.uart" "$O/det2.uart" && echo "determinism: two C runs identical ($(wc -l < $O/det1.uart) accesses)" || { echo "determinism: C runs DIFFER"; diff "$O/det1.uart" "$O/det2.uart" | head; exit 2; }
fi
while IFS='|' read -r n c; do
  [ -z "$n" ] && continue
  for t in C R; do img=$C; [ $t = R ] && img=$R
    $here/uart-trace.sh "$img" "$O/$t-$n" "${WAIT:-5}" "vga=ask debug $c" >/dev/null
  done
  # runs of identical consecutive accesses (status-poll loops of tty.c's putchar on a port that never becomes ready: 65535 reads per
  # character, count depends on wall-clock time) are collapsed before comparing; everything else, incl. order, must match exactly.
  uniq "$O/C-$n.uart" > "$O/C-$n.uniq"; uniq "$O/R-$n.uart" > "$O/R-$n.uniq"
  if cmp -s "$O/C-$n.uniq" "$O/R-$n.uniq"; then
    echo "[$n] UART trace identical ($(wc -l < $O/R-$n.uniq) accesses after collapsing poll runs, $(grep -c '^w ' $O/R-$n.uniq) writes; raw C/R $(wc -l < $O/C-$n.uart)/$(wc -l < $O/R-$n.uart))"
  else echo "[$n] UART TRACE DIFFERS"; diff "$O/C-$n.uniq" "$O/R-$n.uniq" | head -8; rc=1; fi
done <<< "${SCEN:-$DEFAULT}"
[ $rc = 0 ] && echo "UART-CMP ALL IDENTICAL" || echo "UART-CMP DIFFERENCES"; exit $rc
