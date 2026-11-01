#!/usr/bin/env bash
# uart-trace.sh <bzImage> <out-prefix> <wait-s> <cmdline...>  -- boot with vga2.sh (KVM) and record EVERY guest port-I/O access
# (read/write, port, size, value, in order) to the UART ranges (and any ports in env UART_PORTS="lo-hi lo-hi" extra) through the host
# kernel's kvm:kvm_pio tracepoint (this QEMU build has no serial_ioport_* trace events; the host-kernel event sees the same accesses
# the VMM would). Output <out-prefix>.uart: one line "r|w 0xPORT sSIZE 0xVAL" per access, normalised (timestamps/pids dropped).
# Use a scenario that parks the setup at the vga=ask prompt (cmdline contains vga=ask): the kernel proper never starts, so the trace
# is exactly BIOS + setup (deterministic). The per-CPU ring buffer is raised to UART_BUF_KB (default 64 MiB) because a poll loop on a port
# that never becomes ready (tty.c putchar: 65535 reads per character) makes ~10^6 events in 5 s; it is put back to 1408 KiB afterwards. Needs passwordless sudo (tracefs); serialised with flock (the tracepoint is host-global).
set -u
here=$(cd "$(dirname "$0")" && pwd); BZ=$1; OUT=$2; W=$3; shift 3
T=/sys/kernel/tracing
ranges="${UART_PORTS:-} 0x2e8-0x2ff 0x3e8-0x3ff"
filt=""; for r in $ranges; do lo=${r%-*}; hi=${r#*-}; filt="${filt:+$filt || }(port >= $lo && port <= $hi)"; done
exec 9>/tmp/uart-trace.lock; flock 9
sudo sh -c "echo 0 > $T/tracing_on; echo ${UART_BUF_KB:-65536} > $T/buffer_size_kb; echo > $T/trace; echo '$filt' > $T/events/kvm/kvm_pio/filter; echo 1 > $T/events/kvm/kvm_pio/enable; echo 1 > $T/tracing_on"
$here/vga2.sh "$BZ" "$OUT" "$W" - "$@" > "$OUT.txt" 2>/dev/null
sudo sh -c "echo 0 > $T/tracing_on; echo 0 > $T/events/kvm/kvm_pio/enable; echo 0 > $T/events/kvm/kvm_pio/filter; cat $T/trace" > "$OUT.rawtrace"
sudo sh -c "echo > $T/trace; echo 1408 > $T/buffer_size_kb; echo 1 > $T/tracing_on"
python3 - "$OUT.rawtrace" "$OUT.uart" <<'PY'
import re,sys
out=[]
for l in open(sys.argv[1]):
    m=re.search(r'pio_(read|write) at (0x[0-9a-f]+) size (\d+) count (\d+) val (0x[0-9a-f]+)',l)
    if m: out.append(f"{m[1][0]} {m[2]} s{m[3]} x{m[4]} {m[5]}")
open(sys.argv[2],'w').write("\n".join(out)+("\n" if out else ""))
print(f"{len(out)} UART-range accesses -> {sys.argv[2]}")
PY
