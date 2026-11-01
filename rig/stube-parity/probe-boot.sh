#!/usr/bin/env bash
# probe-boot.sh <build-dir>   (needs the pf-probe.patch applied to port/tree misc.c and the build redone)
# Boots with earlyprintk and reports whether the stub's two probes printed and userspace came up.
D=$1; L=$(mktemp)
"$(dirname "$0")/../stubc-parity/qboot.sh" "$D/arch/x86/boot/bzImage" "$L" earlyprintk=serial,ttyS0,115200 console=ttyS0 panic=-1 >/dev/null
for k in "STUBE-PROBE pf ok" "STUBE-PROBE nmi ok" "RIG: done"; do printf '%-22s %s\n' "$k" "$(grep -c "$k" "$L")"; done
rm -f "$L"
