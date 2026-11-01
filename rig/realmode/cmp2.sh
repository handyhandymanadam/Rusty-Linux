#!/usr/bin/env bash
# cmp2.sh <C.bzImage> <R.bzImage> <outdir>  -- boot both images from the same tree under QEMU/SeaBIOS (legacy BIOS)
# and compare: VGA text screen (vga=ask prompt, vga=ask + ENTER), serial lines (e820, "early console in setup
# code", RIG init), and the 4 KiB zero page (boot_params, located through the symbol in <img>.setup.elf, setup
# loaded at 0x10000 by QEMU). Extra scenarios: pass cmdlines in EXTRA (newline separated "name|cmdline").
# Env CMP2_ONLY_EXTRA=1 runs only the EXTRA scenarios.
# Env CMP2_SYMS="cpu:100 cpu_vendor:12" also compares those setup variables (bytes, from the memory dump at the symbol's address in each image's setup.elf).
# Env CMP2_ZP_MASK="224-225,..." masks more zero-page byte ranges (hex, inclusive), e.g. hdr.heap_end_ptr when the loader leaves header.S's link-time value (_end+512) in place.
# Env CMP2_SERIAL_FULL=1 additionally compares the complete serial output byte for byte.
# Env QEMU_CPU_ARGS overrides "-enable-kvm -cpu host" (e.g. "-cpu qemu32" = TCG, no long mode: the cpu.c error path).
set -u
here=$(cd "$(dirname "$0")" && pwd); C=$1; R=$2; O=$3; mkdir -p "$O"; rc=0
V=$here/vga2.sh
zp() { # <img.bzImage> <memfile> -> hex of boot_params
  local elf="${1%.bzImage}.setup.elf" a
  a=$(nm "$elf" | awk '$3=="boot_params"{print $1}'); python3 - "$2" "$a" <<'PY'
import sys
m=open(sys.argv[1],'rb').read(); a=int(sys.argv[2],16)   # offset inside the 0x10000 dump (seg 0x1000 -> 0 bias)
print(m[a:a+4096].hex())
PY
}
sc() { # name wait keys cmdline
  local n=$1 w=$2 k=$3; shift 3
  for t in C R; do
    img=$C; [ $t = R ] && img=$R
    $V "$img" "$O/$t-$n" "$w" "$k" "$@" > "$O/$t-$n.txt" 2>/dev/null
  done
  local ok=1
  cmp -s "$O/C-$n.txt" "$O/R-$n.txt" && echo "[$n] VGA identical ($(wc -l < $O/R-$n.txt) lines)" || { echo "[$n] VGA DIFFERS"; diff "$O/C-$n.txt" "$O/R-$n.txt" | head; ok=0; }
  f='BIOS-e820\|early console in setup\|RIG: init\|This kernel requires\|Unable to boot\|A20'
  diff <(grep -a "$f" "$O/C-$n.serial") <(grep -a "$f" "$O/R-$n.serial") >/dev/null && echo "[$n] serial key lines identical ($(grep -ac "$f" "$O/R-$n.serial"))" || { echo "[$n] SERIAL DIFFERS"; ok=0; }
  if [ -s "$O/C-$n.mem" ] && [ -s "$O/R-$n.mem" ]; then
    # zero page compare, skipping fields that legitimately differ run to run? none expected: report differing byte offsets
    python3 - <(zp $C "$O/C-$n.mem") <(zp $R "$O/R-$n.mem") "$n" <<'PY' || ok=0
import sys
a=bytes.fromhex(open(sys.argv[1]).read().strip()); b=bytes.fromhex(open(sys.argv[2]).read().strip())
# masked: hdr.kernel_version (0x20e, points at the version string, moves with the setup size) and
# hdr.ramdisk_image/size (0x218-0x21f, initrd cpio is rebuilt per run), hdr.payload_length (0x24c-0x24f: the compressed size of vmlinux,
# which kbuild relinks with a new build number/timestamp between the two bz.sh builds)
import os
extra=[tuple(int(x,16) for x in r.split('-')) for r in os.environ.get('CMP2_ZP_MASK','').split(',') if r]   # more masked ranges (hex, inclusive), e.g. "224-225"
d=[i for i in range(min(len(a),len(b))) if a[i]!=b[i] and not (0x20e<=i<=0x20f or 0x218<=i<=0x21f or 0x24c<=i<=0x24f or any(lo<=i<=hi for lo,hi in extra))]
print(f"[{sys.argv[3]}] zero page: {'identical' if not d else 'DIFFERS at '+', '.join(hex(i) for i in d[:40])} ({len(a)} bytes)")
sys.exit(1 if d else 0)
PY
  fi
  if [ -n "${CMP2_SYMS:-}" ] && [ -s "$O/C-$n.mem" ] && [ -s "$O/R-$n.mem" ]; then   # setup .bss variables, e.g. CMP2_SYMS="cpu:100 cpu_vendor:12"
    python3 - "$C" "$R" "$O/C-$n.mem" "$O/R-$n.mem" "$n" "$CMP2_SYMS" <<'PY' || ok=0
import sys,subprocess
c,r,mc,mr,n,syms=sys.argv[1:7]
def addr(img,sym):
    out=subprocess.run(['nm',img[:-8]+'.setup.elf'],capture_output=True,text=True).stdout
    for l in out.splitlines():
        f=l.split()
        if len(f)==3 and f[2]==sym: return int(f[0],16)
    raise SystemExit('symbol %s not found'%sym)
A=open(mc,'rb').read(); B=open(mr,'rb').read(); bad=0
for item in syms.split():
    sym,ln=item.split(':'); ln=int(ln); a=addr(c,sym); b=addr(r,sym)
    x=A[a:a+ln]; y=B[b:b+ln]
    print(f"[{n}] {sym} ({ln} bytes at C {a:#x} / R {b:#x}): {'identical' if x==y else 'DIFFERS'}  C={x[:24].hex()}")
    bad|= x!=y
sys.exit(1 if bad else 0)
PY
  fi
  if [ -n "${CMP2_SERIAL_FULL:-}" ]; then   # error-path boots: the whole serial stream, byte for byte
    cmp -s "$O/C-$n.serial" "$O/R-$n.serial" && echo "[$n] FULL serial identical ($(wc -c < $O/R-$n.serial) bytes)" || { echo "[$n] FULL SERIAL DIFFERS"; ok=0; }
  fi
  [ $ok = 1 ] || rc=1
}
if [ -z "${CMP2_ONLY_EXTRA:-}" ]; then   # CMP2_ONLY_EXTRA=1: skip the three base scenarios (error-path boots)
sc ask 6 - "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200"
sc ret 6 ret "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200"
sc boot 20 - "console=ttyS0 panic=-1 loglevel=7 debug earlyprintk=serial,ttyS0,115200"
fi
while IFS='|' read -r n w c k; do [ -n "$n" ] && sc "$n" "$w" "${k:--}" "$c"; done <<< "${EXTRA:-}"   # EXTRA line: name|wait|cmdline[|keys comma-separated, e.g. ret,s,c,a,n,ret]
[ $rc = 0 ] && echo "CMP2 ALL IDENTICAL" || echo "CMP2 DIFFERENCES"; exit $rc
