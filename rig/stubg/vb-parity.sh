#!/usr/bin/env bash
# vb-parity.sh <builddir> [outdir]   (a CONFIG_X86_VERBOSE_BOOTUP + EARLY_PRINTK build, e.g. build-vb)
# Serial transcripts of the Rust-stub kernel and the original-C-stub kernel (kmake boot_rust_ok=), compared byte for byte:
#  * normal boot with nokaslr (deterministic stub output) -- stub part and whole transcript (kernel timestamps stripped)
#  * normal boot with KASLR: same, with hex values masked (addresses differ per boot by design)
#  * crafted payloads that make parse_elf() fail (magic / align)
# Rebuilds the stub twice (kmake -j4); leaves the Rust build restored.
set -uo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"; cd "$root"
b=${1:-build-vb}; D=${2:-/tmp/vbpar.$$}; mkdir -p $D
bz=$b/arch/x86/boot/bzImage; sv=$b/arch/x86/boot/compressed/vmlinux
kmake O="$PWD/$b" -j4 >/dev/null 2>&1; echo "rust-stub build rc=$?"
cp $bz $D/rust.bz; cp $sv $D/rust.vmlinux
for k in magic align; do python3 rig/stubg/craft.py $D/rust.bz $D/rust.vmlinux $D/rust-$k.bz $k >/dev/null; done
rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
kmake O="$PWD/$b" -j4 boot_rust_ok= >/dev/null 2>&1; echo "C-stub build rc=$?"
echo "C-stub rust symbols in the stub: $(nm $sv | grep -cE '_rs|rust_|misc_cfg|parse_elf_rs')  (parse_elf is C: $(nm $sv | grep -c ' t parse_elf'))"
cp $bz $D/c.bz; cp $sv $D/c.vmlinux
for k in magic align; do python3 rig/stubg/craft.py $D/c.bz $D/c.vmlinux $D/c-$k.bz $k >/dev/null; done
rm -f $b/arch/x86/boot/compressed/*.o $b/arch/x86/boot/compressed/vmlinux
kmake O="$PWD/$b" -j4 >/dev/null 2>&1; echo "restored (Rust) build rc=$?"
fail=0
cmp_one() { # name image-suffix cmdline mask(0/1)
  local name=$1 suf=$2 cl=$3 mask=$4
  for v in c rust; do LIMIT=${LIMIT:-60} rig/stubc-parity/qboot.sh $D/$v$suf.bz $D/$name-$v.log "$cl" >/dev/null; \
    sed -i -E 's/qemu-system-x86_64: terminating on signal 15 from pid [0-9]* \(timeout\)//; s/^\[ *[0-9]+\.[0-9]+\] //' $D/$name-$v.log
    if [ $mask = 1 ]; then sed -i -E 's/0x[0-9a-f]+/0xHEX/g; s/[0-9a-f]{12,}/HEXLONG/g' $D/$name-$v.log; fi; done
  # (a) the stub's own output: everything before the kernel's first line, byte for byte
  for v in c rust; do sed -n '1,/^Linux version/p' $D/$name-$v.log | sed '$d' > $D/$name-$v.stub; done
  # (b) the whole transcript (lines SORTED: two CPUs interleave console output) with the lines that depend on boot timing removed (TSC/PIT/HPET calibration, BogoMIPS, lpj, clocksource, sched_clock, oops `Code:` bytes), 8+-digit hex and in-text timestamps masked
  for v in c rust; do grep -avE 'tsc|BogoMIPS|calibrate_delay|lpj=|clocksource|sched_clock|Calibrating delay|HPET|PIT|Detected .* MHz|^Code:|symbols$' $D/$name-$v.log | sed -E 's/[0-9a-f]{8,}/HEX/g; s/\[ *[0-9]+\.[0-9]+\]/[T]/g; s/HELLO [0-9]+/HELLO N/; s/CPU: [0-9]+/CPU: N/; s/swapper\/[0-9]+/swapper\/N/' | sort > $D/$name-$v.norm; done
  r1=IDENTICAL; case "$cl" in *earlyprintk*) cmp -s $D/$name-c.stub $D/$name-rust.stub || { r1=DIFFERENT; fail=1; };; *) r1=n/a;; esac
  r2=IDENTICAL; cmp -s $D/$name-c.norm $D/$name-rust.norm || { r2=DIFFERENT; fail=1; }
  printf 'stub:%-9s whole:%-9s %-22s stub %5d bytes, whole(normalised) %6d bytes (C) / %6d (Rust) [%s]\n' $r1 $r2 "$name" $(stat -c%s $D/$name-c.stub) $(stat -c%s $D/$name-c.norm) $(stat -c%s $D/$name-rust.norm) "$cl"
}
cmp_one nokaslr "" "earlyprintk=ttyS0 console=ttyS0 panic=-1 nokaslr" 0
cmp_one kaslr-masked "" "earlyprintk=ttyS0 console=ttyS0 panic=-1" 1
cmp_one noprintk "" "console=ttyS0 panic=-1 nokaslr" 0
cmp_one bad-magic -magic "earlyprintk=ttyS0 console=ttyS0 panic=-1 nokaslr" 0
cmp_one bad-align -align "earlyprintk=ttyS0 console=ttyS0 panic=-1 nokaslr" 0
# VGA text buffer (0xb8000..): the stub's __putstr also writes the screen; compare the raw 4000 bytes after the halt (crafted images)
for k in magic align; do
  for v in c rust; do LIMIT=30 rig/stubg/vga-dump.sh $D/$v-$k.bz $D/vga-$k-$v earlyprintk=ttyS0 console=ttyS0 panic=-1 nokaslr > $D/vga-$k-$v.txt; done
  if cmp -s $D/vga-$k-c.vga $D/vga-$k-rust.vga && [ -s $D/vga-$k-c.vga ]; then r=IDENTICAL; else r=DIFFERENT; fail=1; fi
  printf 'VGA:%-9s bad-%-6s text buffer %d bytes, %d text lines\n' $r $k $(stat -c%s $D/vga-$k-c.vga 2>/dev/null || echo 0) $(wc -l < $D/vga-$k-c.txt)
done
echo "--- stub part of the nokaslr transcript (Rust):"; sed -n '1,/Linux version/p' $D/nokaslr-rust.log | head -30
echo "--- error transcripts:"; tail -c 300 $D/bad-magic-rust.log; echo; tail -c 300 $D/bad-align-rust.log; echo
echo "outdir $D; fail=$fail"; exit $fail
