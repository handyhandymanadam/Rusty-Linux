#!/usr/bin/env bash
# run-mem.sh [builddir]   (default build-tdx: a CONFIG_RUST build with UNACCEPTED_MEMORY + INTEL_TDX_GUEST + AMD_MEM_ENCRYPT)
# Differential test of mem.c: original C object (compiled with kbuild's command for misc.o, stub flags) vs the
# Rust mem_rs.o linked into the stub, against recording fakes of every function they call. See memtest.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
b="$root/${1:-build-tdx}"
w=$(mktemp -d "${TMPDIR:-/tmp}/stubdmem.XXXXXX")
line=$(head -1 "$b/arch/x86/boot/compressed/.misc.o.cmd" | sed 's/^savedcmd_[^ ]* := //')
for d in INFLATE_BOOT_RUST INFLATE_DRIVER_BOOT_RUST XZ_BOOT_RUST XZ_DRIVER_BOOT_RUST ZSTD_BOOT_RUST LZO_BOOT_RUST LZO_DRIVER_BOOT_RUST BZIP2_BOOT_RUST LZ4_BOOT_RUST LZ4_DRIVER_BOOT_RUST LZMA_BOOT_RUST; do line=${line//-D$d/}; done
line=${line//-c -o arch\/x86\/boot\/compressed\/misc.o *\/misc.c/-c -o $w/mem_c.o $root/src/linux/arch/x86/boot/compressed/mem.c}
line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.misc.o.d/}
(cd "$b" && eval "$line")
grep -q "CONFIG_UNACCEPTED_MEMORY=y" "$b/.config" && grep -q "CONFIG_INTEL_TDX_GUEST=y" "$b/.config" && grep -q "CONFIG_AMD_MEM_ENCRYPT=y" "$b/.config" || { echo "config lacks the three symbols"; exit 1; }
nm "$w/mem_c.o" | sed 's/^/  C   /'
nm "$b/arch/x86/boot/compressed/mem_rs.o" | sed 's/^/  RS  /'
objcopy --prefix-symbols=c_ "$w/mem_c.o" "$w/c.o"
objcopy --prefix-symbols=rs_ "$b/arch/x86/boot/compressed/mem_rs.o" "$w/rs.o"
cc -O1 -g -o "$w/memtest" "$root/rig/stubd-string/memtest.c" "$w/c.o" "$w/rs.o"
rc=0
for s in 0 1 2 3 4 5 6; do "$w/memtest" $s || rc=1; done
echo "memtest rc=$rc (objects in $w)"
exit $rc
