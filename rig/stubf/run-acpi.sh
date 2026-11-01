#!/usr/bin/env bash
# run-acpi.sh [builddir]   (default build-kas)
# Differential test of acpi.c: ORIGINAL C (kbuild's command line for acpi.o, stub flags; a COPY of the source whose only change is
# ACPI_EBDA_PTR_LOCATION 0x40E -> 0x1040E, see acpitest.c) vs acpi_rs.rs built with the Makefile's STUBF flags for that config
# (+ --cfg=stubf_test_ebda for the same address). The cfg set is derived from the build's .config exactly as the Makefile does.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/kbuild-env.sh"
b="$root/${1:-build-kas}"; cfgf="$b/.config"
w=$(mktemp -d "${TMPDIR:-/tmp}/stubfacpi.XXXXXX")
has() { grep -q "^CONFIG_$1=y" "$cfgf"; }
cfg=(); has X86_VERBOSE_BOOTUP && cfg+=(--cfg=verbose_bootup); has EFI && cfg+=(--cfg=efi)
hot=0; if has RANDOMIZE_BASE && has MEMORY_HOTREMOVE; then cfg+=(--cfg=hotremove_srat); hot=1; fi
has KEXEC_CORE && cfg+=(--cfg=kexec_core)
shift_=$(sed -n 's/^CONFIG_NODES_SHIFT=//p' "$cfgf"); shift_=${shift_:-0}
echo "cfgs: ${cfg[*]}  NODES_SHIFT=$shift_ hotremove=$hot"
src=$root/src/linux/arch/x86/boot/compressed
sed 's|^#include <linux/numa.h>|#include <linux/numa.h>\n#undef ACPI_EBDA_PTR_LOCATION\n#define ACPI_EBDA_PTR_LOCATION 0x1040E|' $src/acpi.c > $w/acpi_test.c
grep -q 'define ACPI_EBDA_PTR_LOCATION 0x1040E' $w/acpi_test.c
line=$(head -1 "$root/build-efi/arch/x86/boot/compressed/.acpi.o.cmd" | sed 's/^savedcmd_[^ ]* := //')
line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.acpi.o.d/}
line=${line//-c -o arch\/x86\/boot\/compressed\/acpi.o *\/acpi.c/-I $src -c -o $w/acpi_c.o $w/acpi_test.c}
(cd "$b" && eval "$line")
cd "$b/arch/x86/boot/compressed"
STUBF_NODES_SHIFT=$(sed -n 's/^CONFIG_NODES_SHIFT=//p' "$cfgf") RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
  -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
  --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" -Zdirect-access-external-data=yes "${cfg[@]}" --cfg=stubf_test_ebda \
  -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=acpi_rs --emit=obj \
  --extern core=libcore.rlib --extern compiler_builtins=libcompiler_builtins.rlib -o "$w/acpi_rs.o" "$root/port/tree/arch/x86/boot/compressed/acpi_rs.rs"
echo "C symbols:";  nm -S "$w/acpi_c.o" | grep -E ' [TtUBbDd] ' | sed 's/^/  /'
echo "Rust symbols:"; nm -S "$w/acpi_rs.o" | grep -E ' [TtUBbDd] ' | sed 's/^/  /'
if [ $hot = 1 ]; then
  cs=$(nm -S "$w/acpi_c.o" | awk '$4=="immovable_mem"{print $2}'); rsz=$(nm -S "$w/acpi_rs.o" | awk '$4=="immovable_mem"{print $2}')
  echo "immovable_mem size C=$cs Rust=$rsz"; [ "$cs" = "$rsz" ] || { echo "FAIL: immovable_mem size differs"; exit 1; }
fi
objcopy --prefix-symbols=c_ "$w/acpi_c.o" "$w/c.o"; objcopy --prefix-symbols=rs_ "$w/acpi_rs.o" "$w/rs.o"
def=(); [ $hot = 1 ] && def=(-DHOTREMOVE)
cc -O1 -g "${def[@]}" -DIMM_ENTRIES=$((2 << shift_)) -o "$w/acpitest" "$root/rig/stubf/acpitest.c" "$w/c.o" "$w/rs.o"
"$w/acpitest" ${N:-100000}
echo "objects in $w"
