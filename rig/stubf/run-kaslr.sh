#!/usr/bin/env bash
# run-kaslr.sh [builddir] [force]    (default build-kas; "force" adds -DCONFIG_KEXEC_HANDOVER / UNACCEPTED_MEMORY / EFI_SOFT_RESERVE
# to BOTH sides so every arm of kaslr.c is compiled and run, even ones no gate config has)
# Differential test of kaslr.c (incl. the arch/x86/lib/kaslr.c, lib/ctype.c, lib/cmdline.c it #includes): the original C, compiled
# with kbuild's command line (a COPY of the sources, only the four hardware leaf calls renamed -> kaslr_hw_*), against
# kaslr_rs.rs built with the Makefile's STUBF flags for that config + --cfg=stubf_fake_hw, plus kaslr_cfg.c. See kaslrtest.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/kbuild-env.sh"
b="$root/${1:-build-kas}"; force=${2:-}; cfgf="$b/.config"
w=$(mktemp -d "${TMPDIR:-/tmp}/stubfkaslr.XXXXXX")
has() { grep -q "^CONFIG_$1=y" "$cfgf"; }
cfg=(); defs=()
has X86_VERBOSE_BOOTUP && cfg+=(--cfg=verbose_bootup); has EFI && cfg+=(--cfg=efi)
if has UNACCEPTED_MEMORY || [ -n "$force" ]; then cfg+=(--cfg=unaccepted_memory); [ -n "$force" ] && defs+=(-DCONFIG_UNACCEPTED_MEMORY=1); fi
if has KEXEC_HANDOVER || [ -n "$force" ]; then cfg+=(--cfg=kexec_handover); [ -n "$force" ] && defs+=(-DCONFIG_KEXEC_HANDOVER=1); fi
[ -n "$force" ] && defs+=(-DCONFIG_EFI_SOFT_RESERVE=1)
if has MEMORY_HOTREMOVE && has ACPI; then cfg+=(--cfg=hotremove_acpi); fi
echo "cfgs: ${cfg[*]}  extra C defs: ${defs[*]:-none}"
src=$root/src/linux; cmp=$src/arch/x86/boot/compressed
# ---- test copy of the C source tree (only these files differ from the real ones)
mkdir -p $w/t/arch/x86/boot/compressed $w/t/arch/x86/lib $w/t/lib
cp $cmp/kaslr.c $w/t/arch/x86/boot/compressed/kaslr.c
sed -e 's/\brdtsc()/kaslr_hw_rdtsc()/; s/\brdrand_long(&raw)/kaslr_hw_rdrand_long(\&raw)/; s/\boutb(/kaslr_hw_outb(/; s/\binb(/kaslr_hw_inb(/' $src/arch/x86/lib/kaslr.c > $w/t/arch/x86/lib/kaslr.c
{ diff $src/arch/x86/lib/kaslr.c $w/t/arch/x86/lib/kaslr.c || true; } | grep -c '^>' | sed 's/^/lines changed in the test copy of arch\/x86\/lib\/kaslr.c: /'
ln -s $src/lib/ctype.c $w/t/lib/ctype.c; ln -s $src/lib/cmdline.c $w/t/lib/cmdline.c
donor="$root/build-efi/arch/x86/boot/compressed/.kaslr.o.cmd"
mk_c() { # $1 = source $2 = output ; extra args after
  local line; line=$(head -1 "$donor" | sed 's/^savedcmd_[^ ]* := //')
  line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.kaslr.o.d/}
  line=${line//-c -o arch\/x86\/boot\/compressed\/kaslr.o *\/kaslr.c/-I $cmp ${defs[*]:-} ${3:-} -c -o $2 $1}
  (cd "$b" && eval "$line")
}
mk_c $w/t/arch/x86/boot/compressed/kaslr.c $w/kaslr_c.o "-include $root/rig/stubf/fakehw.h"
sed 's|^#include "misc.h"|#include "misc.h"|' $root/port/tree/arch/x86/boot/compressed/kaslr_cfg.c > $w/kaslr_cfg.c
mk_c $root/port/tree/arch/x86/boot/compressed/kaslr_cfg.c $w/kaslr_cfg.o ""
cd "$b/arch/x86/boot/compressed"
RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
  -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
  --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" -Zdirect-access-external-data=yes "${cfg[@]}" --cfg=stubf_fake_hw \
  -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=kaslr_rs --emit=obj \
  --extern core=libcore.rlib --extern compiler_builtins=libcompiler_builtins.rlib -o "$w/kaslr_rs.o" "$root/port/tree/arch/x86/boot/compressed/kaslr_rs.rs"
echo "C object globals:";    nm "$w/kaslr_c.o"  | grep -E ' [TDRB] ' | awk '{print $3}' | sort | tr '\n' ' '; echo
echo "Rust object globals:"; nm "$w/kaslr_rs.o" | grep -E ' [TDRB] ' | awk '{print $3}' | sort | tr '\n' ' '; echo
ld -r -o $w/rs_all.o $w/kaslr_rs.o $w/kaslr_cfg.o
objcopy --prefix-symbols=c_ $w/kaslr_c.o $w/c.o; objcopy --prefix-symbols=rs_ $w/rs_all.o $w/rs.o
cc -O1 -g -o $w/kaslrtest "$root/rig/stubf/kaslrtest.c" $w/c.o $w/rs.o
$w/kaslrtest ${N:-20000}
echo "objects in $w"
