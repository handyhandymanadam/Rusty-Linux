#!/usr/bin/env bash
# run-efi.sh [builddir]   (default build-efi: a CONFIG_RUST build with CONFIG_EFI)
# Differential test of efi.c: the ORIGINAL C (compiled with kbuild's command line for efi.o, stub flags) against efi_rs.rs
# (rebuilt here with the Makefile's STUBF flags), twice: debug_putstr() off (CONFIG_X86_VERBOSE_BOOTUP unset) and on
# (-DCONFIG_X86_VERBOSE_BOOTUP / --cfg=verbose_bootup). Prefixed symbols c_/rs_, fakes in efitest.c.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/kbuild-env.sh"
b="$root/${1:-build-efi}"; cd "$b"
w=$(mktemp -d "${TMPDIR:-/tmp}/stubfefi.XXXXXX")
cd "$b/arch/x86/boot/compressed"
for v in off on; do
  line=$(head -1 .efi.o.cmd | sed 's/^savedcmd_[^ ]* := //')
  line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.efi.o.d/}
  line=${line//-c -o arch\/x86\/boot\/compressed\/efi.o /-c -o $w\/efi_c_$v.o }
  [ $v = on ] && line="$line -DCONFIG_X86_VERBOSE_BOOTUP=1"
  (cd "$b" && eval "$line")
  cfg=(); [ $v = on ] && cfg=(--cfg=verbose_bootup)
  RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
    -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
    --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" \
    -Zdirect-access-external-data=yes "${cfg[@]}" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=efi_rs --emit=obj \
    --extern core=libcore.rlib --extern compiler_builtins=libcompiler_builtins.rlib \
    -o "$w/efi_rs_$v.o" "$root/port/tree/arch/x86/boot/compressed/efi_rs.rs"
  echo "--- verbose=$v: C symbols:"; nm "$w/efi_c_$v.o" | grep -E ' [TtU] ' | tr '\n' ';'; echo
  echo "--- verbose=$v: Rust symbols:"; nm "$w/efi_rs_$v.o" | grep -E ' [TtU] ' | tr '\n' ';'; echo
  objcopy --prefix-symbols=c_ "$w/efi_c_$v.o" "$w/c_$v.o"
  objcopy --prefix-symbols=rs_ "$w/efi_rs_$v.o" "$w/rs_$v.o"
  cc -O1 -g -o "$w/efitest_$v" "$root/rig/stubf/efitest.c" "$w/c_$v.o" "$w/rs_$v.o"
  "$w/efitest_$v" ${N:-300000}
done
echo "objects in $w"
