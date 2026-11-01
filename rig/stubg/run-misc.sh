#!/usr/bin/env bash
# run-misc.sh [builddir [N]]   (default build-efi: RELOCATABLE + X86_NEED_RELOCS; build-fast: neither)
# Differential test of misc.c's parse_elf()/handle_relocations(): the ORIGINAL C (port/pristine misc.c, compiled with the
# build's own kbuild flags minus every *_BOOT_RUST define) against misc_rs.rs built with the Makefile's STUBG flags,
# twice (debug_putstr() off / on). Synthetic images; whole-arena, return value, __putstr/error text and heap state compared.
# RS_SRC=<file> tests another copy of the Rust (sabotage runs).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
b="$root/${1:-build-efi}"; n=${2:-${N:-100000}}; rs_src=${RS_SRC:-$root/port/tree/arch/x86/boot/compressed/misc_rs.rs}
w=$(mktemp -d "${TMPDIR:-/tmp}/stubgmisc.XXXXXX"); mkdir -p $w/compressed
cp "$root/port/pristine/arch/x86/boot/compressed/misc.c" $w/compressed/misc_orig.c
# the C's own __putstr() would drive the UART/VGA; rename its DEFINITION so the call sites reach the test's recording fake
n_ren=$(grep -c '^void __putstr(const char \*s)$' $w/compressed/misc_orig.c); [ "$n_ren" = 1 ] || { echo "putstr rename matched $n_ren"; exit 2; }
sed -i 's/^void __putstr(const char \*s)$/void __putstr_orig(const char *s)/' $w/compressed/misc_orig.c
# a voffset.h of the test's own: text_to_bss_start = 0x8000, same numbers as the fake misc_cfg consts in misctest.c
cat > $w/voffset.h <<'EOH'
#define VO___bss_start _AC(0xffffffff81008000,UL)
#define VO___inittext_end _AC(0xffffffff81003000,UL)
#define VO___start_rodata _AC(0xffffffff81002000,UL)
#define VO__end _AC(0xffffffff81009000,UL)
#define VO__sinittext _AC(0xffffffff81001000,UL)
#define VO__text _AC(0xffffffff81000000,UL)
EOH
cat > $w/compressed/ref.c <<'EOR'
#include "misc_orig.c"
size_t ref_parse_elf(void *o) { return parse_elf(o); }
void ref_handle_relocations(void *o, unsigned long l, unsigned long v) { handle_relocations(o, l, v); }
unsigned long ref_heap_state(void) { return malloc_ptr ^ ((unsigned long)malloc_count << 56); }
void ref_heap_reset(void) { malloc_ptr = 0; malloc_count = 0; }
EOR
relocs=""; grep -q '^CONFIG_X86_NEED_RELOCS=y' $b/.config && relocs=-DHAVE_RELOCS
reloc_cfg=(); grep -q '^CONFIG_X86_NEED_RELOCS=y' $b/.config && reloc_cfg+=(--cfg=need_relocs)
grep -q '^CONFIG_RELOCATABLE=y' $b/.config && reloc_cfg+=(--cfg=relocatable)
for v in off on; do
  line=$(head -1 $b/arch/x86/boot/compressed/.misc.o.cmd | sed 's/^savedcmd_[^ ]* := //')
  line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.misc.o.d/}
  line=$(echo "$line" | sed -E 's/-D[A-Z0-9_]*BOOT_RUST//g; s# -c -o [^ ]* [^ ]*misc\.c# -c -o '$w'/c_'$v'.o '$w'/compressed/ref.c -I'$w'/compressed#')
  [ $v = on ] && line="$line -DCONFIG_X86_VERBOSE_BOOTUP=1"
  (cd "$b" && eval "$line")
  cfg=(); [ $v = on ] && cfg=(--cfg=verbose_bootup)
  RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
    -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
    --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" \
    -Zdirect-access-external-data=yes "${cfg[@]}" "${reloc_cfg[@]}" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=misc_rs --emit=obj \
    --extern core=$b/arch/x86/boot/compressed/libcore.rlib --extern compiler_builtins=$b/arch/x86/boot/compressed/libcompiler_builtins.rlib \
    -o "$w/misc_rs_$v.o" "$rs_src"
  echo "--- verbose=$v relocs=${relocs:-none}: Rust undefined: $(nm -u $w/misc_rs_$v.o | awk '{print $2}' | tr '\n' ' ')"
  objcopy --prefix-symbols=c_ "$w/c_$v.o" "$w/cp_$v.o"
  objcopy --prefix-symbols=rs_ "$w/misc_rs_$v.o" "$w/rs_$v.o"
  cc -O1 -g $relocs -c -o "$w/t_$v.o" "$root/rig/stubg/misctest.c"
  # symbols the C file references but this test never calls (extract_kernel's callees, ...): link-only stubs (ud2)
  nm -P "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" | awk 'NF>=2 && $2!="U"{d[$1]=1} NF>=2 && $2=="U"{u[$1]=1} END{for(k in u) if(!(k in d) && k ~ /^(c_|rs_)/) print k}' > "$w/undef_$v.txt"
  for sym in $(cat "$w/undef_$v.txt"); do printf '.globl %s\n%s: ud2\n' $sym $sym; done > "$w/stubs_$v.s"
  cc -O1 -g -o "$w/misctest_$v" "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" "$w/stubs_$v.s"
  "$w/misctest_$v" $n
done
echo "objects in $w"
