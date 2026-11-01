#!/usr/bin/env bash
# run-putstr.sh [builddir [N]]   (needs the step-2 misc_rs.rs: RS_SRC=<file> or the port copy)
# Differential test of misc.c's __putstr/__puthex/__putdec (+ scroll/serial_putchar/__putnum): ORIGINAL C (port/pristine misc.c,
# kbuild flags minus *_BOOT_RUST) vs misc_rs.rs, with pio_ops fakes; see putstrtest.c. Runs with EARLY_PRINTK arms as the build has them.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
b="$root/${1:-build-efi}"; n=${2:-${N:-100000}}; rs_src=${RS_SRC:-$root/port/tree/arch/x86/boot/compressed/misc_rs.rs}
w=$(mktemp -d "${TMPDIR:-/tmp}/stubgputstr.XXXXXX"); mkdir -p $w/compressed
cp "$root/port/pristine/arch/x86/boot/compressed/misc.c" $w/compressed/misc_orig.c
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
void ref_set_video(int l, int c, char *m, int p) { lines = l; cols = c; vidmem = m; vidport = p; }
EOR
rcfg=(); grep -q '^CONFIG_EARLY_PRINTK=y' $b/.config && rcfg+=(--cfg=early_printk)
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
    -Zdirect-access-external-data=yes "${cfg[@]}" "${rcfg[@]}" $(grep -q '^CONFIG_X86_NEED_RELOCS=y' $b/.config && echo --cfg=need_relocs) $(grep -q '^CONFIG_RELOCATABLE=y' $b/.config && echo --cfg=relocatable) -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=misc_rs --emit=obj \
    --extern core=$b/arch/x86/boot/compressed/libcore.rlib --extern compiler_builtins=$b/arch/x86/boot/compressed/libcompiler_builtins.rlib \
    -o "$w/misc_rs_$v.o" "$rs_src"
  objcopy --prefix-symbols=c_ "$w/c_$v.o" "$w/cp_$v.o"
  objcopy --prefix-symbols=rs_ "$w/misc_rs_$v.o" "$w/rs_$v.o"
  cc -O1 -g -c -o "$w/t_$v.o" "$root/rig/stubg/putstrtest.c"
  nm -P "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" | awk 'NF>=2 && $2!="U"{d[$1]=1} NF>=2 && $2=="U"{u[$1]=1} END{for(k in u) if(!(k in d) && k ~ /^(c_|rs_)/) print k}' > "$w/undef_$v.txt"
  for sym in $(cat "$w/undef_$v.txt"); do printf '.globl %s\n%s: ud2\n' $sym $sym; done > "$w/stubs_$v.s"
  cc -O1 -g -o "$w/pstest_$v" "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" "$w/stubs_$v.s"
  echo "--- verbose=$v (stubs for never-called symbols: $(wc -l < $w/undef_$v.txt))"
  "$w/pstest_$v" $n
done
echo "objects in $w"
