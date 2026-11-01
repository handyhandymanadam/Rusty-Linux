#!/usr/bin/env bash
# run-extract.sh [builddir [N]]   (build-efi: RANDOMIZE_BASE+ACPI+EARLY_PRINTK+RELOCATABLE; build-fast: none of them; build-sev: AMD_MEM_ENCRYPT;
#                                  build-tdx: INTEL_TDX_GUEST+UNACCEPTED_MEMORY -- the Rust cfgs follow the build's .config)
# Differential test of extract_kernel() (+ parse_mem_encrypt, early_sev_detect): the ORIGINAL C (misc.c as of commit 858e93e, its static
# decompress_kernel() renamed away so the call reaches a fake) vs misc_rs.rs, every callee a recording fake, VGA memory at 0xb0000 and
# the port-I/O stream compared too. debug_* off and on. See exttest.c. RS_SRC=<file> tests another copy of the Rust (sabotage runs).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); source "$root/kbuild-env.sh"
b="$root/${1:-build-efi}"; n=${2:-${N:-100000}}; rs_src=${RS_SRC:-$root/port/tree/arch/x86/boot/compressed/misc_rs.rs}
w=$(mktemp -d "${TMPDIR:-/tmp}/stubgext.XXXXXX"); mkdir -p $w/compressed
# the C before this work = master 858e93e port/tree misc.c (upstream misc.c + the pre-boot Rust probe call)
git -C "$root" show 858e93e:port/tree/arch/x86/boot/compressed/misc.c > $w/compressed/misc_orig.c
cp "$root/port/tree/arch/x86/boot/compressed/misc_cfg.c" $w/compressed/misc_cfg.c
c=$(grep -c '^unsigned long decompress_kernel(unsigned char \*outbuf, unsigned long virt_addr,$' $w/compressed/misc_orig.c); [ "$c" = 1 ] || { echo "decompress_kernel rename matched $c"; exit 2; }
sed -i 's/^unsigned long decompress_kernel(unsigned char \*outbuf, unsigned long virt_addr,$/unsigned long decompress_kernel_orig(unsigned char *outbuf, unsigned long virt_addr,/' $w/compressed/misc_orig.c
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
void *ref_extract_kernel(void *r, unsigned char *o) { return extract_kernel(r, o); }
void ref_sanitize(void *bp) { sanitize_boot_params(bp); }
long ref_heap_base(void) { return (long)boot_heap; }
void ref_video(int *l, int *c, char **m, int *p) { *l = lines; *c = cols; *m = vidmem; *p = vidport; }
EOR
cfgs=(); for pair in X86_NEED_RELOCS:need_relocs RELOCATABLE:relocatable EARLY_PRINTK:early_printk ACPI:acpi RANDOMIZE_BASE:randomize_base INTEL_TDX_GUEST:tdx_guest AMD_MEM_ENCRYPT:amd_mem_encrypt UNACCEPTED_MEMORY:unaccepted_memory; do
  grep -q "^CONFIG_${pair%%:*}=y" $b/.config && cfgs+=(--cfg=${pair##*:}); done
echo "Rust cfgs: ${cfgs[*]}"
ccline() { # <src> <out> [extra]
  local line; line=$(head -1 $b/arch/x86/boot/compressed/.misc.o.cmd | sed 's/^savedcmd_[^ ]* := //')
  line=${line//-Wp,-MMD,arch\/x86\/boot\/compressed\/.misc.o.d/}
  echo "$line" | sed -E 's/-D[A-Z0-9_]*BOOT_RUST//g; s# -c -o [^ ]* [^ ]*misc\.c# -c -o '$2' '$1' -I'$w'/compressed '"$3"'#'
}
for v in off on; do
  x=""; [ $v = on ] && x="-DCONFIG_X86_VERBOSE_BOOTUP=1"
  (cd "$b" && eval "$(ccline $w/compressed/ref.c $w/c_$v.o "$x")")
  (cd "$b" && eval "$(ccline $w/compressed/misc_cfg.c $w/cfg_$v.o "$x")")
  vc=(); [ $v = on ] && vc=(--cfg=verbose_bootup)
  RUSTC_BOOTSTRAP=1 "$KB_RUSTC" -Zunstable-options --sysroot=/dev/null -O -C panic=immediate-abort -Zplt=yes \
    -C debug-assertions=off -C overflow-checks=off -C relocation-model=pie -Zfunction-sections=y \
    --target="$root/port/tree/arch/x86/boot/compressed/preboot_target.json" \
    -Zdirect-access-external-data=yes "${vc[@]}" "${cfgs[@]}" -Zcrate-attr=no_std --edition=2021 --crate-type=rlib --crate-name=misc_rs --emit=obj \
    --extern core=$b/arch/x86/boot/compressed/libcore.rlib --extern compiler_builtins=$b/arch/x86/boot/compressed/libcompiler_builtins.rlib \
    -o "$w/misc_rs_$v.o" "$rs_src"
  objcopy --prefix-symbols=c_ "$w/c_$v.o" "$w/cp_$v.o"
  objcopy --prefix-symbols=rs_ "$w/misc_rs_$v.o" "$w/rs_$v.o"
  objcopy --prefix-symbols=rs_ "$w/cfg_$v.o" "$w/rscfg_$v.o"
  cc -O1 -g -c -o "$w/t_$v.o" "$root/rig/stubg/exttest.c"
  nm -P "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" "$w/rscfg_$v.o" | awk 'NF>=2 && $2!="U"{d[$1]=1} NF>=2 && $2=="U"{u[$1]=1} END{for(k in u) if(!(k in d) && k ~ /^(c_|rs_)/) print k}' > "$w/undef_$v.txt"
  for sym in $(cat "$w/undef_$v.txt"); do printf '.globl %s\n%s: ud2\n' $sym $sym; done > "$w/stubs_$v.s"
  cc -O1 -g -o "$w/exttest_$v" "$w/t_$v.o" "$w/cp_$v.o" "$w/rs_$v.o" "$w/rscfg_$v.o" "$w/stubs_$v.s"
  echo "--- verbose=$v (never-called stubs: $(wc -l < $w/undef_$v.txt))"
  "$w/exttest_$v" $n
done
echo "objects in $w"
