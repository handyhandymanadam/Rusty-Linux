#!/usr/bin/env bash
# run-pm-diff.sh [scenarios] [seed] -- lockstep differential of port/tree/arch/x86/boot/pm_rs.rs against the original arch/x86/boot/pm.c,
# both built for the HOST with mocks for every outside effect (asm instructions, port I/O, enable_a20/puts/die/protected_mode_jump, ds(), the
# 32-bit addresses). The C copy is the original pm.c with exactly these mechanical substitutions (each asserted to match once):
#   asm lcallw / cli / lgdtl / lidtl -> mock calls; (u32)&boot_gdt / (u32)&boot_params -> mock_addr_* hooks (a 64-bit host cannot truncate real pointers).
# The GDT macros are the real kernel's (#define lines of asm/segment.h and asm/desc_defs.h extracted into a temp include dir).
# Sabotage: SABOTAGE=sed-expression applies to a copy of the Rust (the tree is untouched).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
. "$root/kbuild-env.sh" >/dev/null 2>&1
T=$(mktemp -d); trap 'rm -rf $T' EXIT; mkdir -p "$T/asm"
python3 - "$root" "$T" <<'PY'
import re,sys
root,T=sys.argv[1:3]
def defs(path, pat):
    out=[]; lines=open(path).read().split('\n'); i=0
    while i<len(lines):
        if re.match(r'#define\s+(%s)'%pat,lines[i]):
            blk=[lines[i]]
            while blk[-1].rstrip().endswith('\\'): i+=1; blk.append(lines[i])
            out+=blk
        i+=1
    return '\n'.join(out)+'\n'
A=root+'/src/linux/arch/x86/include/asm/'
open(T+'/asm/desc_defs.h','w').write('#define _AC(X,Y) X##Y\n'+defs(A+'desc_defs.h',r'_DESC_\w+|DESC_\w+'))
open(T+'/asm/segment.h','w').write(defs(A+'segment.h',r'GDT_ENTRY\b|GDT_ENTRY_BOOT_\w+'))
src=open(root+'/src/linux/arch/x86/boot/pm.c').read()
subs=[(r'asm volatile\("lcallw \*%0"\s*:\s*:\s*"m" \(boot_params\.hdr\.realmode_swtch\)\s*:\s*"eax", "ebx", "ecx", "edx"\);','mock_lcallw(boot_params.hdr.realmode_swtch);'),
      (r'asm volatile\("cli"\);','mock_cli();'),
      (r'asm volatile\("lgdtl %0" : : "m" \(gdt\)\);','mock_lgdt(&gdt);'),
      (r'asm volatile\("lidtl %0" : : "m" \(null_idt\)\);','mock_lidt(&null_idt);'),
      (r'\(u32\)&boot_gdt','mock_addr_boot_gdt(boot_gdt)'),
      (r'\(u32\)&boot_params','mock_addr_boot_params(&boot_params)')]
for a,b in subs:
    src,n=re.subn(a,b,src)
    assert n==1,(a,n)
open(T+'/pm_c.c','w').write('void mock_lcallw(unsigned);void mock_cli(void);void mock_lgdt(const void*);void mock_lidt(const void*);unsigned mock_addr_boot_gdt(const void*);unsigned mock_addr_boot_params(const void*);\n'+src)
PY
cp "$root/build-fast/arch/x86/boot/pm_gen.rs" "$T/"
cp "$root/port/tree/arch/x86/boot/"{pm_rs.rs,rm_common.rs} "$T/"
if [ -n "${SABOTAGE:-}" ]; then
  cp "$T/pm_rs.rs" "$T/pm_rs.before"; sed -i "$SABOTAGE" "$T/pm_rs.rs"
  cmp -s "$T/pm_rs.rs" "$T/pm_rs.before" && { echo "SABOTAGE did not change the file"; exit 2; }
fi
CI="-I$here/inc-pm -I$T"
clang -O1 -w $CI -Dputs=mock_puts -Ddie=mock_die -Denable_a20=mock_enable_a20 -Dprotected_mode_jump=mock_protected_mode_jump \
      -Dgo_to_protected_mode=c_go_to_protected_mode -c "$T/pm_c.c" -o "$T/c_pm.o"
RM_GEN_DIR=$T RUSTC_BOOTSTRAP=1 "$KB_RUSTC" --edition=2021 --crate-type=staticlib -C opt-level=2 -C panic=abort --cfg host_mock \
    --crate-name=pm_rs -o "$T/libpm_rs.a" "$T/pm_rs.rs"
clang -O2 -w $CI "$here/pm-diff.c" -o "$T/h" "$T/c_pm.o" "$T/libpm_rs.a" -lpthread -ldl -lm
"$T/h" "${1:-200000}" "${2:-1}"
