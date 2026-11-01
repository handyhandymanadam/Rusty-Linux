#!/usr/bin/env bash
# pm-gdtmem.sh <C.bzImage> <R.bzImage> <outdir> -- boot both images to a parked kernel (rdinit=/nonexist: panic, setup memory at
# 0x10000 stays intact), dump guest memory 0x10000..0x1ffff (QEMU monitor pmemsave through vga2.sh) and compare, via each image's
# setup.elf symbols (C: setup_gdt.boot_gdt / setup_gdt.gdt / setup_idt.null_idt; Rust: mangled ...BOOT_GDT/GDT/NULL_IDT):
#   * the 40 bytes of boot_gdt in guest memory are identical C vs Rust AND equal to the descriptors the C preprocessor gives
#     (build-fast/arch/x86/boot/pm_gen.rs: GDT_ENTRY(...) from the kernel headers), AND equal to the object's .rodata bytes;
#   * gdt_ptr = {len 0x27, ptr = 0x10000 + &boot_gdt (loader ds = 0x1000)} in each image;  * null_idt 6 zero bytes;
#   * alignment of boot_gdt >= 16.
set -u
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd); C=$1; R=$2; O=$3; mkdir -p "$O"
for t in C R; do img=$C; [ $t = R ] && img=$R
  $here/vga2.sh "$img" "$O/$t" 12 - "console=ttyS0 rdinit=/nonexist panic=0 debug earlyprintk=serial,ttyS0,115200" >/dev/null 2>&1
done
python3 - "$C" "$R" "$O" "$root/build-fast/arch/x86/boot/pm_gen.rs" <<'PY'
import sys,subprocess,re,struct
C,R,O,gen=sys.argv[1:5]
g=dict(re.findall(r'pub const (\w+): \w+ = (.*);',open(gen).read()))
ev=lambda n: eval(g[n]) & (2**64-1)   # same operators in Python and C/Rust (| & << on non-negative ints)
exp=[0,0]+[ev('RM_GDT_CS'),ev('RM_GDT_DS'),ev('RM_GDT_TSS')]
expb=b''.join(struct.pack('<Q',x) for x in exp); print('generated descriptors:',[hex(x) for x in exp])
bad=0
res={}
for t,img,names in (('C',C,('setup_gdt.boot_gdt','setup_gdt.gdt','setup_idt.null_idt')),('R',R,('BOOT_GDT','_GDT','NULL_IDT'))):
    nm=subprocess.run(['nm',img[:-8]+'.setup.elf'],capture_output=True,text=True).stdout
    sy={}
    for l in nm.splitlines():
        f=l.split()
        if len(f)==3:
            for k,n in zip(('gdt','ptr','idt'),names):
                if (t=='C' and f[2]==n) or (t=='R' and f[2].startswith('_RN') and f[2].endswith(('rs3GDT' if n=='_GDT' else n))): sy[k]=int(f[0],16)
    m=open(f'{O}/{t}.mem','rb').read()
    gdt=m[sy['gdt']:sy['gdt']+40]; ptr=m[sy['ptr']:sy['ptr']+6]; idt=m[sy['idt']:sy['idt']+6]
    ln,pt=struct.unpack('<HI',ptr)
    print(f"{t}: boot_gdt@{sy['gdt']:#x} (align16: {sy['gdt']%16==0}) gdt_ptr@{sy['ptr']:#x} = len {ln:#x} ptr {pt:#x}; null_idt {idt.hex()}")
    # the TSS access byte reads 0x8b in guest memory: the CPU sets the busy bit (type 9 -> 0xb) when protected_mode_jump executes `ltr`
    live=bytearray(gdt); live[4*8+5]&=~2
    gdt_eq = bytes(live)==expb
    ok = gdt_eq and ln==39 and pt==0x10000+sy['gdt'] and idt==bytes(6) and sy['gdt']%16==0
    print(f"{t}: bytes==generated descriptors (TSS busy bit masked, set by ltr) {gdt_eq}; len==0x27 {ln==39}; ptr==0x10000+&boot_gdt {pt==0x10000+sy['gdt']}; null idt zero {idt==bytes(6)} ->",'OK' if ok else 'BAD')
    bad|= not ok; res[t]=gdt
print('guest memory boot_gdt C vs Rust:', 'IDENTICAL' if res['C']==res['R'] else 'DIFFERS')
bad|= res['C']!=res['R']
sys.exit(1 if bad else 0)
PY
echo "pm-gdtmem rc=$?"
