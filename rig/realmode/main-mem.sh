#!/usr/bin/env bash
# main-mem.sh <C.bzImage> <R.bzImage> <outdir> [dump-base]  -- boot both images to a parked kernel (rdinit=/nonexist: setup memory stays intact), dump the
# setup memory (QEMU pmemsave through vga2.sh; dump-base 0x10000 for a protocol >= 2.02 header, 0x90000 for a patched 2.00/2.01 one) and read main.c's globals
# through each image's setup.elf symbols (C: __inb/__outb/__outw, Rust: ...x86_inb/outb/outw):
#   * pio_ops = {&inb, &outb, &outw} are exactly the three port-function addresses of that image;
#   * boot_params is 16-byte aligned; hdr copied (0x1f1..0x26b) equals the image's own header bytes in the setup (hdr symbol);
#   * cmd_line_ptr (0x228) after copy_boot_params; loadflags/heap_end_ptr; HEAP (initial _end, advanced by video.c's GET_HEAP) and heap_end:
#       expected heap_end = loadflags&0x80 ? min(heap_end_ptr+0x200, esp-1024) : _end (WARNING path)
#     where esp is not stored: it is derived as heap_end+1024 when the clamp is active, and reported (C: its main frame is 4 bytes deeper than the Rust one).
set -u
here=$(cd "$(dirname "$0")" && pwd); C=$1; R=$2; O=$3; BASE=${4:-0x10000}; mkdir -p "$O"
for t in C R; do img=$C; [ $t = R ] && img=$R
  DUMP_BASE=$BASE $here/vga2.sh "$img" "$O/$t" 12 - "console=ttyS0 rdinit=/nonexist panic=0 debug earlyprintk=serial,ttyS0,115200" >/dev/null 2>&1
done
python3 - "$C" "$R" "$O" <<'PY'
import sys,subprocess,struct
C,R,O=sys.argv[1:4]
bad=0; res={}
for t,img in (('C',C),('R',R)):
    nm=subprocess.run(['nm',img[:-8]+'.setup.elf'],capture_output=True,text=True).stdout
    sy={}
    for l in nm.splitlines():
        f=l.split()
        if len(f)==3:
            n=f[2]
            if n in('boot_params','HEAP','heap_end','pio_ops','_end','hdr'): sy[n]=int(f[0],16)
            for k in('inb','outb','outw'):
                if n=='__'+k or (n.startswith('_RN') and n.endswith('main_rs%d'%(len('x86_'+k))+'x86_'+k)): sy[k]=int(f[0],16)
    m=open(f'{O}/{t}.mem','rb').read()
    u32=lambda a: struct.unpack_from('<I',m,a)[0]; u16=lambda a: struct.unpack_from('<H',m,a)[0]
    bp=sy['boot_params']
    po=struct.unpack_from('<III',m,sy['pio_ops'])
    ok_po = po==(sy['inb'],sy['outb'],sy['outw'])
    lf=m[bp+0x211]; hp=u16(bp+0x224); cl=u32(bp+0x228)
    HEAP=u32(sy['HEAP']); HE=u32(sy['heap_end']); end=sy['_end']
    he=hp+0x200
    hdr_ok = m[bp+0x1f1:bp+0x1f1+0x7b]==m[sy['hdr']:sy['hdr']+0x7b] or None
    print(f"{t}: pio_ops={po[0]:#x},{po[1]:#x},{po[2]:#x} == nm({sy['inb']:#x},{sy['outb']:#x},{sy['outw']:#x}): {ok_po}; boot_params@{bp:#x} align16 {bp%16==0}; _end {end:#x}")
    print(f"{t}: loadflags {lf:#x} heap_end_ptr {hp:#x} cmd_line_ptr {cl:#x}; HEAP {HEAP:#x} (HEAP-_end {HEAP-end:#x}); heap_end {HE:#x}; hdr_ptr+0x200 {he:#x}")
    if lf&0x80:
        clamp = HE < he
        print(f"{t}: CAN_USE_HEAP: heap_end {'= esp-1024 (clamped), esp at init_heap = %#x'%(HE+1024) if clamp else '= heap_end_ptr+0x200 (no clamp)'}")
        ok_he = HE==he or (HE<he)
    else:
        ok_he = HE==end
        print(f"{t}: no CAN_USE_HEAP: heap_end == _end: {ok_he}")
    print(f"{t}: cmd_line_ptr nonzero and < 1 MiB: {0<cl<0x100000}")
    bad|= (not ok_po) or bp%16!=0 or (not ok_he) or not (0<cl<0x100000)
    res[t]=dict(esp=HE+1024,HEAPrel=HEAP-end,cl=cl,lf=lf)
print('HEAP-_end equal C vs Rust:',res['C']['HEAPrel']==res['R']['HEAPrel'],'; cmd_line_ptr equal:',res['C']['cl']==res['R']['cl'])
if res['C']['lf']&0x80 and res['R']['lf']&0x80: print('heap_end+1024 (esp at init_heap when clamped): C %#x, Rust %#x (difference %d = main()\'s frame, C pushes one register for the ds() temporary)'%(res['C']['esp'],res['R']['esp'],res['R']['esp']-res['C']['esp']))
bad|= res['C']['HEAPrel']!=res['R']['HEAPrel'] or res['C']['cl']!=res['R']['cl']
# the one KNOWN difference: the C main() pushes one 4-byte register more than the Rust main(): esp at init_heap differs by exactly 4; any other value is a defect (e.g. STACK_SIZE)
if res['C']['lf']&0x80 and res['R']['lf']&0x80:
    d=res['R']['esp']-res['C']['esp']; print('expected frame difference 4 (env EXPECT_FRAME_DIFF):', 'OK' if d==int(__import__('os').environ.get('EXPECT_FRAME_DIFF','4')) else 'UNEXPECTED %d'%d); bad|= d!=int(__import__('os').environ.get('EXPECT_FRAME_DIFF','4'))
sys.exit(1 if bad else 0)
PY
echo "main-mem rc=$?"
