#!/usr/bin/env bash
# main-intcall.sh <C.bzImage> <R.bzImage> <outdir>  -- BIOS-call trace of the whole real-mode setup, C vs Rust. QEMU (TCG, -cpu max, so the whole path to the vga=ask prompt
# runs) is started halted with its gdbstub; gdb sets a breakpoint on intcall() (bioscall.S, unchanged C object, setup.elf symbol, setup at 0x10000) and at every hit logs
# int_no (al) and the 44 bytes of `struct biosregs ireg` (edx points at it; ds = 0x1000). The two logs (the stream of INT 10h/15h/16h/... the setup issues: main.c's
# INT 15h EC00 / E980 and INT 16h 02 / 0305 and the callees') must be identical. Runs of identical lines are collapsed (keyboard polling).
set -u
here=$(cd "$(dirname "$0")" && pwd); C=$1; R=$2; O=$3; mkdir -p "$O"; PORT=${GDBPORT:-12347}
for t in C R; do img=$C; [ $t = R ] && img=$R
  ic=$(nm "${img%.bzImage}.setup.elf" | awk '$3=="intcall"{print $1}')
  cat > "$O/$t.py" <<PY
import gdb
gdb.execute("set pagination off")
gdb.execute("target remote :$PORT")
A=$((0x10000 + 0x$ic))
bp=gdb.Breakpoint("*%d"%A)
f=open("$O/$t.calls","w")
inf=gdb.selected_inferior()
while True:
    gdb.execute("continue")
    eax=int(gdb.parse_and_eval("\$eax"))&0xffffffff; edx=int(gdb.parse_and_eval("\$edx"))&0xffffffff
    mem=bytes(inf.read_memory(0x10000+(edx&0xffff),44)).hex()
    f.write("int %02x ireg %s\n"%(eax&0xff,mem)); f.flush()
    bp.delete(); gdb.execute("stepi"); bp=gdb.Breakpoint("*%d"%A)   # gdb sees ip (0x2d5), not the linear address of the breakpoint: step off it by hand
PY
  QEMU_CPU_ARGS="-accel tcg -cpu max" QEMU_EXTRA_ARGS="-gdb tcp::$PORT -S" $here/vga2.sh "$img" "$O/$t" ${INTWAIT:-60} - "console=ttyS0 vga=ask debug earlyprintk=serial,ttyS0,115200" > "$O/$t.txt" 2>/dev/null &
  sleep 3
  timeout $(( ${INTWAIT:-60} + 20 )) gdb -q -batch -x "$O/$t.py" > "$O/$t.gdb.log" 2>&1
  wait
done
python3 - "$O" "$C" "$R" <<'PY'
import sys,struct,subprocess
O,CI,RI=sys.argv[1:4]
def endsym(img):
    for l in subprocess.run(['nm',img[:-8]+'.setup.elf'],capture_output=True,text=True).stdout.splitlines():
        f=l.split()
        if len(f)==3 and f[2]=='_end': return int(f[0],16)
END={'C':endsym(CI),'R':endsym(RI)}
# Pointers into the setup's own data legitimately differ between the images: the e820 buffer (INT 15h AX=E820: edi = a stack address inside detect_memory) is masked;
# the VBE/VGA buffers (INT 10h AX=4Fxx, edi) are heap pointers = _end + offset, so edi is compared as (edi - _end of that image).
def load(t):
    n=[]; raw=0
    for l in open(f'{O}/{t}.calls'):
        p=l.split(); i=int(p[1],16); r=list(struct.unpack('<11I',bytes.fromhex(p[3]))); raw+=1
        ax=r[7]&0xffff
        if i==0x15 and ax==0xe820: r[0]=0
        elif i==0x10 and (ax>>8)==0x4f: r[0]=(r[0]-END[t])&0xffffffff
        e=(i,tuple(r))
        if n and n[-1]==e: continue      # runs of identical calls (INT 16h/1Ah polling: the count depends on timing)
        n.append(e)
    return raw,n
rc,L1=load('C'); rr,L2=load('R')
print(f"C: {rc} intcall hits, {len(L1)} after collapsing repeats; R: {rr} hits, {len(L2)}; ints: "+' '.join('%02x'%x for x in sorted(set(i for i,_ in L1))))
# The video.c "Press <ENTER> to see video modes" prompt polls INT 16h AH=01 / INT 1Ah AH=00 until the 30 s timeout: how many polls fit in the capture window is
# timing, so each stream is cut at its first INT 16h AH=01 poll (everything before it, i.e. the whole setup path up to the prompt, is compared exactly).
def cut(L):
    for k,(i,r) in enumerate(L):
        if i==0x16 and (r[7]&0xffff)==0x0100: return L[:k]
    return L
L1,L2=cut(L1),cut(L2)
same=L1==L2
print(f"compared prefix: {len(L1)} / {len(L2)} calls (up to the prompt's first INT 16h AH=01 poll)")
print('BIOS-call stream (int number + all 11 ireg words, e820/VBE buffer pointers normalised):','IDENTICAL' if same else 'DIFFERS')
for i,r in L2:
    ax=r[7]&0xffff
    if (i,ax) in ((0x15,0xec00),(0x15,0xe980),(0x16,0x0200),(0x16,0x0305)):
        print('  R int %02x eax=%08x ebx=%08x edx=%08x'%(i,r[7],r[4],r[5]))
if not same:
    for k,(a,b) in enumerate(zip(L1,L2)):
        if a!=b: print('first difference at',k,a,b); break
sys.exit(0 if same else 1)
PY
echo "main-intcall rc=$?"
