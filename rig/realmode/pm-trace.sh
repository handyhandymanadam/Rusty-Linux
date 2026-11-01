#!/usr/bin/env bash
# pm-trace.sh <C.bzImage> <R.bzImage> <outdir> [cmdline] -- port-I/O trace (kvm:kvm_pio tracepoint, see uart-trace.sh) of ports 0x70/0x71, 0x80,
# 0x20/0x21, 0xa0/0xa1, 0xf0/0xf1 (+ the UART, which marks the end of the setup's own output) for pm.c vs pm_rs.rs.
#  1. SETUP WINDOW (strict): in both traces the accesses from the setup's `w 0x70 0x80` (NMI disable) after its last UART write to
#     the `w 0x21 0xfb` + io_delay must be EXACTLY the sequence derived from pm.c (hook: outb(0x80,0x70), delay; enable_a20's
#     a20_test_short io_delay (A20 on under QEMU); reset_coprocessor; mask_all_interrupts), same in C and Rust.
#  2. WHOLE TRACE (normalised: runs of identical lines collapsed; RTC reads and all UART accesses dropped, their values/counts are wall-clock
#     and kernel-text dependent; async BIOS timer EOIs `w 0x20 0x20` dropped): C vs Rust.
set -u
here=$(cd "$(dirname "$0")" && pwd); C=$1; R=$2; O=$3; CMD=${4:-"console=ttyS0 rdinit=/nonexist panic=0 debug earlyprintk=serial,ttyS0,115200"}; mkdir -p "$O"
for t in C R; do img=$C; [ $t = R ] && img=$R
  UART_PORTS="${PM_TRACE_PORTS:-0x70-0x71 0x80-0x80 0x20-0x21 0xa0-0xa1 0xf0-0xf1 0xe9-0xe9}" "$here/uart-trace.sh" "$img" "$O/$t" 12 "$CMD" | sed "s/^/$t: /"
done
python3 - "$O" "${PM_HOOK:-0}" <<'PY'
import sys
O=sys.argv[1]; HOOK=sys.argv[2]=="1"
EXP=["w 0x70 s1 x1 0x80","w 0x80 s1 x1 0x0","w 0x80 s1 x1 0x0","w 0xf0 s1 x1 0x0","w 0x80 s1 x1 0x0","w 0xf1 s1 x1 0x0","w 0x80 s1 x1 0x0",
     "w 0xa1 s1 x1 0xff","w 0x80 s1 x1 0x0","w 0x21 s1 x1 0xfb","w 0x80 s1 x1 0x0"]
if HOOK:   # realmode_swtch patched: the hook stub (rig/realmode/pm-hook.sh) does `out 0xe9,al` (al=0x4b) and returns; no cli / NMI disable
    EXP=["w 0xe9 s1 x1 0x4b"]+EXP[2:]
    ANCH="w 0xe9 s1 x1 0x4b"
else: ANCH="w 0x70 s1 x1 0x80"
bad=0; norm={}
for t in 'CR':
    L=[l for l in open(f'{O}/{t}.uart').read().split('\n')[:-1] if l!='w 0x20 s1 x1 0x20']   # BIOS timer-ISR EOIs arrive asynchronously: dropped
    # last UART data write before the NMI disable: the setup's "\n" of its last message
    idx=[i for i,l in enumerate(L) if l==ANCH]
    cand=[i for i in idx if i>0 and L[i-1]=="w 0x3f8 s1 x1 0xa"]
    i=cand[0] if cand else -1
    win=L[i:i+len(EXP)] if i>=0 else []
    ok=win==EXP
    print(f"{t}: {len(L)} accesses; setup window at line {i}: {'== expected pm.c sequence' if ok else 'DIFFERS: '+str(win)} ({len(EXP)} accesses)")
    bad|=not ok
    N=[]
    for l in L:
        if l.startswith(('r 0x70','r 0x71')) or l.split()[1][2:3] in '23' and len(l.split()[1])==5: continue   # RTC reads and the UART (kernel console text/timing differs per run) dropped
        if N and N[-1]==l: continue
        N.append(l)
    norm[t]=N
same=norm['C']==norm['R']
print(f"whole trace (normalised, {len(norm['C'])}/{len(norm['R'])} lines): {'IDENTICAL' if same else 'DIFFERS'}")
if not same:
    import difflib
    for d in list(difflib.unified_diff(norm['C'],norm['R'],lineterm='',n=0))[:10]: print(d)
bad|=not same
sys.exit(1 if bad else 0)
PY
echo "pm-trace rc=$?"
