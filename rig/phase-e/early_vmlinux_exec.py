#!/usr/bin/env python3
"""early_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (python with `unicorn`; reuses Kernel of e820_vmlinux_exec.py)

parse_early_param() of init/main.c (-> parse_early_options -> the real parse_args -> do_early_param over the `__setup` table) from the linked
unmodified-C kernel and the linked Rust kernel, in the Unicorn emulator. The kernel's own `.init.setup` table is overwritten with 24 test entries
(machine-code stubs `mov eax, N; ret` as setup_func; the remaining entries are not early) and `boot_command_line` with a random line (quotes, `--`, dashes
and underscores, unknown names, > 2047 bytes); `done` is cleared; the function is called twice. Compared: the ordered log of setup_func calls (entry index, value), every printk
record ('Malformed early option'), and the whole 2048-byte private command-line buffer the pass tokenised in place. SABOTAGE=<name> patches the Rust kernel."""
import sys, os, struct, random, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e820_vmlinux_exec as E
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
NS = 24; STUBS = E.SCRATCH + 0x30000; NAMES = E.SCRATCH + 0x20000
def sym_like(k, pat):
    for n, a in k.sym.items():
        if re.search(pat, n): return n
    raise SystemExit('no symbol like ' + pat)
class Run:
    def __init__(self, k):
        self.k = k; self.ev = []
        for i in range(NS): k.uc.hook_add(UC_HOOK_CODE, self.h, begin=STUBS + 0x20 * i, end=STUBS + 0x20 * i, user_data=i)
        if k.rust: self.done, self.tmp = sym_like(k, r'main_rs\d+DONE'), sym_like(k, r'main_rs\d+TMP_CMDLINE')
        else: self.done, self.tmp = 'parse_early_param.done', 'parse_early_param.tmp_cmdline'
        self.nent = (k.sym['__setup_end'] - k.sym['__setup_start']) // 24
        assert self.nent >= NS, self.nent
    def h(self, uc, a, s, i):
        v = uc.reg_read(UC_X86_REG_RDI); self.ev.append(('set', i, self.k.cstr(v) if v else None))
def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    K = [E.Kernel(pa, False), E.Kernel(pb, True)]; R = [Run(k) for k in K]
    sab = os.environ.get('SABOTAGE')
    if sab:
        fn, code = {'early': ('parse_early_param', b'\xc3'), 'done': ('parse_early_options', b'\xc3')}[sab]; K[1].wr(K[1].sym[fn], code); print(f'SABOTAGE: {fn} replaced by {code.hex()} in the Rust kernel only')
    r = random.Random(20261005)
    pool = [b'foo', b'bar-baz', b'bar_baz', b'console', b'mem', b'earlycon', b'x', b'a-b-c', b'noapic', b'root', b'early-param', b'q']
    tot = sets = mal = 0
    for case in range(N):
        names = []; ents = []
        for i in range(NS):
            if r.randrange(5) == 0: ents.append((None, 0, 0)); continue
            nm = bytearray(r.choice(pool))
            if r.randrange(3) == 0: nm = bytearray(95 if x == 45 else 45 if x == 95 else x for x in nm)
            ents.append((bytes(nm) + b'\0', 1 if r.randrange(3) else 0, (r.randrange(5) - 2) if r.randrange(4) == 0 else 0))
        line = b''
        for _ in range(r.randrange(8)):
            nm = bytearray(r.choice(pool))
            if r.randrange(3) == 0: nm = bytearray(95 if x == 45 else 45 if x == 95 else x for x in nm)
            line += bytes(nm)
            m = r.randrange(6)
            if m < 2: line += b'=' + r.choice([b'', b'1', b'"a b"', b'x=y', b'on', b'--'])
            line += b' '
            if r.randrange(12) == 0: line += r.choice([b'-- ', b'--'])
        if r.randrange(40) == 0:
            while len(line) < 2100: line += b'foo=1 '
        line = line.replace(b'\0', b'')
        outs = []
        for ki, k in enumerate(K):
            run = R[ki]; run.ev = []; off = 0
            tab = k.sym['__setup_start']
            for i in range(run.nent):
                if i < NS and ents[i][0] is not None:
                    nm, early, ret = ents[i]; k.wr(NAMES + off, nm); k.wr(STUBS + 0x20 * i, b'\xb8' + struct.pack('<i', ret) + b'\xc3')
                    k.wr(tab + 24 * i, struct.pack('<QQi4x', NAMES + off, STUBS + 0x20 * i, early)); off += len(nm)
                else:
                    k.wr(tab + 24 * i, struct.pack('<QQi4x', NAMES + 0x1000, STUBS + 0x20 * min(i, NS - 1), 0))
            k.wr(NAMES + 0x1000, b'\0')
            cl = line[:2047]; k.wr(k.sym['boot_command_line'], cl + b'\0' * (2048 - len(cl)))
            k.wr(k.sym[run.done], b'\0'); k.wr(k.sym[run.tmp], b'\0' * 2048)
            k.call('parse_early_param'); log1 = list(k.log)      # Kernel.call() clears the printk log on entry: collect after each call
            k.call('parse_early_param'); log2 = list(k.log)
            outs.append((list(run.ev), E.fmt_log(log1 + log2), bytes(k.rd(k.sym[run.tmp], 2048)), bytes(k.rd(k.sym[run.done], 1))))
        if outs[0] != outs[1]:
            print(f'MISMATCH case {case}: line={line[:200]!r}\n  C   : {outs[0][0][:6]} {outs[0][1]} done={outs[0][3]}\n  Rust: {outs[1][0][:6]} {outs[1][1]} done={outs[1][3]}'); sys.exit(1)
        tot += 1; sets += len(outs[0][0]); mal += len(outs[0][1])
    print(f'early_vmlinux_exec: {tot} boot command lines: the C kernel and the Rust kernel agree on every one (setup_func calls with values, printk records, the 2048-byte tokenised buffer, the done flag; second call a no-op); {sets} setup_func calls, {mal} printk lines; __setup table of {R[0].nent} / {R[1].nent} entries')
if __name__ == '__main__':
    main()
