#!/usr/bin/env python3
"""params_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (python with `unicorn`; reuses Kernel of e820_vmlinux_exec.py)

parse_args() (with parse_one, parameq, param_check_unsafe, the real next_arg and skip_spaces) from the linked unmodified-C kernel and the linked
Rust kernel, run in the Unicorn emulator on the same random command lines and parameter tables. Stubbed at their entry (log + canned result):
mutex_lock / mutex_unlock (the parameter mutex: the C kernel inlines kernel_param_lock, so the common callee is the stub point; the argument is compared as 'builtin' for &param_lock), security_locked_down, add_taint, _printk. The parameter callbacks are machine-code stubs
(`[sti;] mov eax, imm32; ret`, so the "option enabled irq's" path runs for real: EFLAGS.IF is read by the kernel's own pushf). Compared per case:
the return value (NULL / ERR_PTR / offset in the buffer), the whole buffer, and the ordered log of stub calls (callback calls with the
parameter index and the value string, lock / unlock arguments, lockdown/taint calls, every printk record). SABOTAGE=<name> patches the Rust kernel."""
import sys, os, struct, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e820_vmlinux_exec as E
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *

BUF, TAB, NAMES, STUBS, OPS = E.SCRATCH, E.SCRATCH + 0x10000, E.SCRATCH + 0x20000, E.SCRATCH + 0x30000, E.SCRATCH + 0x31000

class Run:
    def __init__(self, k):
        self.k = k; self.ev = []; self.lockdown = 0
        for name in ('mutex_lock', 'mutex_unlock', 'security_locked_down', 'add_taint'):
            if name not in k.sym: continue     # security_locked_down is an inline stub without CONFIG_SECURITY
            a = k.sym[name]; k.wr(a, b'\xc3'); k.uc.hook_add(UC_HOOK_CODE, self.stub, begin=a, end=a, user_data=name)
        k.uc.hook_add(UC_HOOK_CODE, self.stub, begin=k.sym['_printk'], end=k.sym['_printk'], user_data='_printk')
        for i in range(8):                       # one hook per callback stub, installed once
            st = STUBS + 0x20 * i
            k.uc.hook_add(UC_HOOK_CODE, self.hook_set, begin=st, end=st, user_data=i)
        unkstub = STUBS + 0x1000
        k.uc.hook_add(UC_HOOK_CODE, self.hook_unk, begin=unkstub, end=unkstub)
    def hook_set(self, uc, a, s, i):
        v = uc.reg_read(UC_X86_REG_RDI); self.ev.append(('set', i, self.cstr(v) if v else None))
    def hook_unk(self, uc, a, s, ud):
        g = uc.reg_read; self.ev.append(('unknown', self.cstr(g(UC_X86_REG_RDI)), self.cstr(g(UC_X86_REG_RSI)) if g(UC_X86_REG_RSI) else None, self.cstr(g(UC_X86_REG_RDX)), g(UC_X86_REG_RCX)))
    def stub(self, uc, addr, size, name):
        rdi, rsi, rdx = (uc.reg_read(r) for r in (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX))
        if name == 'security_locked_down': self.ev.append(('lockdown', rdi)); uc.reg_write(UC_X86_REG_RAX, self.lockdown)
        elif name == 'add_taint': self.ev.append(('taint', rdi & 0xffffffff, rsi & 0xffffffff))
        elif name == '_printk': pass   # Kernel._printk (installed by Kernel.__init__) logs into k.log
        else: self.ev.append((name, 'builtin' if rdi == self.k.sym['param_lock'] else rdi))
    def cstr(self, a): return self.k.cstr(a)

def call8(k, name, args):
    uc = k.uc; sp = E.STACK + E.STACK_SZ - 0x1000
    uc.reg_write(UC_X86_REG_RSP, sp)
    k.wr(sp, struct.pack('<QQQ', E.SENT, args[6] & (2**64 - 1), args[7] & (2**64 - 1))); k.log = []
    for r, v in zip((UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9), args): uc.reg_write(r, v & (2**64 - 1))
    uc.emu_start(k.sym[name], E.SENT, count=5_000_000)
    return uc.reg_read(UC_X86_REG_RAX)

def gen_line(r, names):
    s = b''
    sp = lambda: bytes(r.choice(b' \t\n') for _ in range(1 + r.randrange(3)))
    if r.randrange(3) == 0: s += sp()
    for _ in range(r.randrange(7)):
        c = r.randrange(14)
        if c == 0: s += b'--'
        elif c == 1: s += b'-- init=/bin/sh x=y'
        elif c == 2: s += b'--=v'
        elif c == 3: s += r.choice([b'-', b'---', b'=', b'=x', b'""', b'"', b'" "', b'a"b c"d'])
        elif c == 4: s += bytes(r.choice([34, 61, 32, 45, 95] + list(range(1, 255))) for _ in range(r.randrange(60)))
        elif c == 5: s += bytes(97 + r.randrange(3) for _ in range(300 + r.randrange(1500))) + (b'=v' if r.randrange(2) else b'')
        else:
            n = bytearray(r.choice(names))
            if r.randrange(3) == 0: n = bytearray(95 if x == 45 else 45 if x == 95 else x for x in n)
            n = bytes(n); s += (b'"' + n + b'"') if r.randrange(8) == 0 else n
            m = r.randrange(6)
            if m < 2: s += b'=' + r.choice([b'', b'1', b'on', b'"a b"', b'"quoted"', b'x=y', b'"unterminated', b'a"b c"d', b'""', b'-', b'--'])
            elif m == 2: s += b'="' + bytes(97 + r.randrange(26) for _ in range(r.randrange(20))) + (b'"' if r.randrange(2) else b'')
        s += sp()
    if r.randrange(2): s = s.rstrip(b' \t\n')
    return s.replace(b'\0', b'')

def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
    K = [E.Kernel(pa, False), E.Kernel(pb, True)]
    R = [Run(k) for k in K]
    sab = os.environ.get('SABOTAGE')
    if sab:
        fn, code = {'parse_args': ('parse_args', b'\x31\xc0\xc3'), 'parameq': ('parameq', b'\xb0\x01\xc3'), 'parse_one': ('parse_one', b'\x31\xc0\xc3')}[sab]
        K[1].wr(K[1].sym[fn], code); print(f'SABOTAGE: {fn} replaced by {code.hex()} in the Rust kernel only')
    r = random.Random(20261005)
    names = [b'foo', b'bar-baz', b'bar_baz', b'noarg', b'a-b-c', b'a_b-c', b'console', b'x', b'xyz', b'Foo', b'early-param', b'--', b'-', b'q' * 300]
    CODES = [0, 0, 0, -2, -28, -22, -1, -5, 7]
    tot = 0; sets = 0; msgs = 0; warn = 0; locks = 0; errs = 0
    for case in range(N):
        n = r.randrange(9); line = gen_line(r, names)
        tab = []; rets = []
        for i in range(n):
            nm = r.choice(names) + b'\0'; tab.append(nm); rets.append((r.choice(CODES), r.randrange(int(os.environ.get('STI', '2'))) == 0))
        mn, mx = (-32768, 32767) if r.randrange(2) else (r.choice([-2, 0, 1, -1, 3, -128]), r.choice([0, 1, 2, -1, 127, 5]))
        doing = r.choice([b'Booting kernel', b'early options', b'mymod', b''])
        lockdown = r.choice([0, 0, 1]); iflag = r.randrange(2); unk = r.randrange(3) != 0; unkc = r.choice([0, 0, -2, -28, -22, 5, -1]); argp = 0x77 + r.randrange(9)
        flagsv = [r.randrange(4) for _ in range(n)]; levels = [r.choice([0, 0, -1, 1, 2, -2, 127, -128, 3]) for _ in range(n)]
        mods = [0 if r.randrange(2) else 0x1000 + i * 8 for i in range(n)]; noarg = [r.randrange(2) for _ in range(n)]
        outs = []
        for ki, k in enumerate(K):
            run = R[ki]; run.ev = []; run.lockdown = lockdown
            buf = line + b'\0' + b'\xa5' * 16
            k.wr(BUF, buf)
            off = 0
            for i in range(n):                                  # names, ops, params, stubs
                k.wr(NAMES + off, tab[i]); nameaddr = NAMES + off; off += len(tab[i])
                code = (b'\xfb' if rets[i][1] else b'') + b'\xb8' + struct.pack('<i', rets[i][0]) + b'\xc3'
                stub = STUBS + 0x20 * i; k.wr(stub, code)
                k.wr(OPS + 32 * i, struct.pack('<IIQQQ', noarg[i], 0, stub, 0, 0))
                k.wr(TAB + 40 * i, struct.pack('<QQQHbB4xQ', nameaddr, mods[i], OPS + 32 * i, 0, levels[i], flagsv[i], i))
            unkstub = STUBS + 0x1000; k.wr(unkstub, b'\xb8' + struct.pack('<i', unkc) + b'\xc3')
            dstr = STUBS + 0x2000; k.wr(dstr, doing + b'\0')
            k.uc.reg_write(UC_X86_REG_EFLAGS, 0x2 | (0x200 if iflag else 0))
            args = [dstr, BUF, TAB, n, mn & 0xffffffff, mx & 0xffffffff, argp, unkstub if unk else 0]
            rax = call8(k, 'parse_args', args)
            out_buf = bytes(k.rd(BUF, len(buf)))
            ret = 'NULL' if rax == 0 else f'buf+{rax - BUF}' if BUF <= rax <= BUF + len(buf) else f'ERR({rax - 2**64})' if rax >= 2**64 - 4096 else f'RAW({rax:#x})'
            outs.append((ret, out_buf, list(run.ev), E.fmt_log(k.log) if k.log else []))
        if outs[0] != outs[1]:
            print(f'MISMATCH case {case}: line={line!r} min={mn} max={mx} lockdown={lockdown} IF={iflag}\n  C   : {outs[0][0]} {outs[0][3]}\n  Rust: {outs[1][0]} {outs[1][3]}')
            a, b = outs[0][2], outs[1][2]
            for i in range(max(len(a), len(b))):
                if i >= len(a) or i >= len(b) or a[i] != b[i]: print(f'  ev[{i}]: C {a[i] if i < len(a) else None}  Rust {b[i] if i < len(b) else None}'); break
            sys.exit(1)
        o = outs[0]; tot += 1
        sets += sum(1 for e in o[2] if e[0] == 'set'); locks += sum(1 for e in o[2] if e[0] == 'mutex_lock'); msgs += len(o[3]); warn += sum(1 for m in o[3] if 'enabled irq' in m); errs += o[0].startswith('ERR')
    print(f'params_vmlinux_exec: {tot} command lines: the C kernel and the Rust kernel agree on every one (return value, buffer, ordered stub-call log); set() callbacks {sets}, locks {locks}, printk lines {msgs} (irq-enabled warnings {warn}), ERR_PTR returns {errs}')
if __name__ == '__main__':
    main()
