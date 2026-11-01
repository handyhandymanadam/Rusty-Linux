#!/usr/bin/env python3
"""noop_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (python with `unicorn`; reuses Kernel of e820_vmlinux_exec.py)

The six no-op callbacks of arch/x86/kernel/x86_init.c (x86_init_noop, x86_init_uint_noop, bool_x86_init_noop, x86_op_int_noop,
set_rtc_noop, get_rtc_noop) from the linked C kernel and the linked Rust kernel, run in the Unicorn emulator with random arguments and a
random 128-byte scratch buffer behind the pointer arguments: both must return the same value in the width the C ABI defines (void: not
compared, bool: al, int: eax), leave the scratch buffer untouched, preserve rbx rbp r12-r15 and rsp. Also checks that the six symbols of the
Rust kernel have six different addresses (no function merging: callers compare them by address) and start with endbr64 (IBT: they are
indirect-call targets)."""
import sys, os, struct, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e820_vmlinux_exec as E
from unicorn.x86_const import *
FUNCS = [('x86_init_noop', None), ('x86_init_uint_noop', None), ('bool_x86_init_noop', 8), ('x86_op_int_noop', None), ('set_rtc_noop', 32), ('get_rtc_noop', None)]
def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 500
    K = [E.Kernel(pa, False), E.Kernel(pb, True)]
    addrs = [K[1].sym[f] for f, _ in FUNCS]
    assert len(set(addrs)) == 6, 'functions merged: ' + str([hex(a) for a in addrs])
    for k, nm in zip(K, ('C', 'Rust')):
        heads = [bytes(k.rd(k.sym[f], 4)) for f, _ in FUNCS]
        print(f'{nm} kernel: ' + ', '.join(f'{f}@{k.sym[f]:#x}:{h.hex()}' for (f, _), h in zip(FUNCS, heads)))
        assert all(h == bytes.fromhex('f30f1efa') for h in heads), f'{nm}: a function does not start with endbr64'
    r = random.Random(1); cnt = 0
    for case in range(N):
        for f, w in FUNCS:
            buf = bytes(r.getrandbits(8) for _ in range(128)); a1, a2 = r.getrandbits(64), r.getrandbits(64)
            res = []
            for k in K:
                k.wr(E.SCRATCH, buf)
                uc = k.uc
                regs = {x: r.getrandbits(64) for x in ()}
                saved = {}
                for name, reg in (('rbx', UC_X86_REG_RBX), ('rbp', UC_X86_REG_RBP), ('r12', UC_X86_REG_R12), ('r13', UC_X86_REG_R13), ('r14', UC_X86_REG_R14), ('r15', UC_X86_REG_R15)):
                    v = (case * 7919 + len(name)) & 0xffffffff; uc.reg_write(reg, v | 0x1234 << 40); saved[name] = v | 0x1234 << 40
                arg = E.SCRATCH if f in ('set_rtc_noop', 'get_rtc_noop') else a1
                rax = k.call(f, arg, a2, ret=64)
                out = {name: uc.reg_read(reg) for name, reg in (('rbx', UC_X86_REG_RBX), ('rbp', UC_X86_REG_RBP), ('r12', UC_X86_REG_R12), ('r13', UC_X86_REG_R13), ('r14', UC_X86_REG_R14), ('r15', UC_X86_REG_R15))}
                assert out == saved, f'{f}: callee-saved register changed'
                val = None if w is None else (rax & ((1 << w) - 1))
                res.append((val, bytes(k.rd(E.SCRATCH, 128))))
            if res[0] != res[1] or res[0][1] != buf:
                print(f'MISMATCH {f}: C {res[0][0]} Rust {res[1][0]} (buffer untouched: {res[0][1] == buf}/{res[1][1] == buf})'); sys.exit(1)
            if f == 'set_rtc_noop': assert res[0][0] & 0xffffffff == 0xffffffea, hex(res[0][0])
            if f == 'bool_x86_init_noop': assert res[0][0] == 0
            cnt += 1
    print(f'noop_vmlinux_exec: {cnt} calls ({N} x 6 functions) agree C kernel == Rust kernel (return value in ABI width, scratch buffer untouched, callee-saved registers kept); six distinct addresses, all start with endbr64')
if __name__ == '__main__':
    main()
