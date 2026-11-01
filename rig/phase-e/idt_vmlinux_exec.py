#!/usr/bin/env python3
"""idt_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (run with a python that has `unicorn`; reuses Kernel of e820_vmlinux_exec.py)

Runs the COMPILED, LINKED code of arch/x86/kernel/idt.c from two vmlinux files (the unmodified-C kernel and the ported one) in the
Unicorn emulator on the same random starting state and compares what the two kernels do: idt_setup_early_traps, idt_setup_early_pf,
idt_setup_early_handler, idt_setup_traps (the C table walked by the Rust gate writer; ia32_enabled() read from the image) and
idt_install_sysvec (set_intr_gate -> Rust gate writer). Starting state: idt_table (4096 random bytes), system_vectors (random),
idt_descr (random). Compared after the call: all 256 gates, decoded (an address equal to a kernel entry point or inside
early_idt_handler_array is compared by NAME / index, because the two kernels place those at different addresses), system_vectors,
idt_descr and the IDTR the emulated `lidt` loaded. SABOTAGE=<name> patches the Rust kernel in the emulator (negative control)."""
import sys, os, struct, random, re, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e820_vmlinux_exec as E
from unicorn.x86_const import UC_X86_REG_IDTR

def addr_names(path):
    names = {}
    for l in subprocess.run(['nm', path], capture_output=True, text=True, check=True).stdout.splitlines():
        p = l.split()
        if len(p) == 3 and re.match(r'(asm_exc_|asm_sysvec_|asm_int80|irq_entries_start|spurious_entries_start|entry_INT80)', p[2]): names.setdefault(int(p[0], 16), p[2])
    return names

def decode(K, names, raw):
    out = []
    eh, ehs = K.sym['early_idt_handler_array'], K.size['early_idt_handler_array']
    for i in range(256):
        lo, hi = struct.unpack_from('<QQ', raw, 16 * i)
        seg, bits = (lo >> 16) & 0xffff, (lo >> 32) & 0xffff
        addr = (lo & 0xffff) | (((lo >> 48) & 0xffff) << 16) | ((hi & 0xffffffff) << 32); res = hi >> 32
        if addr in names: a = ('sym', names[addr])
        elif eh <= addr < eh + ehs: a = ('eh', (addr - eh) // (ehs // 32), (addr - eh) % (ehs // 32))
        else: a = ('raw', addr)
        out.append((seg, bits, a, res))
    return out

def state(K, names):
    idt = K.rd(K.sym['idt_table'], 4096)
    vec = K.rd(K.sym['system_vectors'], 32); desc = K.rd(K.sym['idt_descr'], 10)
    sel, base, lim, fl = K.uc.reg_read(UC_X86_REG_IDTR)
    return decode(K, names, idt), vec, desc, (base, lim)

def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
    K = [E.Kernel(pa, False), E.Kernel(pb, True)]
    names = [addr_names(pa), addr_names(pb)]
    sab = os.environ.get('SABOTAGE')
    if sab:
        fn, code = {'early_traps': ('idt_setup_early_traps_rs', b'\xc3'), 'early_pf': ('idt_setup_early_pf_rs', b'\xc3'), 'early_handler': ('idt_setup_early_handler_rs', b'\xc3'),
                    'from_table': ('idt_setup_from_table', b'\xc3')}[sab]
        K[1].wr(K[1].sym[fn], code); print(f'SABOTAGE: {fn} replaced by {code.hex()} in the Rust kernel only')
    for k in K:
        assert k.sym['idt_table'] and k.size['idt_table'] == 4096 and k.size['system_vectors'] == 32, (k.size['idt_table'], k.size['system_vectors'])
        # the emulator starts with IDTR = 0; descriptors loaded must come from the code under test
    print(f'C kernel {pa}\nRust kernel {pb}\nidt_table {K[0].sym["idt_table"]:#x} / {K[1].sym["idt_table"]:#x}, system_vectors {K[0].sym["system_vectors"]:#x} / {K[1].sym["system_vectors"]:#x}, '
          f'Rust symbols present in the Rust kernel: ' + ', '.join(n for n in ('idt_setup_from_table', 'idt_setup_early_traps_rs', 'idt_setup_early_pf_rs', 'idt_setup_early_handler_rs') if n in K[1].sym))
    r = random.Random(20261005); counts = {}; lidts = 0
    ops = ['early_traps', 'early_pf', 'early_handler', 'setup_traps', 'install_sysvec']
    for case in range(N):
        op = ops[case % len(ops)]
        idt = bytes(r.getrandbits(8) for _ in range(4096)); vec = bytearray(r.getrandbits(8) for _ in range(32)); desc = bytes(r.getrandbits(8) for _ in range(10))
        n = r.randrange(0xf0, 0x100); fnname = r.choice(['asm_exc_debug', 'asm_exc_int3', 'asm_exc_page_fault', 'asm_exc_nmi'])
        vec[n // 8] &= ~(1 << (n % 8)) & 0xff     # idt_install_sysvec WARNs (and the emulator would hit __warn) if the bit is already set
        res = []
        for ki, k in enumerate(K):
            k.wr(k.sym['idt_table'], idt); k.wr(k.sym['system_vectors'], bytes(vec)); k.wr(k.sym['idt_descr'], desc)
            k.uc.reg_write(UC_X86_REG_IDTR, (0, 0, 0, 0))
            k.call({'early_traps': 'idt_setup_early_traps', 'early_pf': 'idt_setup_early_pf', 'early_handler': 'idt_setup_early_handler',
                    'setup_traps': 'idt_setup_traps', 'install_sysvec': 'idt_install_sysvec'}[op], *((n, k.sym[fnname]) if op == 'install_sysvec' else ()))
            res.append(state(k, names[ki]))
        if res[0] != res[1]:
            print(f'MISMATCH case {case} op {op}')
            for i in range(256):
                if res[0][0][i] != res[1][0][i]: print(f'  gate {i}: C {res[0][0][i]}  Rust {res[1][0][i]}'); break
            print('  vectors equal' if res[0][1] == res[1][1] else f'  vectors C {res[0][1].hex()} Rust {res[1][1].hex()}')
            print(f'  descr C {res[0][2].hex()} Rust {res[1][2].hex()}; IDTR C {res[0][3]} Rust {res[1][3]}')
            sys.exit(1)
        counts[op] = counts.get(op, 0) + 1
        if res[0][3] != (0, 0): lidts += 1
    print(f'idt_vmlinux_exec: {N} runs, the C kernel and the Rust kernel agree on every one (256 decoded gates, system_vectors, idt_descr, IDTR); IDTR loaded in {lidts} runs')
    print('  per function:', ', '.join(f'{k}={v}' for k, v in counts.items()))
if __name__ == '__main__':
    main()
