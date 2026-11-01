#!/usr/bin/env python3
"""cpu_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (run with a python that has `unicorn`; reuses Kernel of e820_vmlinux_exec.py)

Runs the COMPILED, LINKED code of the CPUID decode group and the early boot-CPU identification of arch/x86/kernel/cpu/common.c from two vmlinux
files (the unmodified-C kernel and the ported one) in the Unicorn emulator, with a MOCKED CPU: every `cpuid` instruction is answered by this script
(an instruction hook; the same random CPU for both kernels), every MSR the code reads is injected the same way. Per case a random CPU is made up
(vendor string of Intel / AMD / Hygon / Centaur / Zhaoxin / unknown, family / model / stepping, max basic / extended CPUID level, random feature words,
the IA32_ARCH_CAPABILITIES value, the microcode revision, forced capability words, the command line) and the same operation runs on both kernels:
cpu_detect, get_cpu_vendor, get_cpu_cap, get_cpu_address_sizes, filter_cpuid_features (on a scratch cpuinfo_x86), and the whole of early_cpu_init()
(on boot_cpu_data; with the vendor callbacks and the hardware-facing helpers stubbed identically: intel_unlock_cpuid_leafs, cpu_init_topology,
sld_setup, mca_bsp_init, add_taint). Compared after each run: the cpuinfo_x86 bytes, boot_cpu_data, cpu_caps_set / cpu_caps_cleared, this_cpu, the
registered cpu_devs, the pr_err_once flag, and the ordered log of every cpuid, printk (format + arguments), stub call (with the hash of the struct it
saw) and taint. Everything else is the real vmlinux code: the real x86_match_cpu() against the real vulnerability tables, the real cpuid-deps, the real
init_scattered_cpuid_features. SABOTAGE=<name> patches the Rust kernel in the emulator (negative control). Prints counts so that a run is evidence
that it saw data. Not covered: the vendor c_early_init / c_bsp_init callbacks themselves (stubbed), anything that needs real hardware."""
import sys, os, struct, random, re, subprocess, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e820_vmlinux_exec as E
from unicorn import UC_HOOK_INSN, UC_HOOK_CODE, UcError
from unicorn.x86_const import *

M64 = 2**64 - 1
STUBS = ['intel_unlock_cpuid_leafs', 'cpu_init_topology', 'sld_setup', 'mca_bsp_init', 'add_taint']
SZ = 0x180                                   # >= sizeof(struct cpuinfo_x86) (0x150)
CAPS_OFF, CAPS_WORDS = 0x30, 24

def u32(x): return x & 0xffffffff
def mix64(x):
    x &= M64; x ^= x >> 33; x = (x * 0xff51afd7ed558ccd) & M64; x ^= x >> 33; x = (x * 0xc4ceb9fe1a85ec53) & M64; x ^= x >> 33; return x

class Cpu:
    """The mocked CPU: answers for CPUID."""
    def __init__(self, r):
        self.seed = r.getrandbits(64)
        self.density = r.randrange(5)
        names = [b'GenuineIntel', b'AuthenticAMD', b'HygonGenuine', b'CentaurHauls', b'  Shanghai  ', b'AMDisbetter!', b'            ']
        v = r.choice(names) if r.randrange(10) < 7 else bytes(0x20 + r.randrange(95) for _ in range(12))
        if r.randrange(12) == 0: v = bytes(b ^ (1 << r.randrange(8)) if i == r.randrange(12) else b for i, b in enumerate(v))
        self.vendor = (struct.unpack('<I', v[0:4])[0], struct.unpack('<I', v[4:8])[0], struct.unpack('<I', v[8:12])[0])    # ebx, edx, ecx
        self.max_basic = r.choice([0, 1, 2, 5, 6, 7, 8, 9, 0xd, 0xe, 0x10, 0x16, 0x1f, 0x80000000, 0xffffffff, r.getrandbits(32), r.randrange(0x20)])
        self.max_ext = r.choice([0, 0x7fffffff, 0x80000000, 0x80000001, 0x80000006, 0x80000007, 0x80000008, 0x8000000a, 0x8000001f, 0x80000021, 0x80000026, 0x8000ffff, 0x80010000, r.getrandbits(32), 0x80000000 | r.randrange(0x30)])
        fam = r.choice([0, 3, 4, 5, 6, 6, 6, 6, 0xf, 0xf, 0x7, 0xe, r.randrange(16)])
        if r.randrange(3) == 0:   # a real-model signature, so that the real vulnerability tables are exercised
            fam, mdl = r.choice([(6, 0x3c), (6, 0x4e), (6, 0x55), (6, 0x8e), (6, 0x9e), (6, 0xa5), (6, 0x6a), (6, 0xb7), (6, 0x97), (6, 0x37), (6, 0x5c), (6, 0x1a), (6, 0x2a), (6, 0x3a), (6, 0x8f), (6, 0xcf), (6, 0xaa), (0xf, 0x40), (0x17, 0x01), (0x17, 0x31), (0x19, 0x21), (0x19, 0x61), (0x18, 0x00), (0x1a, 0x02), (5, 4), (0x16, 0x30)])
            efam = 0
            if fam >= 0xf: efam, fam = fam - 0xf, 0xf
            self.sig = (efam << 20) | ((mdl >> 4) << 16) | (fam << 8) | ((mdl & 0xf) << 4) | r.randrange(0x10)
        else:
            self.sig = (r.choice([0, r.randrange(0x100)]) << 20) | (r.randrange(16) << 16) | (fam << 8) | (r.randrange(16) << 4) | r.randrange(16)
        self.ebx1 = (r.getrandbits(32) & 0xffffff00) | (r.randrange(0x41) << 8)
        self.clflush = r.randrange(2)
        self.leaf7_eax = r.choice([0, 0, 1, 1, 2, 0xffffffff, r.getrandbits(32)])
        self.l8_08_eax = r.choice([0x3024, 0x3030, 0x2434, 0x2028, 0, 0xff, 0xff00, r.getrandbits(32), 0x3039])
        self.log = []
    def rnd(self, op, count, k):
        a = mix64(self.seed ^ (op << 20) ^ (count << 8) ^ (k * 0x9e3779b97f4a7c15)); b = mix64(a + 1); v = a & 0xffffffff
        for i in range(self.density): v &= ((b & 0xffffffff) >> i) | ((b >> 32) << (32 - i) & 0xffffffff)
        return v
    def answer(self, op, count):
        out = [self.rnd(op, count, k) for k in range(4)]
        if op == 0: out = [self.max_basic, self.vendor[0], self.vendor[2], self.vendor[1]]
        elif op == 1: out[0] = self.sig; out[1] = self.ebx1; out[3] = (out[3] & ~(1 << 19)) | (self.clflush << 19)
        elif op == 7 and count == 0: out[0] = self.leaf7_eax
        elif op == 0x80000000: out[0] = self.max_ext
        elif op == 0x80000008: out[0] = self.l8_08_eax
        return out

class Rig:
    def __init__(self, path, rust):
        self.K = E.Kernel(path, rust); self.rust = rust; K = self.K
        self.cpu = None; self.stublog = []; self.msr_arch = 0
        for n in ('boot_cpu_data', 'cpu_caps_set', 'cpu_caps_cleared', 'this_cpu', 'cpu_devs', 'boot_command_line', '__pgtable_l5_enabled', 'alternatives_patched', 'x86_cap_flags', '__x86_cpu_dev_start', '__x86_cpu_dev_end', 'x86_read_arch_cap_msr'):
            assert n in K.sym, (path, n)
        self.once = next(v for k, v in K.sym.items() if re.search(r'VENDOR_ALREADY_DONE', k)) if rust else K.sym['get_cpu_vendor.__already_done']
        K.uc.hook_add(UC_HOOK_INSN, self.on_cpuid, None, 1, 0, UC_X86_INS_CPUID)
        self.stubs = [n for n in STUBS if n in K.sym]
        for n in self.stubs:
            K.wr(K.sym[n], b'\xc3'); K.uc.hook_add(UC_HOOK_CODE, self.make_stub(n), begin=K.sym[n], end=K.sym[n])
        # IA32_ARCH_CAPABILITIES: x86_read_arch_cap_msr() returns what the case says (mov rax, imm64; ret)
        self.arch_stub = K.sym['x86_read_arch_cap_msr']
        self.devs = self.find_devs()
        self.warn_sites = self.patch_warns()
        # the vendors' c_early_init / c_bsp_init: replaced (where non-NULL) by two `ret` stubs that log what they saw (the real ones read MSRs and poke mtrr/pat)
        K.wr(E.V0 + 0x3e100000, b'\xc3'); K.wr(E.V0 + 0x3e100010, b'\xc3')
        K.uc.hook_add(UC_HOOK_CODE, self.make_stub('c_early_init'), begin=E.V0 + 0x3e100000, end=E.V0 + 0x3e100000)
        K.uc.hook_add(UC_HOOK_CODE, self.make_stub('c_bsp_init'), begin=E.V0 + 0x3e100010, end=E.V0 + 0x3e100010)
        for d in self.devs:
            if d == 0: continue
            if struct.unpack('<Q', K.rd(d + 24, 8))[0]: K.wr(d + 24, struct.pack('<Q', E.V0 + 0x3e100000))
            if struct.unpack('<Q', K.rd(d + 32, 8))[0]: K.wr(d + 32, struct.pack('<Q', E.V0 + 0x3e100010))
    def patch_warns(self):
        """The WARN_ON()s of arch/x86/kernel/cpu/ (common.c: setup_force_cpu_cap, cpuid-deps.c: do_clear_cpu_cap): Unicorn does not deliver #UD to a hook, so every `ud2` that
        __bug_table attributes to arch/x86/kernel/cpu/common.c (a WARNING entry) is replaced by two nops and a code hook logs that it was reached.
        A BUG (flags without BUGFLAG_WARNING) is left alone: it would be a defect here."""
        K = self.K; a, b = K.sym['__start___bug_table'], K.sym['__stop___bug_table']; sites = []
        for e in range(a, b, 12):
            disp, fdisp, line, flags = struct.unpack('<iiHH', K.rd(e, 12))
            addr = (e + disp) & M64; f = K.cstr((e + 4 + fdisp) & M64)
            if f.startswith(b'arch/x86/kernel/cpu/') and flags & 1:
                assert K.rd(addr, 2) == b'\x0f\x0b', hex(addr)
                K.wr(addr, b'\x90\x90'); K.uc.hook_add(UC_HOOK_CODE, lambda uc, ad, sz, ud: self.cpu.log.append(('warn',)), begin=addr, end=addr); sites.append(addr)
        return sites
    def find_devs(self):
        K = self.K; devs = []
        # the registration array: the pointers between __x86_cpu_dev_start and __x86_cpu_dev_end
        a, b = K.sym['__x86_cpu_dev_start'], K.sym['__x86_cpu_dev_end']
        for p in range(a, b, 8):
            d = struct.unpack('<Q', K.rd(p, 8))[0]; devs.append(d)
        return devs
    def on_cpuid(self, uc, ud):
        op, cnt = uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ECX); a = self.cpu.answer(op, cnt)
        self.cpu.log.append(('cpuid', op, cnt, tuple(a)))
        for r, v in zip((UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX), a): uc.reg_write(r, v)
        return 1
    def make_stub(self, name):
        def hook(uc, addr, size, ud):
            rdi, rsi = uc.reg_read(UC_X86_REG_RDI), uc.reg_read(UC_X86_REG_RSI)
            if name == 'add_taint': self.cpu.log.append(('taint', rdi & 0xffffffff, rsi & 0xffffffff)); return
            h = hashlib.sha1(self.K.rd(rdi, SZ)).hexdigest()[:12]; self.cpu.log.append(('stub', name, h))
            # a stub that, like the real one, changes the struct: a hash of what it saw goes into x86_model_id[0..8]
            self.K.wr(rdi + 0xa0, bytes.fromhex(h)[:6] + b'\0\0')
        return hook
    def setup(self, cs):
        K = self.K; self.cpu = cs['cpu']; self.cpu.log = []
        K.wr(K.sym['boot_cpu_data'], cs['boot']); K.wr(K.sym['cpu_caps_set'], cs['set']); K.wr(K.sym['cpu_caps_cleared'], cs['cleared'])
        K.wr(K.sym['__pgtable_l5_enabled'], struct.pack('<I', cs['l5'])); K.wr(K.sym['alternatives_patched'], struct.pack('<i', cs['altp']))
        K.wr(K.sym['boot_command_line'], cs['cmdline'].ljust(2048, b'\0'))
        K.wr(self.once, b'\0'); K.wr(self.arch_stub, b'\x48\xb8' + struct.pack('<Q', cs['arch']) + b'\xc3')
        for i in range(12): K.wr(K.sym['cpu_devs'] + 8 * i, struct.pack('<Q', cs['devs'][i]))
        K.wr(K.sym['this_cpu'], struct.pack('<Q', cs['this']))
        K.wr(E.SCRATCH, cs['c'])
    def state(self):
        K = self.K
        return (K.rd(K.sym['boot_cpu_data'], SZ), K.rd(K.sym['cpu_caps_set'], 96), K.rd(K.sym['cpu_caps_cleared'], 96), K.rd(E.SCRATCH, SZ), K.rd(K.sym['this_cpu'], 8),
                K.rd(K.sym['cpu_devs'], 96), K.rd(self.once, 1), tuple(self.cpu.log), tuple(K.log))

def case_state(r, rg, devs_all):
    """A random starting state valid for both kernels (the addresses of the cpu_dev structs differ, so they are chosen by index)."""
    cpu = Cpu(r)
    c = bytearray(r.getrandbits(8) if r.randrange(2) else 0 for _ in range(SZ))
    c[0x9c:0xa0] = b'\0\0\0\0'
    boot = bytearray(r.getrandbits(8) if r.randrange(2) else 0 for _ in range(SZ))
    # vendor id as cpu_detect() leaves it, for the ops that start from it
    if r.randrange(4):
        vs = struct.pack('<III', cpu.vendor[0], cpu.vendor[1], cpu.vendor[2]); c[0x90:0x9c] = vs
    sparse = lambda: bytearray(b''.join(struct.pack('<I', (1 << r.randrange(32)) if r.randrange(5) == 0 else 0) for _ in range(24)))
    return dict(cpu=cpu, c=bytes(c), boot=bytes(boot), set=bytes(sparse()), cleared=bytes(sparse()), l5=r.choice([0, 0, 1]), altp=r.choice([0, 0, 1]),
                arch=r.choice([0, 0, r.getrandbits(64), r.getrandbits(29), (1 << 62) | r.getrandbits(29), 0x1b, 0x2000, 0x4000, 0xe002, 0xffffffffffffffff]),
                cmdline=r.choice([b'', b'console=ttyS0 noxsave', b'noxsaveopt noxsaves nousershstk fred=on', b'clearcpuid=avx,xsave,mwait,la57', b'setcpuid=703,cpu_meltdown', b'clearcpuid=0,5,32,4294967296,bogus,,fpu fred=off',
                                  b'setcpuid=hypervisor,bogus,704 clearcpuid=703,spectre_v1,l1tf', b'clearcpuid=' + b','.join(b'%d' % r.randrange(720) for _ in range(20))]),
                micro=r.choice([0, 0x1, 0x20, 0x500, 0xa000000, 0x80000001, r.getrandbits(32)]))

def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 1500
    R = [Rig(pa, False), Rig(pb, os.environ.get('BOTH_C') is None)]
    sab = os.environ.get('SABOTAGE')
    if sab:
        fn, code = {'cpu_detect': ('cpu_detect', b'\xc3'), 'get_cpu_cap': ('get_cpu_cap', b'\xc3'), 'get_cpu_vendor': ('get_cpu_vendor', b'\xc3'), 'early_cpu_init': ('early_cpu_init', b'\xc3'),
                    'address_sizes': ('get_cpu_address_sizes', b'\xc3')}[sab]
        R[1].K.wr(R[1].K.sym[fn], code); print(f'SABOTAGE: {fn} replaced by {code.hex()} in the Rust kernel only')
    for rg in R:
        print(f'{"Rust" if rg.rust else "C"} kernel: boot_cpu_data {rg.K.sym["boot_cpu_data"]:#x}, cpu_devs {rg.K.sym["cpu_devs"]:#x}, WARN sites patched {len(rg.warn_sites)}, stubs {", ".join(rg.stubs)}, registered cpu_devs {len(rg.devs)}')
    r = random.Random(20261005 + int(os.environ.get('SEED', '0')))
    ops = ['detect', 'vendor', 'cap', 'addrsz', 'filter', 'earlyinit']
    counts = {}; cpuids = printks = stubs = taints = unknown = known = 0; bugs = {}
    for case in range(N):
        op = ops[case % len(ops)]
        cs0 = case_state(r, R[0], None)
        # registered devs: the same index pattern on both kernels
        order = list(range(len(R[0].devs))); r.shuffle(order)
        res = []
        for rg in R:
            cs = dict(cs0)
            cs['boot'] = bytearray(cs0['boot']); cs['boot'][0x148:0x14c] = struct.pack('<I', cs0['micro']); cs['boot'] = bytes(cs['boot'])
            res.append((rg, cs))
        # device tables: the kernel's real cpu_dev list, in init order when `earlyinit` (init_cpu_devs fills cpu_devs), else pre-filled for both
        pre = r.randrange(3)
        out = []
        for rg, cs in res:
            devs = rg.devs
            cs['devs'] = [devs[i] if (pre != 0 and i < len(devs)) else 0 for i in range(12)]
            cs['this'] = devs[order[0] % len(devs)] if pre == 2 else rg.K.sym['default_cpu']
            rg.setup(cs); rg.K.log = []
            K = rg.K
            try:
                if op == 'detect': K.call('cpu_detect', E.SCRATCH)
                elif op == 'vendor': K.call('get_cpu_vendor', E.SCRATCH)
                elif op == 'cap': K.call('get_cpu_cap', E.SCRATCH)
                elif op == 'addrsz': K.call('get_cpu_address_sizes', E.SCRATCH)
                elif op == 'filter': K.call('filter_cpuid_features', E.SCRATCH, cs0['altp'])
                else: K.call('early_cpu_init')
            except UcError as e:
                print(f'emulator error case {case} op {op} on the {"Rust" if rg.rust else "C"} kernel: {e} at rip {K.uc.reg_read(UC_X86_REG_RIP):#x}'); sys.exit(2)
            st = rg.state()
            # this_cpu and cpu_devs hold addresses that differ between the kernels: compare by the vendor the pointed-to cpu_dev names
            def dev_id(p):
                if p == 0: return 'none'
                if p in devs: return 'dev%d' % devs.index(p)
                return 'default' if p == K.sym['default_cpu'] else 'other'
            this = dev_id(struct.unpack('<Q', st[4])[0]); cdevs = tuple(dev_id(struct.unpack('<Q', st[5][8 * i:8 * i + 8])[0]) for i in range(12))
            # printk args that are pointers into the kernel differ (x86_cap_flags strings are the same text): resolve %s to text
            out.append((st[0], st[1], st[2], st[3], this, cdevs, st[6], st[7], st[8]))
        if out[0] != out[1]:
            print(f'MISMATCH case {case} op {op} sig {cs0["cpu"].sig:#x} vendor {cs0["cpu"].vendor} max_basic {cs0["cpu"].max_basic:#x} max_ext {cs0["cpu"].max_ext:#x} arch {cs0["arch"]:#x} pre {pre}')
            names = ['boot_cpu_data', 'caps_set', 'caps_cleared', 'scratch c', 'this_cpu', 'cpu_devs', 'once', 'cpu log', 'printk log']
            for i, n in enumerate(names):
                if out[0][i] != out[1][i]:
                    print(f'  {n}: differs')
                    if isinstance(out[0][i], bytes):
                        j = next(k for k in range(len(out[0][i])) if out[0][i][k] != out[1][i][k]); print(f'    first byte {j:#x}: C {out[0][i][j]:#x} Rust {out[1][i][j]:#x}')
                    elif isinstance(out[0][i], tuple) and out[0][i] and isinstance(out[0][i][0], tuple):
                        a, b = out[0][i], out[1][i]; j = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b))); print(f'    C   [{j}]: {a[j:j+3]}\n    Rust[{j}]: {b[j:j+3]}  (lengths {len(a)} / {len(b)})')
                    else: print(f'    C {out[0][i]} Rust {out[1][i]}')
            sys.exit(1)
        counts[op] = counts.get(op, 0) + 1
        cpuids += sum(1 for x in out[0][7] if x[0] == 'cpuid'); stubs += sum(1 for x in out[0][7] if x[0] == 'stub'); taints += sum(1 for x in out[0][7] if x[0] == 'taint'); printks += len(out[0][8])
        if op in ('vendor', 'earlyinit'):
            if out[0][4] in ('default', 'none'): unknown += 1
            else: known += 1
        if op == 'earlyinit':
            w = struct.unpack('<24I', out[0][0][CAPS_OFF:CAPS_OFF + 96])
            for k in (22, 23):
                for bit in range(32):
                    if (w[k] >> bit) & 1: bugs[(k - 22) * 32 + bit] = bugs.get((k - 22) * 32 + bit, 0) + 1
    print(f'cpu_vmlinux_exec: {N} runs, the C kernel and the Rust kernel agree on every one (boot_cpu_data, the scratch cpuinfo_x86, cpu_caps_set / cpu_caps_cleared, this_cpu, cpu_devs, the pr_err_once flag, the ordered cpuid / stub / taint / printk log)')
    print('  per op:', ', '.join(f'{k}={v}' for k, v in counts.items()), f'| cpuid instructions {cpuids}, stub calls {stubs}, taints {taints}, printk records {printks}, vendor known {known} / default or none {unknown}')
    print('  bug bits set by early_cpu_init across the runs (bit index in the bug words -> runs):', dict(sorted(bugs.items())))
if __name__ == '__main__':
    main()
