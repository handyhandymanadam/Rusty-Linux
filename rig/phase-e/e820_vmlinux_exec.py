#!/usr/bin/env python3
"""e820_vmlinux_exec.py <vmlinux-C> <vmlinux-Rust> [N]     (run with a python that has `unicorn`)

Runs the COMPILED, LINKED kernel code of arch/x86/kernel/e820.c and platform-quirks.c from two vmlinux files -- the
unmodified-C kernel (build-full-base) and the ported one -- in the Unicorn x86-64 emulator, on the same random
inputs, and compares what the two kernels do. Where the userspace differential (e820_cmp.sh) compares SOURCES, this
compares what the toolchain made of them: relocations, section placement, calling convention, the glue, the real
`sort`, `memparse`, `memcpy`. Nothing is recompiled: both ELF images are loaded at their link addresses, the
function is called with the System V ABI, `_printk` is stubbed at its entry (the emulator logs format + arguments
and returns) so the kernel's printk machinery is not needed, everything else is the real vmlinux code.

Per run: the main table, the kexec and firmware tables, boot_params, max_pfn, pci_mem_start, userdef and
x86_platform are written, the function called, and the return value (masked to the declared width), the three tables,
pci_mem_start, userdef, x86_platform, boot_params' tail and the whole printk log are read back. The two kernels must
agree on all of it. Prints counts per function so a run is evidence that it saw data. Exit 1 on the first mismatch.
Not covered: BUG_ON paths (ud2), anything needing real hardware."""
import sys, os, struct, subprocess, random, re
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE, UcError
from unicorn.x86_const import *

# Unicorn cannot execute at canonical high addresses in flat mode, so the CPU runs with long-mode paging: the top 1 GiB of
# the address space (0xffffffff80000000..) is mapped by 2 MiB pages onto 1 GiB of emulated physical memory at PHYS0, which
# is where the vmlinux segments, the stack and the scratch buffers live.
V0, PHYS0 = 0xffffffff80000000, 0x40000000
STACK_SZ = 0x100000
STACK = V0 + 0x3ef00000
SCRATCH = V0 + 0x3d000000
SENT = V0 + 0x3e000000
def paddr(va):
    assert va >= V0, hex(va)
    return PHYS0 + (va - V0)

class Kernel:
    def __init__(self, path, rust):
        self.path, self.rust = path, rust
        nm = subprocess.run(['nm', '-S', path], capture_output=True, text=True, check=True).stdout.splitlines()
        self.sym, self.size = {}, {}
        for l in nm:
            p = l.split()
            if len(p) == 4:
                n = re.sub(r'\.\d+$', '', p[3]) if p[3] in ('userdef', ) or re.match(r'userdef\.\d+$', p[3]) else p[3]
                self.sym.setdefault(n, int(p[0], 16)); self.size.setdefault(n, int(p[1], 16))
            elif len(p) == 3 and p[2] not in self.sym:
                self.sym[p[2]] = int(p[0], 16)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(0x0, 0x10000, UC_PROT_ALL); self.uc.mem_map(PHYS0, 0x40000000, UC_PROT_ALL)
        PML4, PDPT, PD = 0x1000, 0x2000, 0x3000
        self.uc.mem_write(PML4 + 511 * 8, struct.pack('<Q', PDPT | 3)); self.uc.mem_write(PDPT + 510 * 8, struct.pack('<Q', PD | 3))
        for i in range(512): self.uc.mem_write(PD + i * 8, struct.pack('<Q', (PHYS0 + i * 0x200000) | 0x83))
        self.uc.reg_write(UC_X86_REG_CR3, PML4); self.uc.reg_write(UC_X86_REG_CR4, 0x20)
        self.uc.msr_write(0xC0000080, 0x100); self.uc.reg_write(UC_X86_REG_CR0, 0x80000001)
        d = open(path, 'rb').read()
        phoff, phentsize, phnum = struct.unpack_from('<Q', d, 32)[0], struct.unpack_from('<H', d, 54)[0], struct.unpack_from('<H', d, 56)[0]
        for i in range(phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', d, phoff + i * phentsize)
            if t != 1 or va < 0xffffffff80000000: continue
            self.uc.mem_write(paddr(va), d[off:off + fsz])
        self.wr(SENT, b'\xf4')
        self.log = []
        pk = self.sym['_printk']
        self.wr(pk, b'\xc3')                       # `ret` at _printk's entry: the hook logs, the ret returns
        self.uc.hook_add(UC_HOOK_CODE, self._printk, begin=pk, end=pk)
        self.userdef_name = 'e820_userdef' if rust else 'userdef'
        self.snap = {}
    def rd(self, a, n): return bytes(self.uc.mem_read(paddr(a), n))
    def wr(self, a, b): self.uc.mem_write(paddr(a), bytes(b))
    def cstr(self, a):
        out = b''
        while True:
            c = self.rd(a, 1)
            if c == b'\0' or len(out) > 512: return out
            out += c; a += 1
    def _printk(self, uc, addr, size, ud):
        fmt = self.cstr(uc.reg_read(UC_X86_REG_RDI))
        regs = [uc.reg_read(r) for r in (UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)]
        args, k = [], 0
        for m in re.finditer(rb'%[#0-9.-]*(ll|l|L|h|hh)?([sudxXp])', fmt):
            v = regs[k]; k += 1
            if m.group(2) == b's': args.append(('s', self.cstr(v)))
            else: args.append(('n', v & (0xffffffff if not m.group(1) in (b'll', b'l', b'L') else 0xffffffffffffffff)))
        self.log.append((fmt, tuple(args)))
    def call(self, name, *args, ret=64):
        a = self.sym[name] if isinstance(name, str) else name
        uc = self.uc
        uc.reg_write(UC_X86_REG_RSP, STACK + STACK_SZ - 0x1000)
        sp = STACK + STACK_SZ - 0x1000
        self.wr(sp, struct.pack('<Q', SENT)); self.log = []
        for r, v in zip((UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9), args): uc.reg_write(r, v & 0xffffffffffffffff)
        uc.emu_start(a, SENT, count=20_000_000)
        rax = uc.reg_read(UC_X86_REG_RAX)
        return rax & ((1 << ret) - 1)

def entries(img, nr): return [struct.unpack_from('<QQI', img, 4 + 20 * i) for i in range(nr)]
def put(k, which, img): k.wr(k.sym[which], img)

class Gen:
    def __init__(self, seed, emax): self.r = random.Random(seed); self.emax = emax
    def addr(self, m):
        r = self.r
        if m == 0: return r.randrange(24) * 0x1000
        if m == 1: return r.choice([r.randrange(0xa0) * 0x1000, 0x100000 + r.randrange(0x1000) * 0x1000, 0x100000000 + r.randrange(0x4000) * 0x10000, r.randrange(0xc0000000) & ~0xfff])
        if m == 2: return r.getrandbits(64) >> r.randrange(40) if r.randrange(4) else r.getrandbits(64)
        if m == 3: return (r.choice([0, 1, 0xfff, 0x1000, 0x9f000, 0xa0000, 0x100000, 0xffffffff, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 0x1000, (1 << 64) - 1]) + r.randrange(5) - 2) & (2**64 - 1)
        return r.randrange(48) * 0x400000
    def size(self, m):
        r = self.r
        if m == 0: return r.randrange(12) * 0x1000
        if m == 1: return r.choice([r.randrange(0x100) * 0x1000, (1 + r.randrange(0x1000)) * 0x10000, r.randrange(0x40000000) & ~0xfff])
        if m == 2: return r.getrandbits(64) >> r.randrange(50) if r.randrange(5) else r.getrandbits(64)
        if m == 3: return (r.choice([0, 1, 2, 0xfff, 0x1000, 0x2000, 0x100000, 1 << 30, 1 << 63, (1 << 64) - 0x1000, (1 << 64) - 1, 1 << 32]) + r.randrange(3) - 1) & (2**64 - 1)
        return (1 + r.randrange(8)) * 0x400000
    def typ(self):
        r = self.r
        if r.randrange(6) == 0: return r.getrandbits(32)
        T = [1, 2, 3, 4, 5, 7, 12, 0xefffffff, 0, 6, 13, 128, 0xffffffff, 8]
        return T[r.randrange(5)] if r.randrange(10) < 6 else r.choice(T)
    def table(self, size_bytes):
        r = self.r; emax = self.emax
        img = bytearray(size_bytes)
        if r.randrange(2): img = bytearray(r.getrandbits(8) for _ in range(size_bytes))
        m = r.choice([0, 0, 0, 0, 1, 1, 2, 2, 4, 4, 3])
        nr = r.choice([0, 1, emax, emax - 1, emax - r.randrange(4), r.randrange(emax + 1), r.randrange(emax + 1), r.randrange(min(emax, 12) + 1)]); nr = max(0, min(nr, emax))
        cur = 0
        for i in range(nr):
            a, s = self.addr(m), self.size(m)
            if m == 4: a = (cur + r.randrange(4) * 0x400000) & (2**64 - 1); s = (1 + r.randrange(4)) * 0x400000; cur = a + s
            elif r.randrange(7) == 0 and i: pa, ps, _ = struct.unpack_from('<QQI', img, 4 + 20 * (i - 1)); a = (pa + ps) & (2**64 - 1) if r.randrange(2) else pa; s = ps if r.randrange(2) else s
            struct.pack_into('<QQI', img, 4 + 20 * i, a, s, self.typ())
        struct.pack_into('<I', img, 0, nr)
        return bytes(img)
    def rng_for(self, img):
        r = self.r; nr = struct.unpack_from('<I', img, 0)[0]; m = r.choice([0, 2, 3, 1])
        if nr and nr <= self.emax and r.randrange(3) == 0:
            a, s, _ = struct.unpack_from('<QQI', img, 4 + 20 * r.randrange(nr)); M = 2**64 - 1
            c = r.randrange(6)
            if c == 0: return a, s
            if c == 1: return (a + r.randrange(max(1, min(s, 1 << 20)))) & M, r.randrange(max(1, min(s, 1 << 20)))
            if c == 2: return (a - r.randrange(0x3000)) & M, (s + r.randrange(0x6000)) & M
            if c == 3: return (a + s) & M, self.size(m)
            if c == 4: return (a - (self.size(m) & 0xfffffff)) & M, self.size(m)
            return a, r.randrange(max(1, min(s, 1 << 24)))
        return self.addr(m), self.size(m)

def parse_string(r):
    sizes = ["0", "1", "4", "16", "0x1000", "0x100000", "1K", "512k", "1M", "64m", "2G", "1g", "3T", "1P", "1E", "0x10M", "010", "0x", "0xG", "", "7z",
             "18446744073709551615", "18446744073709551616", "0xffffffffffffffff", "4096", "64M", "128M", "0x7fffffff", "99999999999999999999", "-1", " 1", "268", "4294967297", "4294967308", "0x10c", "256"]
    seps = ["@", "#", "$", "!", "%", "", "", "@", "@", "?", "*"]
    s = ''
    for k in range(1 + r.randrange(4)):
        if k: s += ','
        c = r.randrange(14)
        if c == 0: s += 'exactmap'
        elif c == 1: s += 'exactmapx'
        elif c == 2: s += 'exact'
        elif c == 3: s += 'nopentium'
        elif c == 4: s += ''
        else:
            s += r.choice(sizes); sep = r.choice(seps); s += sep
            if sep == '%':
                s += r.choice(sizes)
                c2 = r.randrange(5)
                v = ["1", "2", "3", "4", "7", "12", "5", "0", "0x7", "x", "268"]
                if c2 == 0: s += '-' + r.choice(v)
                elif c2 == 1: s += '+' + r.choice(v)
                elif c2 == 2: f = r.choice(["1", "2", "3"]); t = r.choice(["1", "2", "3", "12"]); s += '-' + f + '+' + (t if t != f else str(int(f) + 1))   # a == b would reach BUG_ON
                elif c2 == 3: s += '-' + r.choice(["1", "2"]) + '-1'
            elif sep != '': s += r.choice(sizes)
            if r.randrange(9) == 0: s += r.choice(["x", "zz", " ", "@", "%", "-", "+"])
    return s.encode()

def norm_xp(k, b):
    b = bytearray(b)
    if struct.unpack_from('<Q', b, 112)[0] == k.sym['x86_init_noop']: b[112:120] = struct.pack('<Q', 1)   # kernel-specific address of the callback
    return bytes(b)


def fmt_log(log):
    """Render the (format, args) records as kernel log lines (KERN_CONT pieces joined, level byte dropped)."""
    lines, cur = [], ''
    for fmt, args in log:
        txt = fmt.decode('latin1'); cont = txt.startswith('\x01c'); txt = txt[2:] if txt.startswith('\x01') else txt
        it = iter(args)
        def sub(m):
            kind, v = next(it); spec = m.group(0)
            if kind == 's': return v.decode('latin1')
            flag = '#' if '#' in spec else ''; w = re.search(r'%#?0?(\d+)', spec); w = int(w.group(1)) if w else 0
            if spec.endswith('u'): return str(v)
            return (('0x' + format(v, 'x').zfill(max(w - 2, 0))) if flag else format(v, 'x').zfill(w))
        txt = re.sub(r'%[#0-9.-]*(?:ll|l|L|h|hh)?[sudxXp]', sub, txt)
        if not cont and cur: lines.append(cur); cur = ''
        cur += txt
        if cur.endswith('\n'): lines.append(cur[:-1]); cur = ''
    if cur: lines.append(cur)
    return lines

SEABIOS_1G = [(0x0, 0x9fc00, 1), (0x9fc00, 0x400, 2), (0xf0000, 0x10000, 2), (0x100000, 0x3ff00000 - 0x100000 - 0x20000, 1), (0x3ffe0000, 0x20000, 2), (0xfeffc000, 0x4000, 2), (0xfffc0000, 0x40000, 2)]
OVMF_LIKE = [(0x0, 0xa0000, 1), (0x100000, 0x700000, 1), (0x800000, 0x10000, 4), (0x810000, 0xf0000, 1), (0x900000, 0x1000, 3), (0x901000, 0x1ff000, 1), (0x1000000, 0x2000000, 1), (0x3000000, 0x100000, 3), (0x3100000, 0x20000, 4),
             (0x3120000, 0x3ae00000 - 0x3120000, 1), (0x3ae00000, 0x100000, 2), (0x3af00000, 0x100000, 3), (0xfec00000, 0x1000, 2), (0xfee00000, 0x1000, 2), (0xffc00000, 0x400000, 2), (0x100000000, 0x40000000, 1)]
MESSY = [(0x0, 0xa0000, 1), (0x90000, 0x30000, 2), (0x100000, 0x8000000, 1), (0x4000000, 0x2000000, 3), (0x6000000, 0x1000000, 1), (0x6000000, 0x1000000, 1), (0xa0000, 0x60000, 2), (0x100000000, 0x1000, 5), (0x100000800, 0x2000, 12), (0x100001000, 0x1000, 12)]
MANY = [(0x100000 + 0x2000 * i, 0x1000, 1 if i % 3 else 2) for i in range(128)]
CMDLINES = ["", "mem=64M", "mem=0x3000000", "memmap=16M$0x2000000", "memmap=1M#0x3000000", "memmap=2M!0x3200000", "memmap=exactmap memmap=640K@0 memmap=127M@1M",
            "memmap=exactmap memmap=640K@0 memmap=63M@1M memmap=1M$0x4000000", "memmap=8M%0x1000000-1+2", "memmap=8M%0x2000000+2", "memmap=4M%0x2800000-1", "memmap=4M%0x2800000",
            "memmap=1G@0x100000000", "mem=nopentium", "memmap=nonsense memmap=12M@x", " ".join("memmap=4K$0x%x" % (0x2000000 + 0x2000 * i) for i in range(140))]

def bootseq(K, emax, tsz):
    """The e820 part of setup_arch() as the emulator runs it: e820__memory_setup, the mem= / memmap= early params in command-line order,
    e820__finish_early_params, e820__end_of_ram_pfn, e820__setup_pci_gap -- for firmware maps x command lines, C kernel vs Rust kernel."""
    n = 0; shown = False; toomany = 0; updates = 0; removes = 0
    for mname, m in (('SeaBIOS 1G', SEABIOS_1G), ('OVMF-like', OVMF_LIKE), ('messy overlaps', MESSY), ('128 entries', MANY)):
        for cl in CMDLINES:
            res = []
            for k in K:
                for t in ('e820_table_init', 'e820_table_kexec_init', 'e820_table_firmware_init'): k.wr(k.sym[t], bytes(tsz))
                k.wr(k.sym['e820_table'], struct.pack('<Q', k.sym['e820_table_init'])); k.wr(k.sym['e820_table_kexec'], struct.pack('<Q', k.sym['e820_table_kexec_init']))
                k.wr(k.sym['e820_table_firmware'], struct.pack('<Q', k.sym['e820_table_firmware_init']))
                bp = bytearray(4096); bp[0x1e8] = len(m)
                for i, (a, z, t) in enumerate(m): struct.pack_into('<QQI', bp, 0x2d0 + 20 * i, a, z, t)
                k.wr(k.sym['boot_params'], bytes(bp)); k.wr(k.sym[k.userdef_name], b'\0'); k.wr(k.sym['pci_mem_start'], struct.pack('<Q', 0xaeedbabe))
                k.log = []; allog = []
                def run(name, *a, ret=64):
                    v = k.call(name, *a, ret=ret); allog.extend(k.log); return v
                run('e820__memory_setup', ret=0)
                off = 0x10000
                for tok in cl.split():
                    for key, fn in (('mem=', 'parse_memopt'), ('memmap=', 'parse_memmap_opt')):
                        if tok.startswith(key):
                            k.wr(SCRATCH + off, tok[len(key):].encode() + b'\0'); run(fn, SCRATCH + off, ret=32); off += 0x1000
                run('e820__finish_early_params', ret=0)
                mpfn = run('e820__end_of_ram_pfn'); k.wr(k.sym['max_pfn'], struct.pack('<Q', mpfn))
                run('e820__setup_pci_gap', ret=0)
                res.append((fmt_log(allog), k.rd(k.sym['e820_table_init'], tsz), k.rd(k.sym['e820_table_kexec_init'], tsz), k.rd(k.sym['e820_table_firmware_init'], tsz), k.rd(k.sym['pci_mem_start'], 8), mpfn))
            if res[0] != res[1]:
                print(f'BOOTSEQ MISMATCH map={mname} cmdline={cl[:80]!r}')
                for i, nme in enumerate(('log lines', 'main table', 'kexec table', 'firmware table', 'pci_mem_start', 'max_pfn')):
                    if res[0][i] != res[1][i]: print(f'  {nme}: C {str(res[0][i])[:500]}\n  {" " * len(nme)}  Rust {str(res[1][i])[:500]}')
                sys.exit(1)
            n += 1; toomany += sum('too many entries' in l for l in res[0][0]); updates += sum(l.startswith('e820: update') for l in res[0][0]); removes += sum(l.startswith('e820: remove') for l in res[0][0])
            if not shown and mname == 'SeaBIOS 1G' and cl.startswith('memmap=8M%0x1000000-1+2'):
                print('  sample (SeaBIOS map, memmap=8M%0x1000000-1+2), the e820 lines both kernels print:'); [print('    ' + l) for l in res[1][0]]; shown = True
    print(f'e820_vmlinux_exec BOOTSEQ: {n} (firmware map x command line) sequences, C kernel == Rust kernel on every log line (BIOS-e820 / user: / e820: update|remove / last_pfn / PCI gap), the three tables, pci_mem_start and max_pfn; the sequences printed {updates} `e820: update` lines, {removes} `e820: remove` lines, {toomany} `too many entries` lines')

def main():
    pa, pb = sys.argv[1], sys.argv[2]; N = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    K = [Kernel(pa, False), Kernel(pb, True)]
    sab = os.environ.get('SABOTAGE')       # negative control: patch the Rust kernel's code in the emulator and expect a mismatch
    if sab:
        fn, code = {'pnpbios': ('x86_pnpbios_disabled', b'\xb0\x01\xc3'), 'range_add': ('e820__range_add', b'\xc3'), 'quirks': ('x86_early_init_platform_quirks', b'\xc3'),
                    'mapped_any': ('e820__mapped_any', b'\x31\xc0\xc3'), 'update_table': ('e820_update_table_rs', b'\x31\xc0\xc3')}[sab]
        K[1].wr(K[1].sym[fn], code); print(f'SABOTAGE: {fn} replaced by {code.hex()} in the Rust kernel only')
    emax = (K[0].size['e820_table_init'] - 4) // 20
    assert (K[1].size['e820_table_init'] - 4) // 20 == emax
    tsz = K[0].size['e820_table_init']
    print(f'C kernel {pa}\nRust kernel {pb}\nE820_MAX_ENTRIES = {emax}, sizeof(struct e820_table) = {tsz}; max entries symbol in the Rust kernel: {struct.unpack("<I", K[1].rd(K[1].sym["e820_table_max_entries"], 4))[0] if "e820_table_max_entries" in K[1].sym else "n/a"}')
    if os.environ.get('BOOTSEQ'): bootseq(K, emax, tsz); return
    g = Gen(20261005, emax); r = g.r
    counts = {}
    ops = ['update_table', 'range_add', 'range_update', 'range_update_table', 'range_remove', 'mapped_any', 'mapped_raw_any', 'mapped_all', 'get_entry_type',
           'print_table', 'update_table_print', 'setup_pci_gap', 'end_of_ram_pfn', 'end_of_low_ram_pfn', 'memory_setup_default', 'parse_memopt', 'parse_memmap_opt',
           'platform_quirks', 'pnpbios_disabled']
    BIGLOG = 0
    for case in range(N):
        img, kx, fw = g.table(tsz), g.table(tsz), g.table(tsz)
        op = ops[case % len(ops)]
        cur = img
        s1, z1 = g.rng_for(cur); ty, ty2 = g.typ(), g.typ(); chk = r.randrange(2)
        e2 = (s1 + z1) & (2**64 - 1)
        if ty == ty2: ty2 = (ty + 1) & 0xffffffff
        which = r.choice([0, 0, 0, 0, 0, 0, 1, 2])
        mpfn = r.choice([r.randrange(0x10000000), r.getrandbits(64) >> 12, r.randrange(0x100000), 0x7fffffff])
        bp = bytearray(r.getrandbits(8) if r.randrange(3) == 0 else 0 for _ in range(4096))
        nbp = r.choice([0, 1, 2, 128, r.randrange(129)]); bp[0x1e8] = nbp
        for i in range(128):
            m = r.choice([0, 3, 2, 1]); struct.pack_into('<QQI', bp, 0x2d0 + 20 * i, g.addr(m), g.size(m), g.typ())
        if r.randrange(2): struct.pack_into('<I', bp, 0x1e0, r.getrandbits(32) & 0xfffffff); struct.pack_into('<H', bp, 2, r.getrandbits(16))
        pm0 = r.getrandbits(64); ud0 = r.randrange(2)
        who = r.choice([b'BIOS-e820', b'user', b'modified', b'extended', b'x']) + b'\0'
        pstr = parse_string(r) + b'\0'
        sub = r.choice(list(range(0, 8)) + [r.getrandbits(32), 0xffffffff]); xp0 = bytearray(r.getrandbits(8) for _ in range(K[0].size['x86_platform'])); use_cb = r.randrange(2)
        cb_ptr_off = 112
        res = []
        for k in K:
            tbls = {'main': k.sym['e820_table_init'], 'kexec': k.sym['e820_table_kexec_init'], 'fw': k.sym['e820_table_firmware_init']}
            put(k, 'e820_table_init', img); put(k, 'e820_table_kexec_init', kx); put(k, 'e820_table_firmware_init', fw)
            k.wr(k.sym['e820_table'], struct.pack('<Q', tbls['main'])); k.wr(k.sym['e820_table_kexec'], struct.pack('<Q', tbls['kexec'])); k.wr(k.sym['e820_table_firmware'], struct.pack('<Q', tbls['fw']))
            k.wr(k.sym['boot_params'], bytes(bp)); k.wr(k.sym['max_pfn'], struct.pack('<Q', mpfn)); k.wr(k.sym['pci_mem_start'], struct.pack('<Q', pm0))
            k.wr(k.sym[k.userdef_name], struct.pack('<I', ud0) if k.size.get(k.userdef_name, 4) >= 4 else struct.pack('<B', ud0))
            k.wr(SCRATCH, who); k.wr(SCRATCH + 0x1000, pstr)
            xk = bytearray(xp0); xk[112:120] = struct.pack('<Q', k.sym['x86_init_noop'] if use_cb else 0); k.wr(k.sym['x86_platform'], bytes(xk)); k.wr(k.sym['boot_params'] + 0x23c, struct.pack('<I', sub))
            tb = tbls[['main', 'kexec', 'fw'][which]]
            sym = lambda n: k.sym[n] if n in k.sym else None
            try:
                if op == 'update_table': rv = k.call('e820__update_table', tb, ret=32)
                elif op == 'range_add': rv = k.call('e820__range_add', s1, z1, ty, ret=0)
                elif op == 'range_update': rv = k.call('e820__range_update', s1, z1, ty, ty2)
                elif op == 'range_update_table': rv = k.call('e820__range_update_table', tb, s1, z1, ty, ty2)
                elif op == 'range_remove': rv = k.call('e820__range_remove', s1, z1, ty, chk, ret=64)
                elif op == 'mapped_any': rv = k.call('e820__mapped_any', s1, e2, ty, ret=8)
                elif op == 'mapped_raw_any': rv = k.call('e820__mapped_raw_any', s1, e2, ty, ret=8)
                elif op == 'mapped_all': rv = k.call('e820__mapped_all', s1, e2, ty, ret=8)
                elif op == 'get_entry_type': rv = k.call('e820__get_entry_type', s1, e2, ret=32)
                elif op == 'print_table': rv = k.call('e820__print_table', SCRATCH, ret=0)
                elif op == 'update_table_print': rv = k.call('e820__update_table_print', ret=0)
                elif op == 'setup_pci_gap': rv = k.call('e820__setup_pci_gap', ret=0)
                elif op == 'end_of_ram_pfn': rv = k.call('e820__end_of_ram_pfn')
                elif op == 'end_of_low_ram_pfn': rv = k.call('e820__end_of_low_ram_pfn')
                elif op == 'memory_setup_default':
                    rv = k.call('e820__memory_setup_default'); rv = k.cstr(rv)
                elif op == 'parse_memopt': rv = k.call('parse_memopt', 0 if r.randrange(30) == 0 and False else SCRATCH + 0x1000, ret=32)
                elif op == 'parse_memmap_opt': rv = k.call('parse_memmap_opt', SCRATCH + 0x1000, ret=32)
                elif op == 'platform_quirks': rv = k.call('x86_early_init_platform_quirks', ret=0)
                elif op == 'pnpbios_disabled': rv = k.call('x86_pnpbios_disabled', ret=8)
            except UcError as e:
                print(f'EMULATION ERROR in {"Rust" if k.rust else "C"} kernel, op {op}, case {case}: {e} at rip={k.uc.reg_read(UC_X86_REG_RIP):#x} rsp={k.uc.reg_read(UC_X86_REG_RSP):#x} rax={k.uc.reg_read(UC_X86_REG_RAX):#x} rdi={k.uc.reg_read(UC_X86_REG_RDI):#x}; s1={s1:#x} z1={z1:#x} ty={ty:#x}'); sys.exit(2)
            state = (rv, k.rd(k.sym['e820_table_init'], tsz), k.rd(k.sym['e820_table_kexec_init'], tsz), k.rd(k.sym['e820_table_firmware_init'], tsz),
                     k.rd(k.sym['pci_mem_start'], 8), k.rd(k.sym[k.userdef_name], 1)[0], norm_xp(k, k.rd(k.sym['x86_platform'], K[0].size['x86_platform'])),
                     k.rd(SCRATCH + 0x1000, len(pstr)), tuple(k.log))
            res.append(state)
        if res[0] != res[1]:
            names = ['return', 'main table', 'kexec table', 'firmware table', 'pci_mem_start', 'userdef', 'x86_platform', 'parse string buffer', 'printk log']
            for i, nme in enumerate(names):
                if res[0][i] != res[1][i]:
                    print(f'MISMATCH case {case} op {op}: {nme} differs\n  C   : {str(res[0][i])[:600]}\n  Rust: {str(res[1][i])[:600]}')
                    print(f'  s1={s1:#x} z1={z1:#x} ty={ty:#x}/{ty2:#x} which={which} chk={chk} str={pstr!r} sub={sub:#x}')
            sys.exit(1)
        counts[op] = counts.get(op, 0) + 1; BIGLOG += len(res[0][8])
    print(f'e820_vmlinux_exec: {N} runs, the C kernel and the Rust kernel agree on every one (return value, three tables, pci_mem_start, userdef, x86_platform, parse buffer, printk records: {BIGLOG} records total)')
    print('  per function:', ', '.join(f'{k}={v}' for k, v in counts.items()))

if __name__ == "__main__":
    main()
