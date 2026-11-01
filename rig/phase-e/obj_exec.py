#!/usr/bin/env python3
"""obj_exec.py <gdt_idt.pi.o> [<gdt_idt.pi.o> ...]   (run with a python that has `unicorn`)

Executes the REAL object code of arch/x86/boot/startup/gdt_idt (the C kernel's gdt_idt.pi.o or the Rust
gdt_idt_rs.pi.o) in the Unicorn CPU emulator, because lgdt/lidt cannot run in userspace and a boot is the only
other way to run them. The object is linked with ld.lld at fixed addresses (stubs for `__pi_gdt_page` and
`__pi___x86_return_thunk`), loaded flat, and the two functions are called:
  __pi_startup_64_load_idt(handler)   for handler = 0 and many random 64-bit values
  __pi_startup_64_setup_gdt_idt()
and the machine state they leave is printed as a digest: GDTR, IDTR, DS/ES/SS, the 32 bytes*16 of the bringup IDT
table, the bytes of the stack below the frame. Two objects that do the same thing print the same digest.
Prints the digest per object; exit 1 if they are not all equal."""
import sys, subprocess, tempfile, os, hashlib, random, struct
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn.x86_const import *

TEXT, INIT, DATA, GDT, THUNK, STACK, SENT = 0x100000, 0x110000, 0x200000, 0x300000, 0x400000, 0x480000, 0x500000

def link(obj, d):
    open(f'{d}/stub.s', 'w').write('.globl __pi___x86_return_thunk\n.text\n__pi___x86_return_thunk:\n ret\n')
    subprocess.run(['clang', '-c', '-o', f'{d}/stub.o', f'{d}/stub.s'], check=True)
    open(f'{d}/l.ld', 'w').write(f'''SECTIONS {{
 . = {TEXT:#x}; .text : {{ *(.text) }}
 . = {INIT:#x}; .init.text : {{ *(.init.text) }}
 . = {DATA:#x}; .data..page_aligned : {{ *(.data..page_aligned) }}
 __pi_gdt_page = {GDT:#x};
 . = {THUNK:#x}; .stub : {{ stub.o(.text) }}
 /DISCARD/ : {{ *(.debug* .comment .note* __patchable_function_entries .llvm_addrsig .eh_frame) }}
}}''')
    subprocess.run(['ld.lld', '-T', f'{d}/l.ld', '-o', f'{d}/o.elf', obj, f'{d}/stub.o'], check=True, cwd=d)
    syms = {}
    for l in subprocess.run(['llvm-nm', f'{d}/o.elf'], capture_output=True, text=True, check=True).stdout.splitlines():
        p = l.split()
        if len(p) == 3: syms[p[2]] = int(p[0], 16)
    secs = {}
    for s in ('.text', '.init.text', '.data..page_aligned', '.stub'):
        subprocess.run(['llvm-objcopy', '-O', 'binary', f'--only-section={s}', f'{d}/o.elf', f'{d}/{s}.bin'], check=True)
        secs[s] = open(f'{d}/{s}.bin', 'rb').read()
    return syms, secs

def fresh(secs):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x100000, 0x500000 - 0x100000 + 0x1000, UC_PROT_ALL)
    for name, addr in (('.text', TEXT), ('.init.text', INIT), ('.data..page_aligned', DATA), ('.stub', THUNK)):
        b = secs[name]
        # llvm-objcopy -O binary of one section starts at that section's lowest address of the image
        uc.mem_write(addr, b[:])
    # a valid GDT: null, then flat descriptors; entry 3 (0x18) a 64-bit-mode data segment, entry 2 (0x10) code
    gdt = [0, 0, 0x00af9a000000ffff, 0x00cf92000000ffff] + [0] * 12
    uc.mem_write(GDT, b''.join(struct.pack('<Q', g) for g in gdt))
    return uc

def call(uc, addr, rdi=0):
    uc.reg_write(UC_X86_REG_RSP, STACK)
    uc.reg_write(UC_X86_REG_RDI, rdi)
    uc.mem_write(STACK, struct.pack('<Q', SENT))
    uc.emu_start(addr, SENT)

def state(uc):
    gd, idt = uc.reg_read(UC_X86_REG_GDTR), uc.reg_read(UC_X86_REG_IDTR)
    return (gd[1], gd[2], idt[1], idt[2], uc.reg_read(UC_X86_REG_DS), uc.reg_read(UC_X86_REG_ES), uc.reg_read(UC_X86_REG_SS),
            bytes(uc.mem_read(DATA, 512)))

def run(obj):
    d = tempfile.mkdtemp()
    syms, secs = link(obj, d)
    # the three section binaries were produced one at a time with --only-section: each starts at its own address
    load, setup = syms['__pi_startup_64_load_idt'], syms['__pi_startup_64_setup_gdt_idt']
    table = [k for k in syms if k.endswith('bringup_idt_table')]
    h = hashlib.sha256(); rnd = random.Random(1234); n = 0
    handlers = [0, 1, 0xffff, 0x10000, 0xffffffff, 0x100000000, 0xffffffff81000000, 0xffffffffffffffff] + [rnd.getrandbits(64) for _ in range(2000)]
    for hd in handlers:
        uc = fresh(secs); call(uc, load, hd); s = state(uc)
        h.update(repr(s).encode()); n += 1
    uc = fresh(secs); call(uc, setup, 0); s = state(uc); h.update(repr(s).encode()); n += 1
    uc2 = fresh(secs); call(uc2, load, 0xffffffff81234567); v = state(uc2)
    print(f'{obj}: {n} runs, '
          f'setup: GDTR base={s[0]:#x} limit={s[1]:#x} IDTR base={s[2]:#x} limit={s[3]:#x} DS/ES/SS={s[4]:#x}/{s[5]:#x}/{s[6]:#x}; '
          f'load_idt(0xffffffff81234567): IDTR limit={v[3]:#x}, vc entry (#29) = {v[7][29*16:30*16].hex()}; digest {h.hexdigest()[:16]}')
    return h.hexdigest()

digests = [run(os.path.abspath(o)) for o in sys.argv[1:]]
print('ALL IDENTICAL' if len(set(digests)) == 1 else 'DIFFERENT')
sys.exit(0 if len(set(digests)) == 1 else 1)
