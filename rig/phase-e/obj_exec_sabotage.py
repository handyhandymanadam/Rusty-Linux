#!/usr/bin/env python3
"""obj_exec_sabotage.py <build-dir-with-gdt_idt_rs.o.cmd> <C-kernel gdt_idt.pi.o> <python-with-unicorn>
Mutates gdt_idt_rs.rs, builds each mutant with the kernel's own rustc command line (the build dir's .cmd),
prefixes it like the kernel does and runs rig/phase-e/obj_exec.py against the C object: every mutant must
make it report DIFFERENT or crash the emulated CPU (a #GP here is a triple fault on hardware)."""
import subprocess, sys, shlex, os
build, cobj, py = sys.argv[1:4]
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
src = open(f'{root}/port/tree/arch/x86/boot/startup/gdt_idt_rs.rs').read()
line = open(f'{build}/arch/x86/boot/startup/.gdt_idt_rs.o.cmd').readline()
toks = shlex.split(line.split(':=', 1)[1].split(' ; ')[0].strip())
env = {}
while '=' in toks[0] and not toks[0].startswith('-'):
    k, v = toks.pop(0).split('=', 1); env[k] = v
d = '/tmp/pe1_obj_sab'; os.makedirs(d, exist_ok=True)
M = [("gdt-limit", "const GDT_SIZE: u16 = 16 * 8;", "const GDT_SIZE: u16 = 15 * 8;"),
     ("kernel-ds", "const KERNEL_DS: u32 = 0x18;", "const KERNEL_DS: u32 = 0x10;"),
     ("idt-limit", "size: (NUM_EXCEPTION_VECTORS * 16 - 1) as u16,", "size: (NUM_EXCEPTION_VECTORS * 16 - 2) as u16,"),
     ("vc-vector", "table.add(X86_TRAP_VC)", "table.add(X86_TRAP_VC + 1)"),
     ("skip-lgdt", 'asm!("lgdt [{}]", in(reg) &startup_gdt_descr, options(readonly, nostack, preserves_flags));', 'let _ = &startup_gdt_descr;'),
     ("skip-reload", 'asm!("mov ds, {0:e}", "mov ss, {0:e}", "mov es, {0:e}",\n             in(reg) KERNEL_DS, options(nostack, preserves_flags));', 'let _ = KERNEL_DS;')]
caught = 0
for n, a, b in M:
    assert a in src, (n, a)
    rs = f'{d}/m_{n}.rs'; open(rs, 'w').write(src.replace(a, b, 1))
    out = []; skip = False
    for x in toks[:-1]:
        if skip: skip = False; continue
        if x == '--out-dir': out += ['--out-dir', d]; skip = True; continue
        if x.startswith('--emit=obj='): x = f'--emit=obj={d}/m_{n}.o'
        if x.startswith('--emit=dep-info='): x = f'--emit=dep-info={d}/m_{n}.d'
        out.append(x)
    r = subprocess.run(out + ['-Awarnings', rs], cwd=build, env={**os.environ, **env, 'RUSTC_BOOTSTRAP': '1'}, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
    subprocess.run(['llvm-objcopy', '--prefix-symbols=__pi_', f'{d}/m_{n}.o', f'{d}/m_{n}.pi.o'], check=True)
    r = subprocess.run([py, f'{root}/rig/phase-e/obj_exec.py', cobj, f'{d}/m_{n}.pi.o'], capture_output=True, text=True)
    how = 'DIFFERENT' if 'DIFFERENT' in r.stdout else ('emulated CPU fault' if 'UcError' in r.stderr else '')
    print(f'mutant {n:12s}', f'CAUGHT ({how})' if r.returncode and how else '*** NOT CAUGHT')
    caught += bool(r.returncode and how)
print(f'obj_exec sabotage: {caught} of {len(M)} mutants caught'); sys.exit(0 if caught == len(M) else 1)
