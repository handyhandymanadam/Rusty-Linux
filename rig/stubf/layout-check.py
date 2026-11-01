#!/usr/bin/env python3
"""layout-check.py <builddir> <spec> <rust-file> <c-include-lines...>
Checks that every struct the Rust file mirrors has the size and field offsets the C compiler gives.
Spec lines (the C compiler is the single source of numbers; nothing is typed twice):
  type  <C type> | <RustType> | cfield=rfield cfield=rfield ...     -> size and offsets
  const <C type> <C field path> | <RUST_CONST>                      -> offsetof(C) == the Rust const
  size  <C type> | <RUST_CONST>                                     -> sizeof(C) == the Rust const
  val   <C integer constant expression> | <Rust expression>        -> equal values (macro constants)
Step 1: the C file (the includes the real C file uses, kbuild's own flags from .efi.o.cmd-style command) is compiled
to assembly; sizeof/offsetof come out as .long lines. Step 2: a copy of the Rust file gets const asserts appended with
those numbers and is type-checked with rustc (host target; layouts of repr(C) types do not depend on the target here).
Exit 0 only if both steps ran and the Rust asserts held."""
import os, re, subprocess, sys, tempfile
b, spec, rs = sys.argv[1], sys.argv[2], sys.argv[3]
cmdfile = sys.argv[4]          # e.g. arch/x86/boot/compressed/.efi.o.cmd (a kbuild saved command to borrow flags from)
includes = sys.argv[5:]
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
items = []
for ln in open(spec):
    ln = ln.split('#')[0].strip()
    if not ln: continue
    kind, rest = ln.split(None, 1)
    parts = [p.strip() for p in rest.split('|')]
    items.append((kind, parts))
asm = []; names = []
def emit(label, expr):
    names.append(label); asm.append(f'asm volatile(".long %c0 /*{label}*/" :: "i"({expr}));')
for kind, p in items:
    if kind == 'type':
        emit(f'{p[0]}:#size', f'sizeof({p[0]})')
        for pair in p[2].split():
            cf, rf = pair.split('=')
            emit(f'{p[0]}:{cf}', f'__builtin_offsetof({p[0]}, {cf})')
    elif kind == 'const':
        t, f = p[0].rsplit(None, 1) if False else (None, None)
        ctype, cfield = re.match(r'(.*\S)\s+(\S+)$', p[0]).groups()
        emit(f'{ctype}:{cfield}', f'__builtin_offsetof({ctype}, {cfield})')
    elif kind == 'size':
        emit(f'{p[0]}:#size', f'sizeof({p[0]})')
    elif kind == 'val':
        emit(f'val:{p[0]}', f'({p[0]})')
w = tempfile.mkdtemp(prefix='layout.')
csrc = os.path.join(w, 'layout.c')
open(csrc, 'w').write('\n'.join(includes) + '\nvoid layout(void) {\n' + '\n'.join(asm) + '\n}\n')
line = open(os.path.join(os.environ.get('CMD_DONOR', b), cmdfile)).readline()
line = re.sub(r'^savedcmd_\S+ := ', '', line.strip())
line = re.sub(r'-Wp,-MMD,\S+', '', line)
line = re.sub(r'-c -o \S+ \S+$', f'-S -o {w}/layout.s {csrc}', line)
r = subprocess.run(line, shell=True, cwd=b, capture_output=True, text=True)
if r.returncode: print(r.stderr); sys.exit('C step failed')
vals = re.findall(r'\.long\s+(\d+)\s+#?\s*/?\*?\s*(\S+?)\*?/?\s*$|\.long\s+(\d+)', open(f'{w}/layout.s').read(), re.M)
nums = [int(x) & 0xffffffff for x in re.findall(r'^\s*\.long\s+(-?\d+)', open(f'{w}/layout.s').read(), re.M)]
if len(nums) != len(names): sys.exit(f'expected {len(names)} numbers from the C compiler, got {len(nums)}')
cv = dict(zip(names, nums))
rsrc = open(rs).read() + '\n'
for kind, p in items:
    if kind == 'type':
        rsrc += f'const _: () = assert!(core::mem::size_of::<{p[1]}>() == {cv[p[0]+":#size"]});\n'
        for pair in p[2].split():
            cf, rf = pair.split('=')
            rsrc += f'const _: () = assert!(core::mem::offset_of!({p[1]}, {rf}) == {cv[p[0]+":"+cf]});\n'
    elif kind == 'const':
        ctype, cfield = re.match(r'(.*\S)\s+(\S+)$', p[0]).groups()
        rsrc += f'const _: () = assert!({p[1]} == {cv[ctype+":"+cfield]});\n'
    elif kind == 'size':
        rsrc += f'const _: () = assert!({p[1]} == {cv[p[0]+":#size"]});\n'
    elif kind == 'val':
        rsrc += f'const _: () = assert!(({p[1]}) as u64 == {cv["val:"+p[0]]});\n'
rf = os.path.join(w, 'rs_check.rs'); open(rf, 'w').write(rsrc)
for k, v in cv.items(): print(f'  C: {k} = {v}')
env = dict(os.environ, RUSTC_BOOTSTRAP='1')
rustc = os.environ.get('KB_RUSTC', 'rustc')
r = subprocess.run([rustc, '--edition=2021', '--crate-type=lib', '--emit=metadata', '-A', 'dead_code', '-A', 'warnings',
                    '-Zcrate-attr=no_std', '--cfg', 'verbose_bootup'] + sum([['--cfg', c] for c in os.environ.get('LAYOUT_CFGS', '').split()], []) + ['-o', f'{w}/out.rmeta', rf], env=env, capture_output=True, text=True)
if r.returncode:
    print(r.stderr[-1500:]); print('LAYOUT MISMATCH (Rust assert failed or Rust did not compile)'); sys.exit(1)
print(f'layout-check: {len(names)} C numbers, Rust asserts all hold ({rs})')
