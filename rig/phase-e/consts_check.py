#!/usr/bin/env python3
"""consts_check.py BUILD_DIR RUST_FILE.rs [CMD_OBJ]

Checks every `const NAME: ty = VALUE; // C: EXPR` of a Phase E Rust file against the kernel's own headers:
the C expressions are compiled in the kernel tree with the flags of an existing startup object (CMD_OBJ,
default arch/x86/boot/startup/map_kernel.o in BUILD_DIR) into a table, the table is read back from the object
and compared with the Rust value. The file lists the headers in a `// C-HEADERS: a.h b.h` comment (`src:path` = a private header of the kernel tree, e.g. src:arch/x86/kernel/cpu/cpu.h). A const
without `// C:` is skipped. Prints every pair, so a run is evidence that it saw data. Exit 1 on a mismatch."""
import re, subprocess, sys, os, shlex, tempfile, struct
build, rs = sys.argv[1:3]
cmdobj = sys.argv[3] if len(sys.argv) > 3 else "arch/x86/boot/startup/map_kernel.o"
text = open(rs).read()
hdrs = sum((h.split() for h in re.findall(r'^[ \t]*//[ \t]*C-HEADERS:[ \t]*(.*)$', text, re.M)), [])
consts = []
for m in re.finditer(r'^\s*(?:pub\s+)?const\s+([A-Za-z_0-9]+)\s*:\s*[A-Za-z0-9_]+\s*=\s*(.*?);\s*(//.*)?$', text, re.M):
    name, val, cm = m.group(1), m.group(2), m.group(3) or ''
    mc = re.search(r'//\s*C:\s*(.*)$', cm)
    if mc: consts.append((name, val, mc.group(1).strip()))
env = {}
def rust_eval(expr):
    e = re.sub(r'\s+as\s+\w+', '', expr)
    e = re.sub(r'\b(0x[0-9a-fA-F_]+|\d[\d_]*)(?:u8|u16|u32|u64|usize|i32|i64)?\b', lambda m: m.group(1).replace('_', ''), e)
    e = e.replace('!(', '~(')
    return eval(e, {}, env) & (2**64 - 1)
vals = []
for name, val, c in consts:
    v = rust_eval(val); env[name] = v; vals.append((name, v, c))
srctree = next((t[2:-len('/arch/x86/include')] for t in shlex.split(open(os.path.join(build, os.path.dirname(cmdobj), '.' + os.path.basename(cmdobj) + '.cmd')).readline().split(':=', 1)[1].strip().split(' ; ')[0]) if t.startswith('-I') and t.endswith('/arch/x86/include')), None)
d = tempfile.mkdtemp(); c_src = os.path.join(d, 'k.c'); obj = os.path.join(d, 'k.o')
with open(c_src, 'w') as f:
    for h in hdrs:
        if h.startswith('src:'): f.write(f'#include "{srctree}/{h[4:]}"\n')   # a private header of the kernel tree (e.g. arch/x86/kernel/cpu/cpu.h)
        else: f.write(f'#include <{h}>\n')
    f.write('const unsigned long long K[] = {\n')
    for name, v, c in vals: f.write(f'\t(unsigned long long)({c}),\n')
    f.write('};\n')
cmdfile = os.path.join(build, os.path.dirname(cmdobj), '.' + os.path.basename(cmdobj) + '.cmd')
line = open(cmdfile).readline()
cmd = line.split(':=', 1)[1].strip()
cmd = cmd.split(' ; ')[0] if ' ; ' in cmd else cmd
toks = shlex.split(cmd)
out = []; i = 0
while i < len(toks):
    t = toks[i]
    if t == '-o': out += ['-o', obj]; i += 2; continue
    if t.startswith('-Wp,-MMD') or t == '-Werror': i += 1; continue
    out.append(t); i += 1
out = [t for t in out if not t.endswith('.c') or t.startswith('-')] + [c_src]
r = subprocess.run(out, cwd=build, capture_output=True, text=True)
if r.returncode: print(r.stderr[-3000:]); sys.exit(2)
subprocess.run(['llvm-objcopy', '-O', 'binary', '--only-section=.rodata', obj, obj + '.bin'], check=True)
b = open(obj + '.bin', 'rb').read()
got = struct.unpack(f'<{len(b)//8}Q', b)
bad = 0
for (name, v, c), g in zip(vals, got):
    ok = v == g; bad += not ok
    print(f"{'OK  ' if ok else 'FAIL'} {name:26s} rust={v:#x} C({c})={g:#x}")
print(f'consts_check {os.path.basename(build.rstrip("/"))}: {len(vals)} constants, {bad} mismatches')
sys.exit(1 if bad or len(got) != len(vals) else 0)
