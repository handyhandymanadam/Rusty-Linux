#!/usr/bin/env python3
"""consts_check.py BUILD_DIR CMDFILE RUST_FILE.rs [extra clang args...]

Checks every `const NAME: ty = VALUE;` of an asm-carrying Rust file against the C headers.
The file declares, in a comment near the top, the headers its original .S includes:
    // C-HEADERS: asm/segment.h asm/boot.h
A const line may carry   // C: <C expression>   (default: the const's own NAME is the C macro)
or                       // nocheck              (derived value, pinned by the object comparison only).
A generated .S (__ASSEMBLY__, the original object's flags) lists `.quad (expr)` for each const; it is
assembled, the values read back from .data, and compared with the Rust value (evaluated here).
Exit 1 on any mismatch.  Prints every pair, so a run is evidence that it saw data.
"""
import re, subprocess, sys, os, tempfile, struct
build, cmdfile, rs, *extra = sys.argv[1:]
text = open(rs).read()
hdrs = re.findall(r'^[ \t]*//[ \t]*C-HEADERS:[ \t]*(.*)$', text, re.M)
hdrs = sum((h.split() for h in hdrs), [])
consts = []
for m in re.finditer(r'^\s*(?:pub\s+)?const\s+([A-Za-z_0-9]+)\s*:\s*[A-Za-z0-9_]+\s*=\s*(.*?);\s*(//.*)?$', text, re.M):
    name, val, cm = m.group(1), m.group(2), m.group(3) or ''
    if 'nocheck' in cm: continue
    mc = re.search(r'//\s*C:\s*(.*)$', cm)
    consts.append((name, val, mc.group(1).strip() if mc else name))
env = {}
def rust_eval(expr):
    expr = re.sub(r'parse_\w+\(env!\("(\w+)"\)\)', lambda m: str(int(os.environ[m.group(1)], 0)), expr)
    e = re.sub(r'\s+as\s+\w+', '', expr)
    e = re.sub(r'\b(0x[0-9a-fA-F_]+|\d[\d_]*)(?:u8|u16|u32|u64|usize|i32|i64)?\b', lambda m: m.group(1).replace('_', ''), e)
    e = e.replace('!(', '~(')
    return eval(e, {}, env) & (2**64 - 1)
vals = []
for name, val, cexpr in consts:
    v = rust_eval(val); env[name] = v; vals.append((name, v, cexpr))
d = tempfile.mkdtemp()
s = os.path.join(d, 'c.S'); o = os.path.join(d, 'c.o')
with open(s, 'w') as f:
    for h in hdrs: f.write(f'#include <{h}>\n' if not h.startswith('"') else f'#include {h}\n')
    f.write('\t.data\n')
    for name, v, c in vals: f.write(f'\t.quad ({c})\n')
here = os.path.dirname(os.path.abspath(__file__))
r = subprocess.run([sys.executable, os.path.join(here, 'orig_asm.py'), build, cmdfile, s, o] + extra, capture_output=True, text=True)
if r.returncode: print(r.stderr); sys.exit(2)
dump = subprocess.run(['llvm-objcopy', '-O', 'binary', '--only-section=.data', o, o + '.bin'], capture_output=True, text=True)
b = open(o + '.bin', 'rb').read()
got = struct.unpack(f'<{len(b)//8}Q', b)
bad = 0
for (name, v, c), g in zip(vals, got):
    ok = (v == g)
    bad += not ok
    print(f"{'OK  ' if ok else 'FAIL'} {name:32s} rust={v:#x} C({c})={g:#x}")
print(f'consts_check: {len(vals)} constants, {bad} mismatches')
sys.exit(1 if bad or len(got) != len(vals) else 0)
