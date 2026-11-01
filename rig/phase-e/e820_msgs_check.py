#!/usr/bin/env python3
"""e820_msgs_check.py UPSTREAM_E820.o GLUE.o RS.o [PQ_UPSTREAM.o PQ_RS.o]

Message parity (Adam, 2026-10-02: error messages stay identical to Linux's). Compares every string constant of the
upstream-compiled e820.o (the pristine C built with this kernel's configuration) with the union of the strings of
e820_glue.o and e820_rs.o, and prints both differences. A printk format (starts with the \\001<level> byte) or any
other string present on one side only is a finding. Prints every message, so a run is evidence that it saw data."""
import subprocess, sys, tempfile, os, re
def strings(obj):
    out = subprocess.run(['llvm-readelf', '-S', '-W', obj], capture_output=True, text=True, check=True).stdout
    secs = re.findall(r'\]\s+(\.rodata[^\s]*)\s', out)
    res = set()
    d = tempfile.mkdtemp()
    for i, s in enumerate(secs):
        f = os.path.join(d, f's{i}')
        r = subprocess.run(['llvm-objcopy', f'--dump-section={s}={f}', obj, os.path.join(d, 'junk.o')], capture_output=True)
        if r.returncode or not os.path.exists(f): continue
        data = open(f, 'rb').read()
        for piece in data.split(b'\0'):
            if len(piece) >= 3: res.add(piece)
    return res
def show(b): return b.decode('latin1').replace('\x01', '<L>').replace('\n', '\\n')
def cmp(name, up, ours):
    U = set(); [U.update(strings(o)) for o in up]
    O = set(); [O.update(strings(o)) for o in ours]
    # only strings that look like messages: printk format (level byte) or containing a space/percent and letters
    def msg(b): return b[:1] == b'\x01' or re.fullmatch(rb'[\x20-\x7e\n]{3,}', b) is not None
    U = {b for b in U if msg(b)}; O = {b for b in O if msg(b)}
    # strcmp()/strncmp() operands, not messages: the Rust compares them byte by byte against literals (no string constant)
    for lit in (b'exactmap', b'nopentium'):
        if lit in U and lit not in O: U.discard(lit); print('   (compare operand, not a message, compared in code:', lit.decode(), ')')
    print(f'== {name}: upstream {len(U)} message strings, ported {len(O)}')
    for b in sorted(U): print('   ', 'both' if b in O else 'UPSTREAM-ONLY', show(b))
    miss = U - O; extra = O - U
    for b in sorted(extra): print('    PORTED-ONLY', show(b))
    print(f'   upstream-only {len(miss)}, ported-only {len(extra)}')
    return not miss and not extra
ok = cmp('e820', [sys.argv[1]], sys.argv[2:4])
if len(sys.argv) > 5: ok &= cmp('platform-quirks', [sys.argv[4]], [sys.argv[5]])
sys.exit(0 if ok else 1)
