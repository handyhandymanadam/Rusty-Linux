#!/usr/bin/env python3
"""objcmp.py ORIG.o RUST.o [-i REGEX]... -- object-level equivalence of two ELF relocatable objects.

Compares, per the STUBH contract:
  (a) section list: name, type, flags, size, alignment, entry size
  (b) `llvm-objdump -d -r` of every code section (raw bytes + mnemonics + operands + symbol labels)
  (c) symbol table: name, type, binding, visibility, defining section NAME, value, size
  (d) `llvm-objdump -s` of every section with contents (byte equality), and every relocation entry
      (section, offset, type, symbol, addend).
Only the object file name, symbol/section INDEX numbers and symbol-table ORDER are normalised away.
Anything else that differs is printed as a diff and makes the exit code 1, except sections / symbols
matched by -i REGEX (printed as "IGNORED:" so every ignored item is visible and must be explained).
"""
import re, subprocess, sys, difflib, argparse

def run(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout

def sections(o):
    rows = {}
    for l in run('llvm-readelf', '-S', '-W', o).splitlines():
        m = re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s*(\S*)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', l)
        if m:
            idx, name, typ, addr, off, size, es, flg, lk, inf, al = m.groups()
            rows[name] = dict(idx=int(idx), type=typ, size=int(size, 16), es=int(es, 16), flg=flg, al=int(al))
    return rows

def symbols(o, secs):
    byidx = {v['idx']: k for k, v in secs.items()}
    out = []
    for l in run('llvm-readelf', '-s', '-W', o).splitlines():
        m = re.match(r'\s*(\d+):\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$', l)
        if m:
            _, val, size, typ, bind, vis, ndx, name = m.groups()
            if ndx.isdigit():
                ndx = byidx.get(int(ndx), ndx)
            out.append((name, typ, bind, vis, ndx, int(val, 16), int(size)))
    return out

def relocs(o):
    out, cur = [], None
    for l in run('llvm-readelf', '-r', '-W', o).splitlines():
        m = re.match(r"Relocation section '(\S+)'", l)
        if m:
            cur = m.group(1); continue
        m = re.match(r'([0-9a-f]{8,16})\s+[0-9a-f]{8,16}\s+(\S+)\s+(?:[0-9a-f]{8,16}\s+)?(.*)$', l)   # RMASM: 32-bit ELF prints 8-digit offsets
        if m and cur:
            out.append((cur, int(m.group(1), 16), m.group(2), re.sub(r'\s+', ' ', m.group(3)).strip()))
    return out

def objdump(o, *args):
    import os
    extra = os.environ.get('OBJCMP_OBJDUMP_ARGS', '').split()   # RMASM: e.g. `-M i8086` for the real-mode objects
    t = run(os.environ.get('OBJCMP_OBJDUMP', 'llvm-objdump'), *extra, *args, o)   # RMASM: GNU `objdump -M i8086` is an independent 16-bit decoder
    return [l for l in t.splitlines() if 'file format' not in l and l.strip() != '']

def split_by_section(lines, key):
    d, cur = {}, None
    for l in lines:
        if l.startswith(key):
            cur = l; d[cur] = []
        elif cur is not None:
            d[cur].append(l)
    return d

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('a'); ap.add_argument('b')
    ap.add_argument('-i', action='append', default=[], help='ignore sections/symbols whose name matches')
    ap.add_argument('--label-a', default='orig'); ap.add_argument('--label-b', default='rust')
    args = ap.parse_args()
    args.i += [r'\.comment', r'\.note\.GNU-stack', r'\.debug_.*']   # rustc adds a producer string + an empty stack note (the stub links -z noexecstack)
    ign = [re.compile(x) for x in args.i]
    isign = lambda n: any(r.fullmatch(n) or r.search(n) for r in ign)
    bad = 0

    def report(title, la, lb):
        nonlocal bad
        if la == lb:
            print(f'IDENTICAL  {title}  ({len(la)} items)')
        else:
            bad += 1
            print(f'DIFFERENT  {title}')
            for d in difflib.unified_diff(la, lb, args.label_a, args.label_b, lineterm='', n=1):
                print('    ' + d)

    sa, sb = sections(args.a), sections(args.b)
    def secrow(s, drop_rela=True):
        out = []
        for n, v in sorted(s.items()):
            if n in ('', '.symtab', '.strtab', '.shstrtab') or (drop_rela and n.startswith('.rela')):
                continue
            if isign(n):
                out.append(f'IGNORED: section {n}'); continue
            out.append(f"{n} type={v['type']} flg={v['flg']} size={v['size']:#x} es={v['es']} al={v['al']}")
        return out
    la, lb = secrow(sa), secrow(sb)
    report('(a) section list [name type flags size entsize align]', [x for x in la if not x.startswith('IGNORED')], [x for x in lb if not x.startswith('IGNORED')])
    for x in la: 
        if x.startswith('IGNORED'): print('  A-side', x)
    for x in lb:
        if x.startswith('IGNORED'): print('  B-side', x)

    keepsyms = lambda S, secs: sorted(s for s in symbols(S, secs) if not isign(s[0]) and s[1] != 'FILE' and s[0] != '')
    ya, yb = keepsyms(args.a, sa), keepsyms(args.b, sb)
    fmt = lambda t: f'{t[0]} type={t[1]} bind={t[2]} vis={t[3]} sec={t[4]} val={t[5]:#x} size={t[6]}'
    report('(c) symbol table [name type bind vis section value size]', [fmt(t) for t in ya], [fmt(t) for t in yb])
    for S, secs, lab in ((args.a, sa, 'A'), (args.b, sb, 'B')):
        for s in symbols(S, secs):
            if s[1] == 'FILE' or isign(s[0]): print(f'  {lab}-side ignored/FILE symbol: {s}')
    oa = [s[0] for s in symbols(args.a, sa) if not isign(s[0]) and s[1] != 'FILE' and s[0]]
    ob = [s[0] for s in symbols(args.b, sb) if not isign(s[0]) and s[1] != 'FILE' and s[0]]
    print('  (info) symtab order', 'identical' if oa == ob else 'differs (not part of the contract)')

    ra = [r for r in relocs(args.a) if not isign(r[0][5:]) ]
    rb = [r for r in relocs(args.b) if not isign(r[0][5:]) ]
    report('(b/d) relocation entries [section offset type symbol+addend]', [str(r) for r in ra], [str(r) for r in rb])

    da = split_by_section(objdump(args.a, '-D', '-r'), 'Disassembly of section')
    db = split_by_section(objdump(args.b, '-D', '-r'), 'Disassembly of section')
    for k in sorted(set(da) | set(db)):
        n = k.split()[-1].rstrip(':')
        if n in ('.symtab', '.strtab', '.shstrtab') or n.startswith('.rela') or n.startswith('.rel.'):
            continue    # tables of indices/strings, compared by value above
        if isign(n):
            print(f'IGNORED: disassembly {n}'); continue
        report(f'(b) llvm-objdump -D -r {n} (disassemble-all)', da.get(k, ['<absent>']), db.get(k, ['<absent>']))
    ca = split_by_section(objdump(args.a, '-s'), 'Contents of section')
    cb = split_by_section(objdump(args.b, '-s'), 'Contents of section')
    for k in sorted(set(ca) | set(cb)):
        n = k.split()[-1].rstrip(':')
        if n in ('.symtab', '.strtab', '.shstrtab') or n.startswith('.rela') or n.startswith('.rel.'):
            continue    # symbol-INDEX encodings; symbols and relocations are compared by name above
        if isign(n):
            print(f'IGNORED: contents {n}'); continue
        report(f'(d) bytes of {n}', ca.get(k, ['<absent>']), cb.get(k, ['<absent>']))
    print('RESULT:', 'IDENTICAL' if bad == 0 else f'{bad} DIFFERENCE GROUP(S)')
    sys.exit(1 if bad else 0)
main()
