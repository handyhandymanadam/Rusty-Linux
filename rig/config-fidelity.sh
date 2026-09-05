#!/usr/bin/env bash
# rig/config-fidelity.sh <oracle-world-outdir>   -- logs/floor.md criterion 8.
#
# "The oracle is compiled in the configuration the kernel builds."
#
# For each pristine C file compiled as an ORACLE, find the CONFIG_* it actually
# branches on, and compare the value its translation unit sees against the
# value the kernel sets. A mismatch means the two arms of that differential are
# not the same configuration.
#
# WHY THIS EXISTS: the differential cannot catch this itself. Measured
# 2026-09-03 -- sabotaging sort_rs.rs to ignore efficient_unaligned entirely,
# so the Rust chose a different swap strategy than the C oracle it was paired
# against, STILL PASSED, because both strategies sort correctly. Two arms in
# different configurations agree exactly whenever the configurations are
# result-equivalent, which is exactly when you cannot notice.
#
# "OK (both ways)" is the other way to satisfy the criterion: the same source
# compiled twice, once each way, with both compared. lzo, zlib_inflate and
# (since 2026-09-03) lib's sort do that.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$root" "${1:?usage: config-fidelity.sh <oracle-world-outdir>}" <<'PY'
import glob, os, re, sys
root, w = sys.argv[1], sys.argv[2]
cfgfile = os.path.join(root, 'build-full', '.config')
kernel = {}
for ln in open(cfgfile, errors='ignore'):
    m = re.match(r'^(CONFIG_[A-Z0-9_]+)=(.*)$', ln.strip())
    if m: kernel[m.group(1)] = m.group(2)

# lib/xz derives its own XZ_DEC_* macros from CONFIG_XZ_DEC_* in xz_private.h
# and then branches on the SHORT name, so a checker looking only for CONFIG_*
# sees nothing in lib/xz at all. Found 2026-09-04, when this guard reported
# clean on a module whose configuration it could not see.
BRANCH = re.compile(r'^[ \t]*#[ \t]*(if|ifdef|ifndef|elif).*?((?:CONFIG_|XZ_)[A-Z0-9_]+)|IS_ENABLED\(((?:CONFIG_|XZ_)[A-Z0-9_]+)\)', re.M)
def branches(path):
    try: txt = open(path, errors='ignore').read()
    except OSError: return set()
    out = set()
    for m in BRANCH.finditer(txt):
        for g in m.groups():
            if not g:
                continue
            if g.startswith('CONFIG_'):
                out.add(g)
            elif g.startswith('XZ_DEC_') or g == 'XZ_USE_CRC64':
                out.add('CONFIG_' + g)   # xz_private.h's mapping
    return out

INC = re.compile(r'#\s*include\s+"([^"]*pristine/[^"]+\.c)"')
def sources(tu):
    """the TU itself plus any pristine .c it textually includes"""
    out = [tu]
    try: txt = open(tu, errors='ignore').read()
    except OSError: return out
    for m in INC.finditer(txt):
        out.append(os.path.normpath(os.path.join(os.path.dirname(tu), m.group(1))))
    return out

rows, bad = {}, 0
for f in sorted(glob.glob(os.path.join(w, '*.cfg'))):
    mod = os.path.basename(f)[:-4]
    tu, defined = None, set()
    blocks = []
    for ln in open(f, errors='ignore'):
        ln = ln.rstrip('\n')
        if ln.startswith('### '):
            if tu: blocks.append((tu, defined))
            tu, defined = ln[4:].split(' :: ')[0].strip(), set()
        elif ln.startswith('CONFIG_') or ln.startswith('XZ_'):
            defined.add(ln)
    if tu: blocks.append((tu, defined))
    for tu, defined in blocks:
        p = os.path.join(root, tu)
        for src in sources(p):
            for c in branches(src):
                # lib/xz branches on the SHORT name (XZ_DEC_ARM) while the
                # kernel config is CONFIG_XZ_DEC_ARM, so a TU that has the
                # short one has the symbol. Accept either spelling.
                have = (c in defined) or (c[len('CONFIG_'):] in defined)
                rows.setdefault((mod, os.path.relpath(src, root), c), []).append(
                    (os.path.basename(tu), have))

print('%-10s %-34s %-38s %-6s %s' % ('MODULE','SOURCE','CONFIG','KERNEL','VERDICT'))
for (mod, src, c), obs in sorted(rows.items()):
    k = 'set' if kernel.get(c) == 'y' else 'unset'
    vals = {v for _, v in obs}
    who = ','.join(sorted({t for t, v in obs if v})) or '(none)'
    if len(vals) == 2:
        verdict = 'OK (both ways)'
    elif (True in vals) == (k == 'set'):
        verdict = 'OK'
    else:
        verdict = '*** MISMATCH ***'; bad += 1
    print('%-10s %-34s %-38s %-6s %s' % (mod, src.replace('port/pristine/','')[:34], c, k, verdict))
    if verdict.startswith('***'):
        print('%-10s   oracle TUs: %s' % ('', ', '.join('%s=%s' % (t, 'set' if v else 'unset') for t, v in obs)))
sys.exit(1 if bad else 0)
PY
