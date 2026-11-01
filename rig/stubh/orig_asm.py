#!/usr/bin/env python3
"""orig_asm.py BUILD_DIR CMDFILE SRC OUT [extra clang args...]

Re-run the kernel's own compile command for an assembler object (taken from a kbuild .cmd file,
relative to BUILD_DIR) on SRC, writing OUT. Extra args (e.g. -DCONFIG_AMD_MEM_ENCRYPT=1) are added
before -c. This is how the ORIGINAL .S object is produced with exactly the kernel's flags.
"""
import shlex, subprocess, sys, os
build, cmdfile, src, out, *extra = sys.argv[1:]
cmdpath = os.path.join(build, cmdfile)
if not os.path.exists(cmdpath):   # a build whose .S objects are Rust has no .cmd for them: use build-fast's (same flags; -I are relative to BUILD)
    cmdpath = os.path.join(os.environ.get('STUBH_CMD_FROM', 'build-fast'), cmdfile)
line = open(cmdpath).readline()
line = line.split(':=', 1)[1].strip()
toks = shlex.split(line)
res, i = [], 0
while i < len(toks):
    t = toks[i]
    if t.startswith('-Wp,'): i += 1; continue
    if t == '-o': i += 2; continue
    if t == '-c': i += 1; continue
    res.append(t); i += 1
res = res[:-1]                       # the source file
cmd = res + extra + ([] if '-E' in extra else ['-c']) + ['-o', os.path.abspath(out), os.path.abspath(src)]
sys.exit(subprocess.run(cmd, cwd=build).returncode)
