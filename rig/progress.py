#!/usr/bin/env python3
"""progress.py <root> -- how much of lib/ is Rust, computed, never typed.

WHY THIS EXISTS. STATUS.md carried "43 modules / 7,040 lines" for several
sessions after it had stopped being true, and said so about itself: "a
hand-maintained number with no rig behind it, which is exactly the kind that
drifts". Adam asked for a percentage; a percentage that is retyped is the same
defect with a % sign on it.

WHAT IT COUNTS, and the three denominators, because there is no single honest
one:

  candidates      GOALS.md §8's rule -- everything in lib/ that is a
                  self-contained algorithm over buffers -- as computed by
                  rig/candidates.sh, restricted to files that exist in the
                  6.18.49 tarball so our own generated files cannot inflate it.
  config-full     the subset that x86_64 config-full actually compiles. A port
                  of something no build compiles cannot be booted or measured.
  config-fast     the subset config-fast compiles: the cheap iteration loop.

WHAT COUNTS AS PORTED. Each Rust file under port/tree declares the C it
replaces on a `//! Replaces:` line. That is a CLAIM, and this script checks it:
every named path must exist upstream, and no path may be claimed twice. What it
does NOT check is whether the Rust is any good -- that is what every other
script in rig/ is for.

RESIDUAL C IS REPORTED, NOT HIDDEN. A port may leave a small C entry behind
(a __weak symbol, a jump label, a guard that must run first -- see
logs/c-entry-rule.md). Those files are ported AND still have C in them, and
both facts are printed, because "% ported" quietly meaning two different things
is how a number stops being usable.
"""
import os
import re
import subprocess
import sys

# `//!` in a crate root, `//` in a file that is `include!`d -- an inner doc
# comment cannot appear part-way through a file, and inffixed_rs.rs is
# included rather than compiled.
RE_REPL = re.compile(r'^//!? Replaces:\s*(.*)$', re.M)


def lines_of(path):
    try:
        with open(path, errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def objs(build):
    """Object basenames (relative to lib/) present in a build directory."""
    out = set()
    d = os.path.join(build, "lib")
    for root, _dirs, files in os.walk(d):
        for f in files:
            if f.endswith(".o") and not f.endswith(".mod.o"):
                out.add(os.path.relpath(os.path.join(root, f), d)[:-2])
    return out


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    os.chdir(root)

    upstream = {l.strip() for l in open("logs/upstream-lib-c.txt") if l.strip()}

    # The candidate rule, run by its own script so there is one copy of it.
    heur = subprocess.run(["./rig/candidates.sh", "--list"],
                          capture_output=True, text=True).stdout.split()
    cands = {c for c in heur if c in upstream}

    # Every claim, and the file that makes it.
    claims = {}
    dup = []
    for r, _d, fs in os.walk("port/tree/lib"):
        for f in sorted(fs):
            if not f.endswith(".rs"):
                continue
            p = os.path.join(r, f)
            m = RE_REPL.search(open(p, errors="replace").read())
            if not m:
                continue
            for path in m.group(1).split():
                # A claim is a PATH TO A .c FILE and nothing else. Without the
                # suffix test, prose on the same line that happens to mention
                # a lib/ path is counted as a port: inffixed_rs.rs replaces a
                # HEADER, said so in words, and was counted as having ported
                # lib/zlib_inflate/inffixed.h -- into both the numerator and,
                # through the union below, the denominator.
                if not (path.startswith("lib/") and path.endswith(".c")):
                    continue
                rel = path[4:]
                if rel in claims:
                    dup.append((rel, claims[rel], p))
                claims[rel] = p

    bad = [(c, p) for c, p in claims.items() if c not in upstream]
    # A claimed file is a candidate by construction: it was ported.
    cands |= set(claims)

    full, fast = objs("build-full"), objs("build-fast")

    def built(c, s):
        b = c[:-2]
        return b in s or b.replace("-", "_") in s

    def src(c):
        p = os.path.join("port/pristine/lib", c)
        return p if os.path.exists(p) else os.path.join("src/linux/lib", c)

    rows = []
    for c in sorted(cands):
        rows.append((c, lines_of(src(c)), c in claims,
                     built(c, full), built(c, fast),
                     os.path.exists(os.path.join("port/tree/lib", c))))

    def report(label, sel):
        sub = [r for r in rows if sel(r)]
        if not sub:
            return
        nf = len(sub)
        nl = sum(r[1] for r in sub)
        pf = [r for r in sub if r[2]]
        pl = sum(r[1] for r in pf)
        print("%-14s %4d/%-4d files  %5.1f%%      %7d/%-7d lines  %5.1f%%"
              % (label, len(pf), nf, 100.0 * len(pf) / nf,
                 pl, nl, 100.0 * pl / nl if nl else 0.0))

    print("HOW MUCH OF lib/ IS RUST")
    print()
    report("candidates", lambda r: True)
    report("config-full", lambda r: r[3])
    report("config-fast", lambda r: r[4])
    print()

    # SCOPE.md §3a, Adam's ruling of 2026-09-04: code no x86-64 build compiles
    # is DEFERRED until there is a cross-architecture testing strategy. It
    # stays in the widest denominator -- it is still lib/ -- but it is not
    # work in progress, and a percentage that does not say so invites the
    # reader to think the project is stalled on it.
    defer = [r for r in rows if not r[3] and not r[4]]
    if defer:
        print("DEFERRED, SCOPE.md \u00a73a: %d files / %d lines that neither "
              "config compiles\n%38s(raid6 SIMD, crc/{riscv,s390}, fdt, fonts, "
              "vdso, options nothing turns on).\n%38sNot excluded -- waiting on "
              "a cross-architecture test strategy."
              % (len(defer), sum(r[1] for r in defer), "", ""))
        print()

    resid = [r for r in rows if r[2] and r[5]]
    print("%d of the %d ported files still have C in the tree (a C entry the "
          "port could not\nclose -- logs/c-entry-rule.md); the other %d are "
          "gone." % (len(resid), sum(1 for r in rows if r[2]),
                     sum(1 for r in rows if r[2]) - len(resid)))
    if resid:
        print("   " + " ".join(sorted(r[0] for r in resid)))
    print()

    rc = 0
    if bad:
        print("*** %d Replaces: claim(s) name a file that is not in the "
              "6.18.49 tarball:" % len(bad))
        for c, p in bad:
            print("      lib/%-40s claimed by %s" % (c, p))
        rc = 1
    if dup:
        print("*** %d file(s) claimed by two Rust files:" % len(dup))
        for c, a, b in dup:
            print("      lib/%-40s %s and %s" % (c, a, b))
        rc = 1
    if rc == 0:
        print("%d Replaces: claim(s), all naming a real upstream file, none "
              "claimed twice." % len(claims))
    return rc


if __name__ == "__main__":
    sys.exit(main())
