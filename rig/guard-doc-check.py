#!/usr/bin/env python3
"""guard-doc-check.py <port-tree> -- a C file must not name a guard it lost.

Called by rig/guard-check.sh as its second pass. See that script for why.

Pass 1 of guard-check.sh compares each deleted C entry against port/pristine/,
and it has a blind spot: a guard the PORT introduced or relocated is not in
the pristine body at all. lib/crypto/chacha-block-generic.c is the case that
proves it -- upstream's WARN_ON_ONCE(nrounds != 20 && nrounds != 12) lives in
a static chacha_permute(), and the port moved it up into the two exported
entries when that static became Rust. When a later commit deleted those
entries the WARN went with them, and pass 1 saw nothing, because upstream's
chacha_block_generic() never had a WARN in it.

What DID identify all seven of those defects, read by hand, was that each
file contradicted itself: the header comment said the guard stayed in C, and
the guard was not there. So the rule here is narrow and mechanical -- if a
comment names a guard construct by name, the code must use it.

Naming it by name is the whole test. A comment that merely discusses "a
warning" is not a claim; "WARN_ON_ONCE" is.
"""
import os
import re
import sys

# Families, not exact spellings. lib/crypto/chacha-block-generic.c is why:
# its comment said "the round-count WARN", which names the construct as
# plainly as "WARN_ON_ONCE" does but matches no exact token. So a comment
# naming any member of a family requires the code to use some member of it.
#
# Each entry is (label, comment-pattern, code-pattern). The comment patterns
# are case-sensitive and anchored on word boundaries, so ordinary English --
# "a bug", "warn the caller" -- is not a claim. WARN and BUG_ON in capitals
# are references to the macros and nothing else.
FAMILIES = [
    ("WARN",       r"\bWARN(_ON(_ONCE)?|_ONCE)?\b",   r"\bWARN\w*\s*\("),
    ("BUG_ON",     r"\bBUG_ON\b|\bBUG\(\)",          r"\bBUG_ON\s*\(|\bBUG\s*\("),
    # Reading a static key, not defining one. lib/math/gcd.c kept its
    # DEFINE_STATIC_KEY_TRUE() after the static_branch_likely() that consulted
    # it had been deleted, so accepting the definition as evidence would have
    # let exactly the defect this exists for pass.
    ("static-key branch",
     r"\bstatic_branch\w*\b|\bstatic_key_(enabled|false|true)\w*\b",
     r"\bstatic_branch\w*\s*\(|\bstatic_key_(enabled|false|true)\w*\s*\("),
]


def split_comments(src):
    """Return (comment_text, code_text) for one C translation unit.

    Written out rather than regexed because a regex that thinks a "/*" inside
    a string literal starts a comment would report the opposite of the truth.
    """
    out_c, out_k = [], []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out_c.append(src[i:j])
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out_c.append(src[i:j])
            i = j
        elif src[i] in "\"'":
            q = src[i]
            j = i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            out_k.append(src[i:j + 1])
            i = j + 1
        else:
            out_k.append(src[i])
            i += 1
    return "".join(out_c), "".join(out_k)


def load_exceptions(path):
    """{(file, family): reason} -- see rig/guard-doc-except.txt.

    KEEP IT SHORT. This pass is worth having because naming a guard in a
    comment IS a claim; every entry here is a hole in that.
    """
    out = {}
    try:
        fh = open(path, errors="replace")
    except OSError:
        return out
    with fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                out[(parts[0], parts[1])] = parts[2]
    return out


def main():
    port = sys.argv[1]
    exc = load_exceptions(sys.argv[2] if len(sys.argv) > 2 else "")
    bad = 0
    excused = 0
    scanned = 0
    print("%-46s %s" % ("FILE", "CLAIM"))
    for root, _dirs, files in os.walk(port):
        for f in sorted(files):
            if not f.endswith(".c"):
                continue
            path = os.path.join(root, f)
            rel = os.path.relpath(path, port)
            try:
                src = open(path, errors="replace").read()
            except OSError:
                continue
            scanned += 1
            comments, code = split_comments(src)
            for label, cpat, kpat in FAMILIES:
                if not re.search(cpat, comments) or re.search(kpat, code):
                    continue
                if (rel, label) in exc:
                    excused += 1
                    continue
                print("%-46s *** names %s, code has none" % (rel, label))
                bad += 1
    print()
    print("PASS 2: %d C file(s) scanned; %d name a guard the code no longer has,"
          " %d excused" % (scanned, bad, excused))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
