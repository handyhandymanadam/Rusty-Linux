#!/usr/bin/env python3
"""kabi-migrate.py <root> <build> <file.c> [...]  [--dry-run]

Move a C file's EXPORT_SYMBOL lines and MODVERSIONS contracts into the Rust
that already defines the symbols, then delete the C file.

WHY A TOOL AND NOT AN EDITOR. Point 2 of logs/abi-contract-design.md:
GENERATED, NEVER TYPED. A contract is a 60-to-600 character literal in which a
single wrong character silently changes a fingerprint. Thirteen files, 44
exports and about 75 contracts is exactly the volume at which hand
transcription starts producing one silent error.

WHAT IT REFUSES TO DO, rather than guess:
  - a C file that still DEFINES a function. That C is doing work; see
    rig/guard-check.sh and the seven closures that deleted guards.
  - a symbol whose #[no_mangle] definition it cannot find in exactly one .rs.
  - a symbol whose licence or namespace in the C macro disagrees with the
    baseline Module.symvers. The baseline is the authority: it is what shipped.
  - a Makefile whose object token does not appear exactly once.
  - a contract it cannot derive from port/pristine/ via the reference build.

CONTRACTS ARE RE-DERIVED, NOT COPIED. The KABI_TYPE_STRING() literals already
in the C file were captured from the built object; this reads port/pristine/
compiled by rig/abi-ref.sh instead, so the result is checkable afterwards by
rig/kabi-contract-check.sh against the same source. Copying them forward would
carry any error forward with them.
"""
import os
import re
import subprocess
import sys

EXPORT_RE = re.compile(
    r'^\s*EXPORT_SYMBOL(?P<ns>_NS)?(?P<gpl>_GPL)?\s*\(\s*'
    r'(?P<sym>[A-Za-z_][A-Za-z0-9_]*)\s*(?:,\s*(?P<nsval>[^)]*?)\s*)?\)\s*;',
    re.M)
FN_DEF_RE = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_ \*]*\b([a-zA-Z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{',
    re.M)
REF_RE = re.compile(r'\b[tsue]#[A-Za-z0-9_.$]+')


def strip_comments(src):
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def die(msg):
    print("REFUSED: %s" % msg)
    sys.exit(1)


def baseline_exports(root):
    """{sym: (license, namespace)} from the shipped baseline."""
    out = {}
    for name in ("Module.symvers-build-full", "Module.symvers-build-fast"):
        path = os.path.join(root, "logs", "baseline", name)
        if not os.path.exists(path):
            continue
        for line in open(path, errors="replace"):
            f = line.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            lic = "GPL" if f[3] == "EXPORT_SYMBOL_GPL" else ""
            ns = f[4] if len(f) > 4 else ""
            out.setdefault(f[1], (lic, ns))
    return out


def find_rs(port, sym):
    """The .rs files defining `sym` under #[no_mangle]."""
    hits = []
    pat = re.compile(
        r'#\[no_mangle\][^\n]*\n(?:\s*#\[[^\n]*\]\s*\n)*\s*pub\s+(?:unsafe\s+)?'
        r'extern\s+"C"\s+fn\s+' + re.escape(sym) + r'\s*[(<]')
    for base, _d, files in os.walk(port):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(base, f)
            if pat.search(open(p, errors="replace").read()):
                hits.append(p)
    return hits


def find_ref_object(refdir, syms):
    """One reference object defining all of syms."""
    for base, _d, files in os.walk(refdir):
        for f in sorted(files):
            if not f.endswith(".o"):
                continue
            p = os.path.join(base, f)
            nm = subprocess.run(["nm", "--defined-only", p],
                                capture_output=True, text=True)
            defined = {l.split()[2] for l in nm.stdout.splitlines()
                       if len(l.split()) >= 3}
            if set(syms) <= defined:
                return p
    return None


def derive(gdk, obj, syms):
    import tempfile
    with tempfile.NamedTemporaryFile("r", suffix=".symtypes", delete=False) as tf:
        name = tf.name
    try:
        r = subprocess.run([gdk, "--stable", "--symtypes", name, obj],
                           input="\n".join(syms) + "\n",
                           capture_output=True, text=True)
        if r.returncode != 0:
            die("gendwarfksyms failed on %s:\n%s" % (obj, r.stderr.strip()))
        out = {}
        for line in open(name, errors="replace"):
            line = line.rstrip("\n")
            if line:
                t, _sp, v = line.partition(" ")
                out[t] = v
        return out
    finally:
        os.unlink(name)


def closure(target, table, seen):
    """Every t#/s#/u#/e# reference reachable from target's value."""
    for ref in REF_RE.findall(table.get(target, "")):
        if ref in seen:
            continue
        if ref not in table:
            die("contract for %s references %s, which the reference build did "
                "not define" % (target, ref))
        seen.add(ref)
        closure(ref, table, seen)
    return seen


def rs_insert(text, sym, block):
    """Insert `block` above the item that defines `sym`, doc comments and all."""
    m = re.search(r'#\[no_mangle\]', text)
    pat = re.compile(
        r'#\[no_mangle\][^\n]*\n(?:\s*#\[[^\n]*\]\s*\n)*\s*pub\s+(?:unsafe\s+)?'
        r'extern\s+"C"\s+fn\s+' + re.escape(sym) + r'\s*[(<]')
    m = pat.search(text)
    if not m:
        die("cannot locate #[no_mangle] fn %s for insertion" % sym)
    # Walk back over the attribute/doc-comment block so the docs stay attached
    # to the function and not to the macro we are about to insert.
    start = text.rfind("\n", 0, m.start()) + 1
    lines = text[:start].split("\n")
    i = len(lines) - 1
    while i > 0:
        prev = lines[i - 1].strip()
        if prev.startswith("///") or prev.startswith("#[") or prev.startswith("//!"):
            i -= 1
        else:
            break
    at = len("\n".join(lines[:i]))
    at = at + 1 if at else 0
    return text[:at] + block + text[at:]


def edit_makefile(path, token, dry):
    """Remove `token` from the one Makefile line that builds it.

    Comment lines are counted separately and never edited. lib/math/Makefile
    carries a comment naming int_pow.o and int_sqrt.o, which made a naive
    whole-file count say 2 and refuse a migration that was fine. A stale
    comment is a real thing to fix, but by a person, not by a regex.
    """
    pat = re.compile(r'(?<![\w.-])' + re.escape(token) + r'(?![\w.-])')
    lines = open(path).read().split("\n")
    code_hits = [i for i, l in enumerate(lines)
                 if not l.lstrip().startswith("#") and pat.search(l)]
    cmt_hits = [i for i, l in enumerate(lines)
                if l.lstrip().startswith("#") and pat.search(l)]
    if len(code_hits) != 1:
        die("%s appears on %d build line(s) of %s -- expected exactly 1"
            % (token, len(code_hits), path))
    i = code_hits[0]
    lines[i] = re.sub(r'(?<![\w.-])' + re.escape(token) + r'\s*', '',
                      lines[i], count=1).rstrip()
    if not dry:
        open(path, "w").write("\n".join(lines))
    if cmt_hits:
        print("    NOTE: %s is still named in a COMMENT at %s:%s -- now stale,"
              " fix it by hand"
              % (token, os.path.basename(path),
                 ",".join(str(n + 1) for n in cmt_hits)))
    return True


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv
    root, build, files = args[0], args[1], args[2:]
    port = os.path.join(root, "port", "tree")
    refdir = os.path.join(root, build, "abi-ref")
    gdk = os.path.join(root, build, "scripts", "gendwarfksyms", "gendwarfksyms")
    base_exports = baseline_exports(root)

    for rel in files:
        cpath = os.path.join(port, rel)
        if not os.path.exists(cpath):
            die("no such file: %s" % cpath)
        src = open(cpath, errors="replace").read()
        code = strip_comments(src)

        fns = [m for m in FN_DEF_RE.finditer(code)
               if m.group(1) not in ("if", "for", "while", "switch", "return")]
        if fns:
            die("%s still defines %s -- that C is doing work, not holding a pin"
                % (rel, ", ".join(m.group(1) for m in fns)))

        exports = []
        for m in EXPORT_RE.finditer(code):
            sym = m.group("sym")
            lic = "GPL" if m.group("gpl") else ""
            ns = (m.group("nsval") or "").strip().strip('"') if m.group("ns") else ""
            exports.append((sym, lic, ns))
        if not exports:
            die("%s exports nothing" % rel)

        for sym, lic, ns in exports:
            if sym not in base_exports:
                die("%s is not in the baseline Module.symvers" % sym)
            blic, bns = base_exports[sym]
            if (blic, bns) != (lic, ns):
                die("%s: the C macro says licence %r namespace %r, the baseline "
                    "says %r %r" % (sym, lic, ns, blic, bns))

        syms = [s for s, _l, _n in exports]
        obj = find_ref_object(refdir, syms)
        if obj is None:
            die("no object under %s defines all of %s -- run ./rig/abi-ref.sh %s"
                % (refdir, " ".join(syms), build))
        table = derive(gdk, obj, syms)
        for s in syms:
            if s not in table:
                die("the reference build produced no contract for %s" % s)

        # Which .rs file owns each symbol
        owner = {}
        for s in syms:
            hits = find_rs(port, s)
            if len(hits) != 1:
                die("%s is defined by %d .rs files (%s) -- expected exactly 1"
                    % (s, len(hits), ", ".join(os.path.relpath(h, port)
                                               for h in hits)))
            owner[s] = hits[0]

        print("=== %s  ->  %s" % (rel, ", ".join(sorted(
            {os.path.relpath(p, port) for p in owner.values()}))))
        print("    reference: %s" % os.path.relpath(obj, root))

        for rs in sorted(set(owner.values())):
            mine = [s for s in syms if owner[s] == rs]
            refs = set()
            for s in mine:
                closure(s, table, refs)
            text = open(rs, errors="replace").read()

            if refs:
                head = ["// The C types these contracts name. A Rust object has\n"
                        "// no C type graph to resolve them against, so they are\n"
                        "// not duplicates of anything -- omit one and the build\n"
                        "// stops naming the reference it could not resolve.\n"
                        "// Generated by rig/kabi-migrate.py; do not hand-edit.\n"]
                for r in sorted(refs):
                    head.append('kernel::kabi_rule!("type_string", "%s",\n    "%s");\n'
                                % (r, table[r]))
                head.append("\n")
                first = min(mine, key=lambda s: syms.index(s))
                text = rs_insert(text, first, "".join(head))

            for s in mine:
                lic, ns = base_exports[s]
                block = ("kernel::kabi_export! {\n"
                         "    %s,\n"
                         "    license = \"%s\",\n"
                         "    namespace = \"%s\",\n"
                         "    contract = \"%s\",\n"
                         "}\n\n" % (s, lic, ns, table[s]))
                text = rs_insert(text, s, block)
                print("    %-28s %s  %s" % (s, "EXPORT_SYMBOL_GPL" if lic
                                            else "EXPORT_SYMBOL",
                                            os.path.relpath(rs, port)))
            if not dry:
                open(rs, "w").write(text)

        # Makefile
        token = os.path.basename(rel)[:-2] + ".o"
        mk = os.path.join(port, os.path.dirname(rel), "Makefile")
        if not os.path.exists(mk):
            die("no Makefile beside %s to remove %s from" % (rel, token))
        edit_makefile(mk, token, dry)
        print("    Makefile: dropped %s from %s"
              % (token, os.path.relpath(mk, port)))
        if not dry:
            os.unlink(cpath)
        print("    %s %s" % ("would delete" if dry else "deleted", rel))
    return 0


if __name__ == "__main__":
    sys.exit(main())
