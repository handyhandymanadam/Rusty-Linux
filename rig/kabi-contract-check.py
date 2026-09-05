#!/usr/bin/env python3
"""kabi-contract-check.py <root> <build> -- see rig/kabi-contract-check.sh."""
import os
import re
import subprocess
import sys
import tempfile

# kabi_export! { SYM, license = "L", namespace = "N", contract = "V", }
EXPORT_RE = re.compile(
    r'kabi_export!\s*[{(]\s*'
    r'(?P<sym>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*'
    r'license\s*=\s*"(?P<license>[^"]*)"\s*,\s*'
    r'namespace\s*=\s*"(?P<ns>[^"]*)"\s*,\s*'
    r'contract\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"\s*,?\s*[})]',
    re.S)

# kabi_rule!("type_string", "TARGET", "VALUE");
RULE_RE = re.compile(
    r'kabi_rule!\s*\(\s*"type_string"\s*,\s*'
    r'"(?P<target>(?:[^"\\]|\\.)*)"\s*,\s*'
    r'"(?P<value>(?:[^"\\]|\\.)*)"\s*,?\s*\)',
    re.S)

# A DWARF back-reference: t# typedef, s# struct, u# union, e# enum
# (scripts/gendwarfksyms/types.c:get_type_prefix). A pin whose target
# looks like one is a TYPE pin; anything else is a SYMBOL pin.
REF_RE = re.compile(r'^[tsue]#')

# KABI_TYPE_STRING("TARGET", "VALUE");  -- the C form, in the files that still
# keep a C entry because it does real work. Same rule, same check: the
# contract is a literal and something has to re-read the C.
C_RULE_RE = re.compile(
    r'KABI_TYPE_STRING\s*\(\s*'
    r'"(?P<target>(?:[^"\\]|\\.)*)"\s*,\s*'
    r'"(?P<value>(?:[^"\\]|\\.)*)"\s*,?\s*\)',
    re.S)


def unescape(s):
    """Undo the Rust string-literal escaping the macro arguments carry."""
    return s.replace('\\"', '"').replace("\\\\", "\\")


def declared(port):
    """Every contract the port asserts: {target: (value, file, symbol?)}.

    Both forms. kernel::kabi_export!/kabi_rule! in .rs, where a Rust object
    carries its own export; KABI_TYPE_STRING() in .c, in the files that still
    keep a C entry because it does real work. A pin is a literal either way.
    """
    out = {}
    for base, _d, files in os.walk(port):
        for f in sorted(files):
            path = os.path.join(base, f)
            rel = os.path.relpath(path, port)
            if f.endswith(".rs"):
                src = open(path, errors="replace").read()
                for m in EXPORT_RE.finditer(src):
                    out[m.group("sym")] = (unescape(m.group("value")), rel,
                                           m.group("sym"))
                for m in RULE_RE.finditer(src):
                    out[unescape(m.group("target"))] = (
                        unescape(m.group("value")), rel, None)
            elif f.endswith(".c"):
                src = open(path, errors="replace").read()
                for m in C_RULE_RE.finditer(src):
                    target = unescape(m.group("target"))
                    # A bare name is a SYMBOL pin; t#/s#/u#/e# is a type pin.
                    sym = None if REF_RE.match(target) else target
                    out[target] = (unescape(m.group("value")), rel, sym)
    return out


def find_object(refdir, sym):
    """The pristine reference object that DEFINES sym."""
    for base, _d, files in os.walk(refdir):
        for f in files:
            if not f.endswith(".o"):
                continue
            path = os.path.join(base, f)
            try:
                nm = subprocess.run(["nm", "--defined-only", path],
                                    capture_output=True, text=True)
            except OSError:
                continue
            for line in nm.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == sym and parts[1] in "TtRrDdBb":
                    return path
    return None


def derive_crc(gdk, obj, syms):
    """{sym: crc} as the PRISTINE C hashes, with no pin in sight."""
    r = subprocess.run([gdk, "--stable", "--dump-versions", obj],
                       input="\n".join(syms) + "\n",
                       capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) == 3 and f[0] == "#SYMVER":
            out[f[1]] = f[2]
    return out


def built_crcs(root, build):
    """{sym: crc} as the kernel we built actually shipped them."""
    out = {}
    path = os.path.join(root, build, "Module.symvers")
    if not os.path.exists(path):
        return out
    for line in open(path, errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 2:
            out[f[1]] = f[0]
    return out


def derive(gdk, obj, syms):
    """Run gendwarfksyms --symtypes and return {target: value}."""
    with tempfile.NamedTemporaryFile("r", suffix=".symtypes",
                                     delete=False) as tf:
        name = tf.name
    try:
        subprocess.run([gdk, "--stable", "--symtypes", name, obj],
                       input="\n".join(syms) + "\n",
                       capture_output=True, text=True)
        out = {}
        with open(name, errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                target, _sp, value = line.partition(" ")
                out[target] = value
        return out
    finally:
        os.unlink(name)


def main():
    root, build = sys.argv[1], sys.argv[2]
    port = os.path.join(root, "port", "tree")
    refdir = os.path.join(root, build, "abi-ref")
    gdk = os.path.join(root, build, "scripts", "gendwarfksyms", "gendwarfksyms")

    decl = declared(port)
    if not decl:
        print("no kabi_export! contracts found under port/tree -- nothing to check")
        return 0

    # Group symbol contracts by the reference object that defines them, so
    # gendwarfksyms is run once per object and its back-references resolve
    # against the same type map the original capture used.
    syms = sorted(t for t, v in decl.items() if v[2] is not None)
    by_obj = {}
    unlocated = []
    for s in syms:
        obj = find_object(refdir, s)
        if obj is None:
            unlocated.append(s)
        else:
            by_obj.setdefault(obj, []).append(s)

    derived = {}
    dcrc = {}
    for obj, ss in sorted(by_obj.items()):
        derived.update(derive(gdk, obj, ss))
        dcrc.update(derive_crc(gdk, obj, ss))
    bcrc = built_crcs(root, build)

    # COMPARE FINGERPRINTS, NOT TEXT.
    #
    # The same signature has more than one faithful spelling. gendwarfksyms
    # emits `t#ucs2_char_t` where that type was already expanded earlier in the
    # string and the full `typedef_type ucs2_char_t { ... }` where it was not,
    # so a pin captured before the --symtypes form was understood reads
    # differently from one captured after -- and hashes identically, because
    # the reference is expanded at first use either way. Comparing text
    # reported five such pins as DIFFERS when nothing had moved.
    #
    # What must hold is that the fingerprint the shipped kernel carries for a
    # symbol is the one the pristine C produces. That is form-independent, and
    # it is the thing an out-of-tree module actually checks. The type strings
    # are still printed when they disagree, because that is what a human needs
    # in order to decide.
    agree = differ = missing = 0
    typeonly = 0
    print("%-34s %-28s %s" % ("TARGET", "DECLARED IN", "VERDICT"))
    for target in sorted(decl):
        value, rel, sym = decl[target]
        if sym is None:
            # A type pin has no fingerprint of its own. It is checked through
            # every symbol whose contract references it.
            typeonly += 1
            continue
        if sym in unlocated:
            print("%-34s %-28s *** NO C REFERENCE" % (target, rel))
            print("      no object under %s/abi-ref defines it. Either"
                  " ./rig/abi-ref.sh %s has not run," % (build, build))
            print("      or it ran and that file did not compile -- read its"
                  " output, do not assume the first.")
            missing += 1
            continue
        if sym not in dcrc:
            print("%-34s %-28s *** NOT IN THE C" % (target, rel))
            print("      the C reference produced no fingerprint for it --"
                  " the symbol may be gone upstream")
            missing += 1
            continue
        if sym not in bcrc:
            print("%-34s %-28s *** NOT EXPORTED BY THE BUILD" % (target, rel))
            print("      %s/Module.symvers has no entry for it" % build)
            missing += 1
            continue
        if dcrc[sym] == bcrc[sym]:
            agree += 1
            continue
        differ += 1
        print("%-34s %-28s *** DIFFERS" % (target, rel))
        print("      the C hashes to %s, the build shipped %s"
              % (dcrc[sym], bcrc[sym]))
        print("      C now:  %s" % derived.get(sym, "<no type string>"))
        print("      pinned: %s" % value)

    print()
    print("%d contract(s) agree with the C, %d DIFFER, %d unresolved"
          " (+%d type pin(s), checked through the symbols that use them)"
          % (agree, differ, missing, typeonly))
    if differ or missing:
        print()
        print("This is the diff, and it is the product. Nothing here has been")
        print("changed for you: a contract that updates itself to match reality")
        print("can never disagree with it, so its alarm can never fire.")
        print("Read each difference, decide whether the ABI really moved, and")
        print("edit the kabi_export! by hand -- or fix the Rust instead.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
