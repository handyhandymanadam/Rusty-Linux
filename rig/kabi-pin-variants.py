#!/usr/bin/env python3
"""kabi-pin-variants.py [--apply FILE.rs] BUILD_DIR...

GENERATE THE kabi_rule! TYPE PINS OF ONE PORTED FILE FOR EVERY (ARCH, CONFIG)
VARIANT AT ONCE, from each build's own pristine C reference object.

WHY (logs/arm64.md failure 7). A pin for a struct pointee (`s#task_struct`,
`s#file`, `s#device`...) is a literal copy of what gendwarfksyms hashes, and
the hash covers the struct's full layout. That layout varies by Kconfig (the
x86 fast/full split already in lib/buildid_rs.rs) AND by ARCH (arm64's
task_struct, device, file, ... differ). Hand-copying one closure per variant
does not scale; this reads them all and emits the minimal cfg-keyed set.

HOW. For each BUILD_DIR the variant is read from its .config:
  arch   = x86_64 if CONFIG_X86_64, aarch64 if CONFIG_ARM64 (add one line for
           riscv64: CONFIG_RISCV -> "riscv64")
  vmcore = CONFIG_VMCORE_INFO, the project's existing discriminant for "which
           of our two Kconfig families is this" (see lib/buildid_rs.rs).
The symbols are the kabi_export! names in FILE.rs; their symtypes closure is
taken from BUILD_DIR/abi-ref/<same path as FILE>.o with that build's own
gendwarfksyms (--stable, exactly as rig/kabi-contract-check.py does).
A tag whose text is identical in every variant is emitted unconditionally;
otherwise each distinct text goes in a `mod` under the cfg that selects the
variants carrying it. A variant that never references a tag is a don't-care
and joins the first text (an unreferenced rule is inert).

With --apply it replaces the text between the
`// BEGIN GENERATED KABI PINS` and `// END GENERATED KABI PINS` markers of
FILE.rs. It never touches a kabi_export! contract: those stay hand-accepted
(rig/kabi-contract-check.sh re-derives and compares them).
"""
import os
import re
import subprocess
import sys

# The Kconfig symbol that separates our "fast" family from our "full" family, per arch.
# CONFIG_VMCORE_INFO does it on x86 and arm64. On riscv64 it does NOT (the riscv defconfig
# lacks CRASH_DUMP, so VMCORE_INFO is off in BOTH families while string_helpers' closure
# differs in ~120 tags: logs/riscv64.md), so riscv64 uses CONFIG_UPROBES (on in defconfig,
# off in allnoconfig+fast.fragment; it adds uprobe_task etc. to task_struct/mm_struct).
DISC = {"riscv64": "CONFIG_UPROBES"}

BEGIN = "// BEGIN GENERATED KABI PINS"
END = "// END GENERATED KABI PINS"
EXPORT_NAME = re.compile(r'kabi_export!\s*[{(]\s*([A-Za-z_][A-Za-z0-9_]*)\s*,')


def variant(build):
    cfg = {}
    for line in open(os.path.join(build, ".config")):
        m = re.match(r'(CONFIG_\w+)=(.*)', line.strip())
        if m:
            cfg[m.group(1)] = m.group(2)
    if "CONFIG_X86_64" in cfg:
        arch = "x86_64"
    elif "CONFIG_ARM64" in cfg:
        arch = "aarch64"
    elif "CONFIG_RISCV" in cfg:
        arch = "riscv64"
    else:
        sys.exit("%s: unknown ARCH in .config" % build)
    return arch, DISC.get(arch, "CONFIG_VMCORE_INFO") in cfg


def symtypes(build, rel_obj, syms):
    gdk = os.path.join(build, "scripts/gendwarfksyms/gendwarfksyms")
    obj = os.path.join(build, "abi-ref", rel_obj)
    out = os.path.join(build, "abi-ref", ".variants.symtypes")
    if os.path.exists(out):
        os.unlink(out)
    subprocess.run([gdk, "--stable", "--symtypes", out, obj],
                   input="\n".join(syms) + "\n", capture_output=True, text=True)
    tags = {}
    for line in open(out, errors="replace"):
        t, _, v = line.rstrip("\n").partition(" ")
        if re.match(r'^[tsue]#', t):
            tags[t] = v
    os.unlink(out)
    return tags


def cond(v):
    arch, vm = v
    return 'all(target_arch = "%s", %s%s%s)' % (
        arch, "" if vm else "not(", DISC.get(arch, "CONFIG_VMCORE_INFO"), "" if vm else ")")


def main():
    args = sys.argv[1:]
    apply = None
    if args[:1] == ["--apply"]:
        apply, args = args[1], args[2:]
    if not apply or not args:
        sys.exit("usage: kabi-pin-variants.py --apply FILE.rs BUILD_DIR...")
    src = open(apply).read()
    syms = sorted(set(EXPORT_NAME.findall(src)))
    rel = os.path.relpath(apply, "port/tree")
    rel_obj = rel[:-len("_rs.rs")] + ".o" if rel.endswith("_rs.rs") else rel[:-3] + ".o"
    per = []
    for b in args:
        per.append((variant(b), symtypes(b, rel_obj, syms), b))
    variants = [p[0] for p in per]
    if len(set(variants)) != len(variants):
        sys.exit("two builds map to the same variant: %s" % variants)
    all_tags = sorted(set(t for _, tg, _ in per for t in tg))
    # group: cfg-set -> [(tag, value)]
    groups = {}
    for t in all_tags:
        byval = {}
        for v, tg, _ in per:
            if t in tg:
                byval.setdefault(tg[t], []).append(v)
        vals = list(byval.items())
        if len(vals) == 1:
            groups.setdefault(None, []).append((t, vals[0][0]))
            continue
        absent = [v for v in variants if all(v not in vs for _, vs in vals)]
        vals[0] = (vals[0][0], vals[0][1] + absent)
        for val, vs in vals:
            groups.setdefault(tuple(sorted(vs)), []).append((t, val))

    def rule(t, val, ind):
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
        return '%skernel::kabi_rule!("type_string", "%s", "%s");\n' % (ind, esc(t), esc(val))

    o = [BEGIN + " -- rig/kabi-pin-variants.py, variants: %s\n" %
         ", ".join("%s%s" % (a, "+vmcore" if m else "") for (a, m) in variants)]
    for t, val in groups.pop(None, []):
        o.append(rule(t, val, ""))
    for key in sorted(groups):
        name = "_kabi_pins_" + "_".join("%s_%s" % (a, "full" if m else "fast") for a, m in key)
        pred = "any(%s)" % ", ".join(cond(v) for v in key) if len(key) > 1 else cond(key[0])
        o.append("#[cfg(%s)]\nmod %s {\n" % (pred, name))
        for t, val in groups[key]:
            o.append(rule(t, val, "    "))
        o.append("}\n")
    o.append(END + "\n")
    block = "".join(o)
    i, j = src.index(BEGIN), src.index(END) + len(END) + 1
    open(apply, "w").write(src[:i] + block + src[j:])
    print("%s: %d tags written for %d variants" % (apply, len(all_tags), len(variants)))


if __name__ == "__main__":
    main()
