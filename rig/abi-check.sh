#!/usr/bin/env bash
# abi-check.sh <build-dir>
#
# THE SIGNATURE INSPECTOR. Every Rust body reached through a C entry thunk is
# measured against the C declaration it must match -- return type and every
# parameter, by width and kind, out of the DWARF of the built kernel.
#
# WHY IT EXISTS. Adam, 2026-09-04, deciding to pursue the thunk-free path:
# "we do this now rather than try to bolt this all on later... we are getting
# the right tools in place that we will most definitely need in the future."
#
# THE DEFECT THAT DEMANDS IT, demonstrated by adversarial review the same day
# and NOT hypothetical. The Rust `_bcd2bin(val: u8) -> c_uint` was changed to
# `_bcd2bin(val: u64) -> u64` -- flatly wrong against the header's
# `unsigned _bcd2bin(unsigned char)`. The result:
#
#     build      clean, exit 0, no warning
#     CRC        0xdf37db04, unchanged
#     module     loaded, and printed the RIGHT ANSWER
#
# because clang happened to zero-extend the register. A latent ABI break
# invisible at every layer this project owns. Written as a C thunk the same
# drift is caught instantly -- "error: conflicting types for '_bcd2bin'" --
# and THAT is the check we would lose by deleting thunks. This rebuilds it.
#
# Note it is not a testing gap: a behavioural test PASSES on the broken build.
# The check has to be static, and this one is.
#
# ---------------------------------------------------------------------------
# THE FIRST VERSION OF THIS FILE WAS ITSELF THE DEFECT. Adversarial review
# found it compared C against C on 47 of 49 pairs and reported `ok` on the very
# sabotage above. The mechanism, measured, not guessed:
#
#     $ llvm-dwarfdump --name=rust_bcd2bin vmlinux
#     0x016a048a: DW_TAG_subprogram              <-- FIRST, and it is the
#                   DW_AT_name ("rust_bcd2bin")      THUNK'S C FORWARD
#                   DW_AT_decl_file ("lib/bcd.c")    DECLARATION
#                   DW_AT_type ("unsigned int")
#                   DW_AT_declaration (true)
#     0x016a04fd: DW_TAG_subprogram              <-- the actual Rust body
#                   DW_AT_decl_file ("bcd_rs.rs")
#                   DW_AT_type ("u32")
#
# The old reader took the first DW_TAG_subprogram and stopped. So it read the
# C declaration OF the Rust function and compared it to the C thunk: two C
# signatures that agree by construction. It could not have failed.
#
# THREE STRUCTURAL RULES NOW MAKE THAT CLASS OF ERROR IMPOSSIBLE, rather than
# merely fixed:
#
#   1. ONLY DEFINITIONS COUNT, and the discriminator is DW_AT_declaration --
#      NOT DW_AT_low_pc. A first attempt used low_pc and was wrong: a function
#      that is always inlined has NO out-of-line copy, so its definition
#      carries DW_AT_inline and no low_pc. `rust_ucs2_strnlen` is exactly that,
#      and requiring low_pc reported it "missing" while its types sat in plain
#      view. DW_AT_declaration(true) is what actually marks a declaration.
#   2. THE LANGUAGE OF EACH SIDE IS ASSERTED. The Rust side must come from a
#      DIE whose DW_AT_decl_file ends in `.rs`, the C side from one ending in
#      `.c`. If either is wrong the pair FAILS -- it does not silently pass.
#      Had this rule existed, the original defect would have been reported on
#      its first run instead of by review.
#   3. FAIL CLOSED. A type that cannot be classified to a width and a kind is
#      an error, never an assumption. Structs by value, unions, floats and
#      arrays are reported UNRESOLVED rather than compared by size, because
#      two different structs of the same size are not the same ABI.
#
# SPEED. The old version made two dwarfdump calls per pair and took 1m36s --
# longer than the kernel build it checks, which is how a guard stops being run.
# llvm-dwarfdump accepts repeated --name and the cost is dominated by scanning
# the file, not by the number of names (measured: 3 names 0.83s, 1 name 0.78s).
# So every symbol is fetched in ONE pass, and unknown types in one more.
# Measured after the change: 2.5s. That batching has a trap, and it cost a
# round of false mismatches. With several --name flags, dwarfdump ALSO prints
# every DW_TAG_inlined_subroutine whose abstract origin bears a matching name,
# re-emitted as a TOP-LEVEL entry. Those call-site DIEs carry formal_parameters
# that have only DW_AT_abstract_origin and no DW_AT_type -- so a reader that
# does not reset its state on a non-subprogram at depth 0 silently appends
# empty parameters to whatever subprogram it saw last. That is where
# `ucs2_strlen` grew two parameters it does not have.
#
# WHEN THE THUNKS GO, the C side must come from a pristine-C reference build
# instead of from vmlinux, because there will be no C definition left to read,
# and the pairing must come from a manifest instead of from thunk source. The
# comparison logic below does not change; only where the C side is sourced.
# That is deliberately NOT built yet -- speculative machinery for a world that
# does not exist would itself be untested.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: abi-check.sh <build-dir>}
[ -d "$root/$build" ] && build="$root/$build"
vmlinux="$build/vmlinux"
[ -f "$vmlinux" ] || { echo "no vmlinux at $vmlinux" >&2; exit 2; }
command -v llvm-dwarfdump >/dev/null || { echo "llvm-dwarfdump not found" >&2; exit 2; }

exec python3 - "$root" "$vmlinux" <<'PYEOF'
import os, re, subprocess, sys

root, vmlinux = sys.argv[1], sys.argv[2]
build_dir = os.path.dirname(vmlinux)

# ---------------------------------------------------------------- pairing
# WHAT REACHES THE COMPARISON IS THE WHOLE BALLGAME. Adversarial review broke
# this guard twice, and both times the comparison engine was correct -- the
# defect was in what never got to it.
#
# The first pairing rule demanded the thunk body be EXACTLY `return rust_X(a);`.
# That silently dropped 20 of 71 true pass-throughs: every void-returning thunk
# (`rust_plist_add(node, head);` -- no `return` keyword) and every thunk with a
# guard statement first (`BUG_ON(...)`, `WARN_ON_ONCE(...)`). A `u32` -> `u64`
# break planted in `arc4_crypt` built clean and the guard printed
# `0 MISMATCH, exit 0` -- with NO LINE for arc4_crypt at all, before or after.
#
# That is the worst outcome available: not a wrong verdict but no verdict,
# under a summary that reads like coverage. So there are now two rules:
#
#   A. A thunk qualifies if its LAST STATEMENT is a tail call passing exactly
#      its own parameters in order, with or without `return`. Found by matching
#      braces, not by a regex that guesses at body shape.
#   B. EVERY rust_* hand-off that does not pair is a HARD FAILURE unless it is
#      declared in rig/abi-except.txt with a reason. A wider regex would only
#      postpone this; the structural rule is what makes the next unanticipated
#      thunk shape loud instead of invisible.
FUNC = re.compile(r'^([A-Za-z_][\w \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.M)
TAIL = re.compile(r'(?:return\s+)?([A-Za-z_]\w*)\s*\(([^;()]*(?:\([^()]*\)[^;()]*)*)\)\s*;\s*$', re.S)
HANDOFF = re.compile(r'\b(rust_\w+)\s*\(')

def strip_comments(t):
    t = re.sub(r'/\*.*?\*/', ' ', t, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', t)

def functions(src):
    """Yield (name, params, body) using real brace matching."""
    for m in FUNC.finditer(src):
        depth, i = 0, m.end() - 1
        for j in range(i, len(src)):
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    yield m.group(2), m.group(3), src[i + 1:j]
                    break

def names_of(params):
    out = []
    for p in params.split(','):
        p = p.strip()
        if not p or p == 'void':
            continue
        out.append(p.split()[-1].lstrip('*').split('[')[0])
    return out

pairs = []
all_handoffs = set()
for dirpath, _, files in os.walk(os.path.join(root, "port", "tree")):
    for fn in sorted(files):
        if not fn.endswith(".c"):
            continue
        src = strip_comments(open(os.path.join(dirpath, fn), errors="ignore").read())
        all_handoffs.update(HANDOFF.findall(src))
        for cname, params, body in functions(src):
            m = TAIL.search(body.strip())
            if not m or not m.group(1).startswith("rust_"):
                continue
            anames = [a.strip() for a in m.group(2).split(",") if a.strip()]
            if names_of(params) == anames:
                pairs.append((cname, m.group(1)))
# THE THUNK-FREE SHAPE. When a thunk is deleted, Rust defines the exported
# symbol itself and the `rust_` prefix disappears -- so the pair vanishes, the
# hand-off vanishes, and even the undeclared-unpaired rule sees nothing to
# complain about. The guard would go quiet exactly where it is needed most.
#
# So: a second pairing source derived from the Rust rather than from the thunk
# being deleted. A `#[no_mangle] extern "C" fn NAME` whose NAME does not start
# with `rust_` is a symbol Rust owns outright, and its C authority is then the
# HEADER DECLARATION -- the same DW_AT_declaration DIE that Rule 1 discards in
# the thunk shape, because post-thunk the declaration is exactly what C callers
# compile against and no C definition exists at all.
NOMANGLE = re.compile(
    r'#\[no_mangle\]\s*(?:#\[[^\]]*\]\s*)*'
    r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z_]\w*)')
direct = set()
for dirpath, _, files in os.walk(os.path.join(root, "port", "tree")):
    for fn in sorted(files):
        if fn.endswith(".rs"):
            src = open(os.path.join(dirpath, fn), errors="ignore").read()
            direct.update(n for n in NOMANGLE.findall(src) if not n.startswith("rust_"))
pairs = sorted(set(pairs) | {(d, d) for d in direct})
if not pairs:
    print("no pass-through thunks found -- nothing to check", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------- one dump
def dwarfdump(names, children):
    """Fetch many named DIEs in ONE pass. Repeated --name is what makes this
    cheap; the file scan dominates, so N names cost what 1 name costs."""
    if not names:
        return ""
    cmd = ["llvm-dwarfdump"] + ["--name=%s" % n for n in sorted(set(names))]
    if children:
        cmd.append("--show-children")
    cmd.append(vmlinux)
    return subprocess.run(cmd, capture_output=True, text=True).stdout

# THE PRISTINE C REFERENCE, built by rig/abi-ref.sh: the unmodified upstream
# .c compiled with kbuild's own command line. For a subsystem whose C callers
# are all gone this is the ONLY C-side authority left, and it is a better one
# than a header declaration because it carries the original PARAMETER NAMES.
refobjs = []
for _dp, _, _fs in os.walk(os.path.join(build_dir, "abi-ref")):
    refobjs += [os.path.join(_dp, _f) for _f in _fs if _f.endswith(".o")]

def dwarfdump_refs(names):
    if not names or not refobjs:
        return ""
    cmd = (["llvm-dwarfdump"] + ["--name=%s" % n for n in sorted(set(names))]
           + ["--show-children"] + sorted(refobjs))
    return subprocess.run(cmd, capture_output=True, text=True).stdout

DIE = re.compile(r'^(0x[0-9a-f]+):(\s*)(DW_TAG_\w+)')
ATTR = re.compile(r'^\s*(DW_AT_\w+)\s*\((.*)\)\s*$')
QUOTED = re.compile(r'"([^"]*)"')

def parse(text):
    """Yield (depth, tag, {attr: rawvalue}) in document order."""
    cur = None
    for line in text.splitlines():
        m = DIE.match(line)
        if m:
            if cur:
                yield cur
            cur = (len(m.group(2)) // 2, m.group(3), {})
            continue
        if cur is None:
            continue
        a = ATTR.match(line)
        if a:
            cur[2].setdefault(a.group(1), a.group(2))
    if cur:
        yield cur

def typename(raw):
    """DW_AT_type is `(0xNNN "spelling")`; we want the spelling."""
    m = QUOTED.search(raw or "")
    return m.group(1) if m else ""

# The ATTR regex stores what is INSIDE the parentheses, so a DW_AT_type value
# arrives as `0x000000da "ERR_enum"` with no leading paren. Anchoring on `(`
# matched nothing and every offset came back empty -- silently, because an
# empty offset just skips the fallback.
OFFS = re.compile(r'^\s*(0x[0-9a-f]+)')

def typeoff(raw):
    """...and sometimes we need the OFFSET instead. An ANONYMOUS type has no
    name to look up -- DWARF renders it `"enumeration "` -- so the only way to
    reach it is the offset its parent points at. ERR_enum -> ZSTD_ErrorCode ->
    an unnamed enumeration is a real chain in lib/zstd, and by name alone it is
    a dead end."""
    m = OFFS.search(raw or "")
    return m.group(1) if m else ""

# offset -> (byte_size, encoding-ish kind) per object file, built lazily. The
# reference objects are small -- zstd_common.o dumps to 514 lines -- so a full
# --debug-info pass over one of them is cheap, unlike over vmlinux.
_OFFCACHE = {}

def resolve_by_offset(obj, off, depth=0):
    if not obj or not off or depth > 8:
        return ""
    if obj not in _OFFCACHE:
        txt = subprocess.run(["llvm-dwarfdump", "--debug-info", obj],
                             capture_output=True, text=True).stdout
        idx, cur = {}, None
        for line in txt.splitlines():
            m = DIE.match(line)
            if m:
                cur = {"tag": m.group(3)}
                idx[m.group(1)] = cur
                continue
            if cur is None:
                continue
            a = ATTR.match(line)
            if a:
                cur.setdefault(a.group(1), a.group(2))
        _OFFCACHE[obj] = idx
    die = _OFFCACHE[obj].get(off)
    if not die:
        return ""
    tag = die["tag"]
    if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
        return resolve_by_offset(obj, typeoff(die.get("DW_AT_type", "")), depth + 1)
    if tag == "DW_TAG_pointer_type":
        return "8:p"
    if tag in ("DW_TAG_enumeration_type", "DW_TAG_base_type"):
        m = re.search(r'0x[0-9a-f]+|\d+', die.get("DW_AT_byte_size", ""))
        if not m:
            return ""
        n = int(m.group(0), 0)
        enc = die.get("DW_AT_encoding", "")
        if tag == "DW_TAG_enumeration_type":
            return "%d:e" % n
        if "float" in enc:
            return ""
        return "%d:%s" % (n, "u" if ("unsigned" in enc or "boolean" in enc) else "s")
    return ""

# Collect every DEFINITION of every symbol we care about, keyed by name.
wanted = {n for pair in pairs for n in pair}
subs = {}      # DEFINITIONS, by name
decls = {}     # HEADER DECLARATIONS, by name -- only for thunk-free symbols
cur = None     # which record the next formal_parameter belongs to
depth_of_sub = 0
for depth, tag, at in parse(dwarfdump(wanted, children=True)):
    if depth == 0:
        # A new top-level entry ends the previous one, WHATEVER its tag.
        # Without this, a top-level DW_TAG_inlined_subroutine (which dwarfdump
        # emits for a batched --name matching its abstract origin) leaves the
        # previous subprogram open and donates its untyped parameters to it.
        cur, depth_of_sub = None, 0
    if tag == "DW_TAG_subprogram":
        depth_of_sub, cur = depth, None
        nm = QUOTED.search(at.get("DW_AT_name", ""))
        nm = nm.group(1) if nm else ""
        if nm not in wanted:
            continue
        f = typename(at.get("DW_AT_decl_file", "")) or at.get("DW_AT_decl_file", "")
        rec = {"file": f, "ret": typename(at.get("DW_AT_type", "")), "params": []}
        is_decl = "true" in at.get("DW_AT_declaration", "")
        if is_decl:
            # A declaration is a definition's opposite -- keep it ONLY as the
            # post-thunk C authority, and only from a header.
            if nm in direct and f.endswith(".h"):
                decls.setdefault(nm, []).append(rec)
                cur = rec
            continue
        # RULE 1: an always-inlined function has no low_pc but IS a definition.
        if "DW_AT_low_pc" not in at and "DW_AT_inline" not in at:
            continue
        subs.setdefault(nm, []).append(rec)
        cur = rec
    elif cur is not None and depth == depth_of_sub + 1:
        # Only DIRECT children are the signature. Parameters of an inlined
        # callee, and variables in lexical blocks, sit deeper.
        if tag == "DW_TAG_formal_parameter":
            cur["params"].append(typename(at.get("DW_AT_type", "")))
        elif tag == "DW_TAG_unspecified_parameters":
            cur["params"].append("...")

# Definitions of thunk-free symbols, out of the pristine reference objects.
refs = {}
_cur = None
_d0 = 0
_obj = ""
_reftext = dwarfdump_refs(direct & wanted)
_objline = re.compile(r'^(\S+):\s+file format')
_lines = []
for _l in _reftext.splitlines():
    m = _objline.match(_l)
    if m:
        _lines.append(("__OBJ__", m.group(1)))
    else:
        _lines.append((None, _l))
def _parse_tagged(items):
    global _obj
    buf = []
    for kind, val in items:
        if kind == "__OBJ__":
            for r in parse("\n".join(buf)):
                yield r
            buf = []
            _obj = val
            continue
        buf.append(val)
    for r in parse("\n".join(buf)):
        yield r
for depth, tag, at in _parse_tagged(_lines):
    if depth == 0:
        _cur, _d0 = None, 0
    if tag == "DW_TAG_subprogram":
        _d0, _cur = depth, None
        nm = QUOTED.search(at.get("DW_AT_name", ""))
        nm = nm.group(1) if nm else ""
        if nm not in direct or "true" in at.get("DW_AT_declaration", ""):
            continue
        if "DW_AT_low_pc" not in at and "DW_AT_inline" not in at:
            continue
        f = typename(at.get("DW_AT_decl_file", "")) or at.get("DW_AT_decl_file", "")
        if not f.endswith(".c"):
            continue
        _cur = {"file": f, "ret": typename(at.get("DW_AT_type", "")), "params": [],
                "obj": _obj, "retoff": typeoff(at.get("DW_AT_type", "")), "paramoffs": []}
        refs.setdefault(nm, []).append(_cur)
    elif _cur is not None and depth == _d0 + 1:
        if tag == "DW_TAG_formal_parameter":
            _cur["params"].append(typename(at.get("DW_AT_type", "")))
            _cur["paramoffs"].append(typeoff(at.get("DW_AT_type", "")))
        elif tag == "DW_TAG_unspecified_parameters":
            _cur["params"].append("...")
            _cur["paramoffs"].append("")

# FAIL CLOSED ON A BINARY WITH NO DEBUG INFO. Proved necessary by adversarial
# review, which ran llvm-objcopy --strip-debug on a copy of this vmlinux and
# got `0 match, 0 MISMATCH, 51 skipped` and EXIT 0. Reporting those as "not
# built (config)" instead would be the same green light in nicer words. This
# guard passes today only because CONFIG_DEBUG_INFO happens to be on -- that is
# a precondition, so it is checked rather than assumed.
#
# This check was written once, staged, and then LOST: a later round of fixes
# was applied from a different patch and the guard silently never landed. It
# was found again only by grepping for it. A fix that is not in the file is not
# a fix, however carefully it was written.
if not subs and not refs:
    print("no DWARF for ANY of the %d symbols across %d pairs."
          % (len(wanted), len(pairs)), file=sys.stderr)
    print("This build has no usable debug info (CONFIG_DEBUG_INFO=n, or stripped).",
          file=sys.stderr)
    print("This guard cannot run here, and it will not pretend it did.", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------- types
# Normalise a DWARF type name to WIDTH:KIND. Kind is u (unsigned), s (signed),
# p (pointer), v (void). Spelling is deliberately discarded: `u32` and
# `unsigned int` are the same 4-byte unsigned quantity written in two
# languages, and what must match is width and kind, never spelling.
TABLE = {
    "u8": "1:u", "unsigned char": "1:u", "_Bool": "1:u", "bool": "1:u",
    "i8": "1:s", "signed char": "1:s", "char": "1:s",
    "u16": "2:u", "short unsigned int": "2:u", "unsigned short": "2:u",
    "i16": "2:s", "short int": "2:s", "short": "2:s",
    "u32": "4:u", "unsigned int": "4:u", "uint32_t": "4:u", "c_uint": "4:u",
    "i32": "4:s", "int": "4:s", "int32_t": "4:s", "c_int": "4:s",
    "u64": "8:u", "usize": "8:u", "long unsigned int": "8:u",
    "unsigned long": "8:u", "unsigned long long": "8:u", "size_t": "8:u",
    "i64": "8:s", "isize": "8:s", "long int": "8:s", "long": "8:s",
    "long long": "8:s", "ssize_t": "8:s", "ptrdiff_t": "8:s",
    "": "0:v", "void": "0:v", "()": "0:v", "!": "0:v",
}

def strip_quals(t):
    # const/volatile are qualifiers, not types. Not stripping them made
    # `const size_t` and `size_t` compare unequal -- six false mismatches on a
    # clean tree, which is how a guard gets ignored.
    prev = None
    while prev != t:
        prev = t
        t = t.strip()
        for q in ("const ", "volatile "):
            if t.startswith(q):
                t = t[len(q):]
        for q in (" const", " volatile"):
            if t.endswith(q):
                t = t[: -len(q)]
    return t

CACHE = {}

def is_ptr(t):
    """A pointer is a pointer: 8 bytes passed by value. That includes FUNCTION
    pointers, spelled `int (*)(const void *, const void *)` in C and
    `i32 (*)(c_void *, c_void *)` in Rust -- two spellings of one machine word.

    This must be asked in BOTH places a spelling is examined. Testing only
    `endswith("*")` here, and forgetting it when following a typedef, is what
    made `bsearch` unresolvable: its C side is the typedef `cmp_func_t`, whose
    target is a function pointer that was then looked up as if it were a type
    name."""
    return t.endswith("*") or "(*)" in t

def norm(t, resolver):
    t = strip_quals(t)
    if is_ptr(t):
        return "8:p"
    if t in TABLE:
        return TABLE[t]
    if t in CACHE:
        return CACHE[t]
    return resolver(t)

# Unknown spellings -- typedefs like `uint64_t`, `z_streamp`, `xz_ret` -- are
# RESOLVED THROUGH THE DWARF rather than added to a table, by following
# DW_TAG_typedef to its base type. A hand-maintained typedef table is the kind
# of thing that silently goes stale; the debug info already knows the answer.
def resolve_batch(unknowns):
    """One dwarfdump pass for all unknown spellings; follow typedef chains."""
    pending, rounds = set(unknowns), 0
    while pending and rounds < 8:
        rounds += 1
        # SEARCH THE REFERENCE OBJECTS TOO. A type used only by a fully-ported
        # subsystem -- ERR_enum, codetype -- no longer exists anywhere in
        # vmlinux, because the C that used it is gone. Looking only in vmlinux
        # left three symbols unresolvable for a reason that had nothing to do
        # with them.
        text = dwarfdump(pending, children=False)
        if refobjs:
            cmd = (["llvm-dwarfdump"] + ["--name=%s" % n for n in sorted(set(pending))]
                   + sorted(refobjs))
            text += subprocess.run(cmd, capture_output=True, text=True).stdout
        found = {}
        for _, tag, at in parse(text):
            nm = QUOTED.search(at.get("DW_AT_name", ""))
            nm = nm.group(1) if nm else ""
            if nm not in pending or nm in found:
                continue
            if tag == "DW_TAG_pointer_type":
                found[nm] = "8:p"
            elif tag == "DW_TAG_typedef":
                found[nm] = ("->", typename(at.get("DW_AT_type", "")))
            elif tag == "DW_TAG_base_type":
                sz = at.get("DW_AT_byte_size", "")
                m = re.search(r'0x[0-9a-f]+|\d+', sz)
                enc = at.get("DW_AT_encoding", "")
                if not m:
                    continue
                n = int(m.group(0), 0)
                # RULE 3: floats are NOT integers. Classifying them as such is
                # exactly the silent-assumption failure this guard exists to
                # stop, so they are left unresolved on purpose.
                if "float" in enc:
                    found[nm] = "?:float " + nm
                elif "unsigned" in enc or "boolean" in enc:
                    found[nm] = "%d:u" % n
                elif "signed" in enc or "char" in enc:
                    found[nm] = "%d:s" % n
                else:
                    found[nm] = "?:enc " + enc
            elif tag == "DW_TAG_enumeration_type":
                sz = at.get("DW_AT_byte_size", "")
                m = re.search(r'0x[0-9a-f]+|\d+', sz)
                if m:
                    # Kind `e`, not `u`. C leaves an enum's underlying type
                    # implementation-defined, so `xz_ret` arriving as
                    # `unsigned int` against a Rust `i32` is not drift -- the
                    # width is the promise, the signedness is not. See compat().
                    found[nm] = "%d:e" % int(m.group(0), 0)
            # structs/unions/arrays by value are deliberately NOT handled:
            # two different structs of the same size are not the same ABI, and
            # comparing them by size would be an assumption, not a measurement.
        nxt = set()
        for nm in list(pending):
            v = found.get(nm)
            if v is None:
                CACHE[nm] = "?:no DWARF for type " + nm
            elif isinstance(v, tuple):
                tgt = strip_quals(v[1])
                if is_ptr(tgt):
                    CACHE[nm] = "8:p"
                elif tgt in TABLE:
                    CACHE[nm] = TABLE[tgt]
                elif (tgt in CACHE and isinstance(CACHE[tgt], str)
                      and not CACHE[tgt].startswith("?:")):
                    CACHE[nm] = CACHE[tgt]
                else:
                    nxt.add(tgt)
                    CACHE[nm] = ("->", tgt)
            else:
                CACHE[nm] = v
        pending = nxt - set(k for k, v in CACHE.items() if isinstance(v, str))
    # settle chains
    for _ in range(8):
        for nm, v in list(CACHE.items()):
            if isinstance(v, tuple):
                tgt = v[1]
                if tgt in TABLE:
                    CACHE[nm] = TABLE[tgt]
                elif isinstance(CACHE.get(tgt), str):
                    CACHE[nm] = CACHE[tgt]
    for nm, v in list(CACHE.items()):
        if isinstance(v, tuple):
            CACHE[nm] = "?:unresolved typedef chain " + nm

# Gather every spelling we will need, then resolve them all at once.
spellings = set()
for lst in list(subs.values()) + list(decls.values()) + list(refs.values()):
    for d in lst:
        for t in [d["ret"]] + d["params"]:
            t = strip_quals(t)
            if t and not is_ptr(t) and t not in TABLE:
                spellings.add(t)
resolve_batch(spellings)

def N(t):
    return norm(t, lambda x: CACHE.get(x, "?:unknown " + x))

def compat(a, b):
    """Equal, except that an enum matches an integer of the same width.

    This is the one deliberate looseness in the check and it is narrow. A C
    enum's underlying type is implementation-defined -- clang renders `xz_ret`
    as 4-byte `unsigned int` -- so a Rust `i32` return against it is a spelling
    difference, not an ABI difference. Width is still compared exactly, which
    is where the danger actually lives: the sabotage this tool exists to catch
    widened u8 to u64."""
    if a == b:
        return True
    wa, ka = a.split(":", 1)
    wb, kb = b.split(":", 1)
    return wa == wb and "e" in (ka, kb) and {ka, kb} <= {"e", "u", "s"}

# ---------------------------------------------------------------- compare
def pick_ref(name):
    """C authority for a thunk-free symbol, best source first.

    1. The PRISTINE REFERENCE BUILD (rig/abi-ref.sh) -- the unmodified upstream
       .c compiled with kbuild's own command line. This is the strongest
       source: it carries the real definition, with parameter names, which a
       header declaration does not have.
    2. A header declaration DIE, if some C translation unit still calls the
       symbol.

    Fails closed when neither exists."""
    if name in refs:
        cands = refs[name]
        if len({(d["ret"], tuple(d["params"])) for d in cands}) > 1:
            return None, "conflicting definitions in the pristine reference"
        return cands[0], None
    return pick_header(name)

def pick_header(name):
    """Post-thunk C authority: the header declaration C callers compile against.

    Fails closed when the build emitted no such DIE. That happens when nothing
    in this configuration calls the symbol, so no translation unit ever
    materialised the declaration -- 19 of 72 exported symbols are in that state
    today (LZ4 stream entry points, __clzdi2 and friends). It is a real gap and
    it is reported as one."""
    cands = decls.get(name, [])
    if not cands:
        return None, "no header declaration DIE -- nothing in this build calls it"
    if len({(d["ret"], tuple(d["params"])) for d in cands}) > 1:
        return None, "conflicting header declarations"
    return cands[0], None

def pick(name, want_ext):
    """RULE 2: assert the language of the DIE we selected. Returns
    (record, error). A definition from the wrong language is a hard error --
    that is the exact failure that made the first version of this tool
    report `ok` on a real ABI break."""
    cands = subs.get(name, [])
    if not cands:
        return None, "no definition DIE in DWARF"
    right = [d for d in cands if d["file"].endswith(want_ext)]
    if not right:
        got = ", ".join(sorted({os.path.basename(d["file"]) for d in cands})) or "?"
        return None, "definition is not %s (found: %s)" % (want_ext, got)
    if len({(d["ret"], tuple(d["params"])) for d in right}) > 1:
        return None, "%d conflicting %s definitions" % (len(right), want_ext)
    return right[0], None

# EXCEPTIONS ARE SCOPED TO A SLOT, NOT TO A PAIR. The first version exempted
# the whole pair the moment any one type was unresolvable, and review then hid
# real breaks behind both entries: an 8-byte parameter narrowed to 4 behind
# `ZSTD_getErrorCode`, and a u32 widened to u64 behind `reciprocal_value`. Both
# reported EXCEPT, 0 MISMATCH, exit 0.
#
# Worse, the reason written in that file was FALSE. It claimed a width change
# on ZSTD_getErrorCode "would show on the Rust side as a non-enum type and
# still be caught". Review tested that exact sentence -- changed the return to
# i64 -- and the guard said `47 signatures match, 0 MISMATCH`. A justification
# nobody tested is how a guard develops a hole shaped like its own comment.
#
# So an entry now names ONE SLOT: `ret`, or `p0`/`p1`/... Every other slot is
# compared normally and the parameter count is always enforced.
#
# Two entry kinds:
#   <symbol> <slot>       a type in that slot cannot be measured
#   <symbol> nonpassthru  the thunk does real work, so no signature claim exists
except_path = os.path.join(root, "rig", "abi-except.txt")
EXCEPT = {}
for line in (open(except_path) if os.path.exists(except_path) else []):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    f = line.split(None, 2)
    if len(f) < 2:
        print("malformed line in abi-except.txt: %r" % line, file=sys.stderr)
        sys.exit(2)
    EXCEPT.setdefault(f[0], {})[f[1]] = f[2] if len(f) > 2 else "(no reason given)"

n_ok = n_bad = n_unres = n_skip = n_exc = n_unpaired = 0
noref = []
fail = 0
print("%-26s %-24s %s" % ("C ENTRY SYMBOL", "RUST BODY", "VERDICT"))
if direct:
    print("(%d thunk-free: C side read from the pristine reference build)" % len(direct))
if direct and not refobjs:
    # Without the reference objects every thunk-free symbol silently falls back
    # to a header declaration and most will report `no C reference`. Say why,
    # rather than let a stale build look like a coverage regression.
    print("    NOTE: %s/abi-ref is empty -- run rig/abi-ref.sh first, or these"
          % build_dir)
    print("    symbols will report `no C reference` for want of a reference build.")
for cfn, rfn in pairs:
    if cfn in direct and cfn not in subs and cfn not in decls and cfn not in refs:
        # NOT BUILT beats NO C REFERENCE. A direct symbol absent from the Rust
        # side too is simply a config this build does not select -- the
        # mpihelp_* family in build-fast. Checking the C side first mislabelled
        # 8 of them as an unverified gap when nothing was built at all.
        print("%-26s %-24s not built (config)" % (cfn, rfn))
        n_skip += 1
        continue
    if cfn in direct:
        cd, cerr = pick_ref(cfn)
        if cerr:
            # NOT a failure and NOT a pass: there is no C-side authority in
            # this build, so nothing was verified. Counted and named, because
            # the alternative is a summary that implies coverage it lacks.
            # These are symbols Rust defines outright whose C callers are gone
            # -- the port succeeding is what removes the reference. Closing
            # this needs a reference translation unit that includes the header
            # and forces a declaration DIE; see logs/thunk-free-ledger.md.
            noref.append(cfn)
            continue
    else:
        cd, cerr = pick(cfn, ".c")
    rd, rerr = pick(rfn, ".rs")
    if cfn not in subs and rfn not in subs and cfn not in decls:
        # NEITHER side is in the DWARF at all. That is not a defect, it is a
        # config this build does not enable -- CONFIG_XZ_DEC_MICROLZMA and
        # CONFIG_CHECK_SIGNATURE are both off in build-fast. Reporting it as a
        # failure would train the reader to ignore failures. Same three-outcome
        # shape as rig/rust-present.sh.
        print("%-26s %-24s not built (config)" % (cfn, rfn))
        n_skip += 1
        continue
    if cerr or rerr:
        why = "C: %s" % cerr if cerr else "Rust: %s" % rerr
        print("%-26s %-24s *** UNRESOLVED -- %s" % (cfn, rfn, why))
        n_unres += 1; fail = 1
        continue
    def side(d):
        """Normalise a record, falling back to OFFSET resolution for anything a
        name lookup cannot reach. An anonymous enum has no name, so this is the
        only route to it -- and it is why ERR_getErrorString, ZSTD_getErrorString
        and zlib_inflate_table do not need exceptions."""
        out = [N(d["ret"])] + [N(x) for x in d["params"]]
        if "obj" not in d:
            return out
        offs = [d.get("retoff", "")] + d.get("paramoffs", [])
        for i, v in enumerate(out):
            if v.startswith("?:") and i < len(offs):
                alt = resolve_by_offset(d["obj"], offs[i])
                if alt:
                    out[i] = alt
        return out
    cn = side(cd)
    rn = side(rd)
    # PARAMETER COUNT IS NEVER EXCUSABLE, whatever the types.
    if len(cn) != len(rn):
        print("%-26s %-24s *** SIGNATURE MISMATCH (%d slots vs %d)"
              % (cfn, rfn, len(cn), len(rn)))
        print("      C    %s" % " ".join(cn))
        print("      Rust %s" % " ".join(rn))
        n_bad += 1; fail = 1
        continue

    exc = EXCEPT.get(cfn, {})
    slots = ["ret"] + ["p%d" % i for i in range(len(cn) - 1)]
    excused = [sl for sl in slots if sl in exc]
    bad = [x for i, x in enumerate(cn + rn)
           if x.startswith("?:") and slots[i % len(cn)] not in exc]
    if bad:
        print("%-26s %-24s *** UNRESOLVED -- %s" % (cfn, rfn, "; ".join(sorted(set(bad)))))
        n_unres += 1; fail = 1
        continue
    diff = [sl for sl, x, y in zip(slots, cn, rn)
            if sl not in exc and not compat(x, y)]
    if not diff:
        if excused:
            print("%-26s %-24s ok  (%s)  [%s not measured]"
                  % (cfn, rfn, " ".join(cn), ",".join(excused)))
            n_exc += 1
            continue
        print("%-26s %-24s ok  (%s)" % (cfn, rfn, " ".join(cn)))
        n_ok += 1
    else:
        print("%-26s %-24s *** SIGNATURE MISMATCH in %s" % (cfn, rfn, ",".join(diff)))
        print("      C    %s   (%s)" % (" ".join(cn), "|".join([cd["ret"]] + cd["params"])))
        print("      Rust %s   (%s)" % (" ".join(rn), "|".join([rd["ret"]] + rd["params"])))
        n_bad += 1; fail = 1

if noref:
    print()
    print("NO C REFERENCE -- %d Rust-defined symbols with no C-side authority in"
          " this build:" % len(noref))
    for i in range(0, len(noref), 3):
        print("    " + "  ".join("%-26s" % u for u in noref[i:i + 3]).rstrip())
    print("    (nothing verified for these. Their C callers are gone -- the port")
    print("     succeeding is what removed the reference. Needs a reference TU.)")

# RULE B. Anything that never reached the comparison above, named out loud.
unpaired = sorted(all_handoffs - {r for _, r in pairs})
undeclared = [u for u in unpaired
              if "nonpassthru" not in EXCEPT.get(u, {})
              and "nonpassthru" not in EXCEPT.get(u[len("rust_"):], {})]
if unpaired:
    print()
    print("NOT PAIRED -- %d rust_* hand-offs, %d of them UNDECLARED:"
          % (len(unpaired), len(undeclared)))
    for u in unpaired:
        mark = "***" if u in undeclared else "   "
        print("    %s %s" % (mark, u))
    if undeclared:
        n_unpaired = len(undeclared)
        fail = 1

print()
print("%d match, %d MISMATCH, %d UNRESOLVED, %d slot-excused, %d not built,"
      " %d no-C-ref, %d UNDECLARED unpaired"
      % (n_ok, n_bad, n_unres, n_exc, n_skip, len(noref), n_unpaired))
if n_bad:
    print("*** a Rust body does not have the signature of the C entry symbol it serves",
          file=sys.stderr)
if n_unres:
    print("*** a pair could not be measured -- this guard fails closed, it does not assume",
          file=sys.stderr)
if n_unpaired:
    print("*** a rust_* hand-off was never compared and is not declared in "
          "rig/abi-except.txt -- silence is not coverage", file=sys.stderr)
sys.exit(fail)
PYEOF
