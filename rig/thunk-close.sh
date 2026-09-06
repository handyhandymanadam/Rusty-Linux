#!/usr/bin/env bash
# thunk-close.sh [--dry-run] <port/tree/.../file.c> [build-dir]
#
# DELETE THE PASS-THROUGH THUNKS IN ONE FILE, letting Rust define the exported
# symbols directly, with their MODVERSIONS fingerprints pinned so they do not
# move. The transformation is mechanical and identical every time, which is
# exactly why it is a tool and not 70 hand edits.
#
# WHAT IT DOES, per pass-through thunk `T c(args) { return rust_c(args); }`:
#   1. CAPTURES THE PIN FIRST, from the still-C definition. This is not
#      reversible: the pin must reproduce the ORIGINAL C type string, parameter
#      names included, and deleting the thunk destroys the only copy of it.
#      A C header declaration carries no parameter names (measured: 0 of 8
#      across bcd.h, math.h, zlib.h, crc16.h), so a pin cannot be reconstructed
#      afterwards.
#   2. Removes the `rust_c` forward declaration and the thunk body from the .c,
#      leaving EXPORT_SYMBOL and adding the pin.
#   3. Renames `rust_c` to `c` in the Rust file that defines it.
#
# IT REFUSES rather than guesses. A thunk whose body is not exactly a
# pass-through, a symbol it cannot find in the Rust, a pin it cannot capture,
# or a file where any edit does not apply cleanly -- all abort the whole file
# with nothing written. Partial application is worse than none.
#
# THAT SENTENCE WAS FALSE FOR A DAY, and it is why this file has the warning
# below rather than a smaller diff. The body pattern was anchored at one end,
# so it matched the LAST STATEMENT of a C entry instead of the whole body.
# Seven entries that guarded, dispatched, or warned before calling into Rust
# were closed as pass-throughs; two stopped the kernel booting. See
# logs/c-entry-rule.md.
#
# BEFORE USING THIS, RUN ./rig/thunk-screen.sh AND READ THE FILE. The screen
# knows nothing about __weak, __pure, or an exported data symbol the entry
# passes down -- and each of those decides a real case in this tree.
# AFTERWARDS, ./rig/guard-check.sh.
#
# AFTER RUNNING IT, the caller must rebuild and check:
#     ./rig/crc-check.sh build-fast     0 CHANGED
#     ./rig/abi-check.sh build-fast     0 MISMATCH
#     ./rig/kabi-pin.sh --check         pins match their headers
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
dry=0; only=""
while :; do
  case "${1:-}" in
    --dry-run) dry=1; shift;;
    --only)    only=$2; shift 2;;   # comma-separated C entry symbols
    *) break;;
  esac
done
cfile=${1:?usage: thunk-close.sh [--dry-run] <port/tree/.../x.c> [build-dir]}
build=${2:-build-fast}
[ -f "$cfile" ] || { echo "no such file: $cfile" >&2; exit 2; }

export TC_BUILD="$build" TC_DRY="$dry" TC_ONLY="$only"
python3 - "$cfile" <<'PYEOF'
import os, re, subprocess, sys

cfile = sys.argv[1]
build = os.environ["TC_BUILD"]
dry   = os.environ["TC_DRY"] == "1"
# --only RESTRICTS THE FILE TO NAMED SYMBOLS. Four files mix thunks whose
# fingerprint can be pinned with thunks whose cannot (their type string carries
# a t# reference that gendwarfksyms re-expands). Closing a whole mixed file
# would silently move the fingerprints of the ones that cannot be pinned, and
# crc-check would then fail for the entire file rather than for the symbol at
# fault.
only = set(f for f in os.environ.get("TC_ONLY", "").split(",") if f)
root  = os.getcwd()

def die(msg):
    print("REFUSING %s: %s" % (cfile, msg), file=sys.stderr)
    sys.exit(1)

src = open(cfile).read()

def strip_comments(t):
    t = re.sub(r'/\*.*?\*/', lambda m: " " * len(m.group(0)), t, flags=re.S)
    return re.sub(r'//[^\n]*', lambda m: " " * len(m.group(0)), t)

bare = strip_comments(src)

# Find pass-through thunks by brace matching, the same rule rig/abi-check.sh
# uses: the LAST statement is a tail call passing exactly the function's own
# parameters, in order, with or without `return`.
FUNC = re.compile(r'^([A-Za-z_][\w \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.M)
# ANCHORED AT BOTH ENDS, AND THAT IS THE WHOLE POINT.
#
# This was `...\s*$` and matched the LAST STATEMENT of the body rather than the
# body. So a C entry like gcd()'s --
#
#     if (!a || !b)
#             return r;
#     if (static_branch_likely(&efficient_ffs_key))
#             return rust_binary_gcd(a, b);
#     return rust_gcd_even_odd(a, b);
#
# -- matched on its last line and was closed as a "pass-through", taking the
# zero guard and the dispatch with it. The kernel then hung at boot. Seven
# closures went through this hole on 2026-09-04; two stopped the kernel
# booting and five deleted a WARN_ON or BUG_ON. The header of this file said
# "IT REFUSES rather than guesses" throughout.
#
# Now the match must span the ENTIRE body. Anything else -- a guard, a second
# statement, a preprocessor line, a local -- fails to match and the symbol is
# not a candidate.
TAIL = re.compile(r'(?:return\s+)?([A-Za-z_]\w*)\s*\(([^;()]*(?:\([^()]*\)[^;()]*)*)\)\s*;', re.S)

def pnames(params):
    out = []
    for p in params.split(','):
        p = p.strip()
        if not p or p == 'void':
            continue
        out.append(p.split()[-1].lstrip('*').split('[')[0])
    return out

thunks = []   # (cname, rname, start, end)
for m in FUNC.finditer(bare):
    depth, i = 0, m.end() - 1
    for j in range(i, len(bare)):
        if bare[j] == '{':
            depth += 1
        elif bare[j] == '}':
            depth -= 1
            if depth == 0:
                body = bare[i + 1:j]
                t = TAIL.fullmatch(body.strip())
                if t and t.group(1).startswith("rust_"):
                    args = [a.strip() for a in t.group(2).split(',') if a.strip()]
                    if pnames(m.group(3)) == args:
                        if not only or m.group(2) in only:
                            thunks.append((m.group(2), t.group(1), m.start(), j + 1))
                break

if only:
    missing = only - {t[0] for t in thunks}
    if missing:
        die("--only names symbols that are not pass-through thunks here: %s"
            % ", ".join(sorted(missing)))
if not thunks:
    print("%s: no pass-through thunks" % cfile)
    sys.exit(0)

# Which Rust file defines each rust_* body, and is the C entry exported?
def rust_file_of(rname):
    hits = subprocess.run(["grep", "-rl", r'fn %s' % rname, "port/tree",
                           "--include=*.rs"], capture_output=True, text=True).stdout.split()
    hits = [h for h in hits if re.search(r'#\[no_mangle\][^\n]*\n(?:\s*#\[[^\n]*\]\s*\n)*\s*pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+%s\b' % rname,
                                         open(h).read())]
    return hits[0] if len(hits) == 1 else None

def exported(cname):
    r = subprocess.run(["grep", "-rqE", r'EXPORT_SYMBOL(_GPL)?\(%s\)' % cname,
                        "port/tree", "--include=*.c"], capture_output=True)
    return r.returncode == 0

plan = []
for cname, rname, s0, s1 in thunks:
    rf = rust_file_of(rname)
    if not rf:
        die("cannot locate a single Rust definition of %s" % rname)
    pin = None
    if exported(cname):
        out = subprocess.run(["./rig/kabi-pin.sh", "--capture", cname, build],
                             capture_output=True, text=True)
        if out.returncode != 0 or "KABI_TYPE_STRING(" not in out.stdout:
            die("could not capture a pin for exported %s:\n%s" % (cname, out.stderr.strip()))
        pin = out.stdout.strip()
    plan.append((cname, rname, s0, s1, rf, pin))

print("%s: %d pass-through thunk(s)" % (cfile, len(plan)))
for cname, rname, _, _, rf, pin in plan:
    print("    %-28s <- %-28s  %s  %s" % (cname, rname, rf.split('/')[-1],
                                          "pinned" if pin else "not exported"))
if dry:
    sys.exit(0)

# ---- rewrite the C file, back to front so offsets stay valid
new = src
pin_blocks = []
for cname, rname, s0, s1, rf, pin in sorted(plan, key=lambda x: -x[2]):
    new = new[:s0] + new[s1:]
    if pin:
        pin_blocks.append(pin)

# DEDUPLICATE BY TARGET. A capture now emits a pin for the symbol AND one for
# every type its string references, and symbols in the same file routinely
# reference the same types -- crc16 and crc_ccitt both name t#u16, t#u8,
# t#size_t. Emitting a rule twice for one target is at best noise and at worst
# a conflict, so each target is written once, types before symbols.
seen = set()
type_pins, sym_pins = [], []
for block in pin_blocks:
    cur, target = [], None
    for line in block.split("\n"):
        cur.append(line)
        m = re.match(r'\s*"([^"]+)",\s*$', line)
        if m and target is None:
            target = m.group(1)
        if line.rstrip().endswith('");'):
            if target and target not in seen:
                seen.add(target)
                (type_pins if "#" in target else sym_pins).append("\n".join(cur))
            cur, target = [], None
    # a leading /* from ... */ comment line is carried with the first pin
pins = type_pins + sym_pins

# the forward declarations of the rust_* bodies go too
for cname, rname, _, _, _, _ in plan:
    pat = re.compile(r'^[A-Za-z_][^\n;]*\b%s\s*\([^;]*\);\s*\n' % rname, re.M)
    n_before = len(pat.findall(new))
    new = pat.sub('', new)
    if n_before == 0:
        die("no forward declaration of %s found to remove" % rname)

if pins:
    if '#include <linux/kabi.h>' not in new:
        m = re.search(r'^#include [^\n]*\n(?![\s\S]*^#include )', new, re.M)
        if not m:
            die("no #include block to anchor <linux/kabi.h> after")
        new = new[:m.end()] + "#include <linux/kabi.h>\n" + new[m.end():]
    anchor = re.search(r'^EXPORT_SYMBOL', new, re.M)
    if not anchor:
        die("pins to add but no EXPORT_SYMBOL line to anchor them before")
    new = new[:anchor.start()] + "\n".join(pins) + "\n\n" + new[anchor.start():]

new = re.sub(r'\n{4,}', '\n\n\n', new)

# ---- rename in the Rust
rust_edits = {}
for cname, rname, _, _, rf, _ in plan:
    t = rust_edits.get(rf, open(rf).read())
    pat = re.compile(r'\b%s\b' % rname)
    if not pat.search(t):
        die("%s does not mention %s" % (rf, rname))
    rust_edits[rf] = pat.sub(cname, t)

open(cfile, "w").write(new)
for rf, t in rust_edits.items():
    open(rf, "w").write(t)
print("  rewritten: %s and %s" % (cfile, ", ".join(sorted(rust_edits))))
PYEOF
