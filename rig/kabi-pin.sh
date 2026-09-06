#!/usr/bin/env bash
# kabi-pin.sh [--check] [build-dir]
#
# GENERATE AND VERIFY THE KABI_TYPE_STRING PINS FOR THUNK-FREE SYMBOLS.
#
# WHY THIS EXISTS. When Rust defines an exported symbol directly, its
# MODVERSIONS fingerprint changes -- CONFIG_GENDWARFKSYMS hashes the DWARF of
# the DEFINITION, and Rust spells the same machine types differently:
#
#     C     base_type unsigned char byte_size(1) encoding(8)
#     Rust  base_type u8            byte_size(1) encoding(7)
#
# Same width, same signedness, same ABI, different hash. Measured on lib/bcd.c:
# _bcd2bin went 0x605be21c -> 0xcf47c3a6 the moment its thunk was deleted.
# Adam's ruling is that third-party modules must keep loading, so that is a
# defect, not a cosmetic difference.
#
# The fix is a KABI_TYPE_STRING() rule pinning the symbol's type string to the
# C one. THE DANGER IS THAT A PIN IS A LITERAL. If the C declaration in the
# header ever changes, the pin keeps asserting the OLD fingerprint and hides a
# real ABI break -- the pin would be doing the exact opposite of its job.
#
# So the pins are GENERATED from the header declaration, never hand-written,
# and --check re-derives them and fails if any has drifted.
#
# HOW A PIN IS DERIVED. gendwarfksyms hashes a type string built from DWARF.
# Compiling a one-line C probe with the symbol's declared signature and dumping
# its type string reproduces the kernel's original CRC exactly -- verified:
#
#     probe  ->  #SYMVER _bcd2bin 0x605be21c   (kernel baseline: 0x605be21c)
#     probe  ->  #SYMVER _bin2bcd 0xf664d2df   (kernel baseline: 0xf664d2df)
#
# so the probe is a faithful stand-in for the C definition that used to exist.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
# --capture <symbol>...   emit the KABI_TYPE_STRING() lines for symbols that
#                         are STILL DEFINED IN C, to paste into the .c file
#                         before deleting the thunk.
#
# ORDER MATTERS AND IT IS NOT REVERSIBLE. The pin must reproduce the ORIGINAL
# C definition's type string, parameter names included -- and that definition
# is precisely what deleting the thunk destroys. Capture first, then delete.
# Trying to reconstruct the pin afterwards means guessing the parameter names,
# because a C header declaration DIE carries none (measured: 0 of 8 across
# bcd.h, math.h, zlib.h, crc16.h).
mode=check
case "${1:-}" in
    --check)
        cat >&2 <<'RETIRED'
--check is RETIRED. Use ./rig/kabi-contract-check.sh <build-dir> instead.

WHY. This compared a pin against the HEADER declaration, by parsing the pin
text. Three things were wrong with that and only the third is fixable:

  1. A header declaration DIE carries no parameter names, and the fingerprint
     depends on them. It could never verify the part that matters most.
  2. It did not understand the --symtypes back-reference form (t#u64,
     s#list_head) -- the form a pin is REQUIRED to be in -- and reported those
     pins as "?" and then as STALE. Nine files were reverted across two runs on
     alarms that were its own, while crc-check read CHANGED 0 throughout.
  3. It could not check a type pin at all: a t# target has no header DIE, so
     every one came back "cannot verify".

kabi-contract-check.sh reads the pristine C COMPILED (parameter names and all,
via rig/abi-ref.sh) and compares FINGERPRINTS rather than text, so the
spelling of a pin cannot fool it either way. It covers both the Rust
kernel::kabi_export!() form and the C KABI_TYPE_STRING() form.

--capture is unaffected and still the way to take a pin from a C definition.
RETIRED
        exit 2;;
    --capture) mode=capture; shift;;
esac
if [ "$mode" = capture ]; then
    syms=()
    while [ $# -gt 0 ] && [ "${1#-}" = "$1" ] && [ ! -d "$1" ]; do syms+=("$1"); shift; done
fi
build=${1:-build-fast}
G="$build/scripts/gendwarfksyms/gendwarfksyms"
[ -x "$G" ] || { echo "no gendwarfksyms at $G -- build first" >&2; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

if [ "$mode" = capture ]; then
    [ ${#syms[@]} -gt 0 ] || { echo "usage: kabi-pin.sh --capture <symbol>... [build-dir]" >&2; exit 2; }
    rc=0
    for sym in "${syms[@]}"; do
        # The object that DEFINES it, not one that references it.
        #
        # NOT JUST `T`. An exported symbol can be a variable -- lib/bitrev.c's
        # byte_rev_table, lib/uuid.c's uuid_null, lib/ctype.c's _ctype -- and
        # nm calls those R, D or B depending on section and constness. Looking
        # only for T made every data symbol report "NOTHING DEFINES IT", which
        # reads as "capture is too late" and is not what happened.
        #
        # gendwarfksyms types a variable perfectly well; measured on
        # lib/bitrev.o, 2026-09-04:
        #     byte_rev_table variable array_type[256] { const_type { t#u8 } }
        #     #SYMVER byte_rev_table 0x997497c0
        #
        # `find`, NOT `grep -rl . --include='*.o'`, WHICH IS WHAT THIS SAID
        # AND WHICH SILENTLY SKIPPED OBJECTS. GNU grep decides per file
        # whether it is binary, and with -l it prints nothing for the ones it
        # calls binary -- so the file list was a subset of the objects, and
        # which subset depended on where the first NUL byte fell. Measured
        # 2026-09-04: build-fast/lib/bug.o and cmdline.o were listed,
        # build-fast/lib/kstrtox.o was not, and capturing any kstrto* pin
        # reported "NOTHING DEFINES IT -- capture is too late" while
        # lib/kstrtox.c sat untouched in the tree with `nm` showing `T
        # kstrtoint` in that very object.
        #
        # That is the worst shape an error can take here: the message says an
        # irreversible thing has already happened, so the reader stops rather
        # than looking. Nothing was lost and nothing had to be.
        # AND `nm` INTO A FILE, NOT INTO `grep -q`. This script runs under
        # `set -o pipefail`, and `grep -q` closes its stdin the instant it
        # matches -- so `nm` is killed by SIGPIPE, the pipeline's status is
        # 141, the `&&` does not fire, and the object that DOES define the
        # symbol is passed over. Whether that happens depends on whether nm
        # finished writing first, i.e. ON THE SIZE OF THE OBJECT: measured
        # 2026-09-04, lib/bitrev.o (small) was found and lib/kstrtox.o
        # (38 KB, 40-odd symbols) was not, from the same loop in the same run.
        # A size-dependent false "capture is too late".
        obj=
        while read -r o; do
            nm "$o" 2>/dev/null > "$work/nm.txt" || true
            if grep -qE " [TRDB] $sym\$" "$work/nm.txt"; then obj=$o; break; fi
        done < <(find "$build/lib" -name '*.o' 2>/dev/null)
        if [ -z "$obj" ]; then
            echo "/* $sym: NOTHING DEFINES IT -- capture is too late */" >&2
            rc=1; continue
        fi
        # THE OBJECT MUST BE A C OBJECT. `nm ... T` finds a Rust object just as
        # happily, and capturing from one emits a pin full of `u8`/`u32` that
        # locks in the RUST fingerprint as if it were the C baseline -- the
        # exact wrong answer, silently, with exit 0. Caught by testing the
        # negative path: capturing the already-thunk-free _bcd2bin produced
        # 0x22d59527 (Rust) instead of 0x605be21c (C).
        dfile=$(llvm-dwarfdump --name="$sym" "$obj" 2>/dev/null \
                | sed -n 's/.*DW_AT_decl_file[^"]*"\([^"]*\)".*/\1/p' | head -1)
        case "$dfile" in
            *.c) ;;
            *)   echo "/* $sym: defined by $obj, whose definition comes from" \
                      "'${dfile:-unknown}' -- NOT a C file. It is already" \
                      "thunk-free; the C fingerprint is gone and cannot be" \
                      "recovered from this build. Capture BEFORE deleting. */" >&2
                 rc=1; continue;;
        esac
        # --symtypes, NOT --dump-versions. THIS IS THE WHOLE BALLGAME.
        #
        # gendwarfksyms emits a literal back-reference like `t#u64` only when
        # that type was ALREADY EXPANDED earlier in the same string
        # (types.c:__calculate_version). --dump-versions prints the first
        # occurrence expanded, destroying that pattern; --symtypes keeps both
        # as `t#u64` and lists every referenced type on its own line.
        #
        # Pinning the dump-versions form gave int_pow 0x8af8d33e against a
        # target of 0xc217874a, and produced the false conclusion that
        # signatures using typedefs could not be pinned at all. They can:
        # Documentation/kbuild/gendwarfksyms.rst specifies the --symtypes form,
        # and types.c:173 lets a type_string rule DEFINE an otherwise
        # unresolvable reference -- "If die_map didn't contain a type, we might
        # still have a type_string kABI rule that defines it."
        #
        # So a capture emits the symbol's pin AND a pin for every type it
        # names. Verified exact on int_pow: 0xc217874a, crc-check CHANGED 0.
        st="$work/$sym.symtypes"
        printf '%s\n' "$sym" | "$G" --symtypes "$st" "$obj" >/dev/null 2>&1
        crc=$(printf '%s\n' "$sym" | "$G" --dump-versions "$obj" 2>/dev/null \
              | sed -n "s/^#SYMVER $sym //p" | head -1)
        if [ ! -s "$st" ]; then
            echo "/* $sym: gendwarfksyms produced no symtypes from $obj */" >&2
            rc=1; continue
        fi
        echo "/* from $obj -- reproduces $crc */"
        # Types first, then the symbol, because the symbol's string
        # references them. Each symtypes line is `<name> <definition>` where
        # <name> is the symbol or a prefixed reference: t# typedef, s# struct,
        # u# union, e# enum.
        while IFS= read -r l; do
            n=${l%% *}; v=${l#* }
            [ "$n" = "$sym" ] && continue
            printf 'KABI_TYPE_STRING(\n\t"%s",\n\t"%s");\n' "$n" "$v"
        done < "$st"
        l=$(grep -m1 "^$sym " "$st"); v=${l#* }
        printf 'KABI_TYPE_STRING(\n\t"%s",\n\t"%s");\n' "$sym" "$v"
    done
    exit $rc
fi

# Every KABI_TYPE_STRING pin currently in the tree, as symbol<TAB>string.
grep -rhA2 'KABI_TYPE_STRING(' port/tree --include='*.c' \
  | tr '\n' ' ' | grep -o '"[^"]*",[[:space:]]*"[^"]*"' \
  | sed 's/^"//; s/",[[:space:]]*"/\t/; s/"$//' | sort > "$work/have.txt"

if [ ! -s "$work/have.txt" ]; then
    echo "no KABI_TYPE_STRING pins in port/tree -- nothing to check"
    exit 0
fi

# WHAT --check CAN AND CANNOT VERIFY, stated exactly.
#
# gendwarfksyms puts the PARAMETER NAME in the string it hashes:
#
#     ... base_type unsigned char byte_size(1) encoding(8) val ) -> ...
#                                                          ^^^
# Measured: the same signature with the parameter called `a0` instead of `val`
# hashes to 0x5267e10d rather than 0x605be21c. But a C DECLARATION DIE carries
# no DW_AT_name for its parameters -- the name lives only in the header source
# and in the definition that was deleted. So a pin cannot be re-derived
# character-for-character from DWARF, and this script does not pretend to.
#
# It checks the part that IS the ABI and IS recoverable: the ordered TYPES.
# If the header's types still match the pin's, the pin is describing the same
# contract. If they differ, the pin is asserting a fingerprint for a signature
# that no longer exists, which is the failure mode that matters.
#
# Whether the fingerprint itself moved is a different question, already
# answered by comparing Module.symvers against the recorded baseline.
fail=0
printf '%-24s %s\n' SYMBOL VERDICT
while IFS=$'\t' read -r sym pinned; do
    # SEARCH THE PRISTINE REFERENCE TOO. A symbol nothing in this build calls
    # has no header declaration DIE anywhere in vmlinux -- the same gap
    # rig/abi-ref.sh was built to close for abi-check. Its objects carry the
    # original C DEFINITION, which is a better source anyway: it has the
    # parameter names a declaration lacks. Without this, LZ4's *_usingDict
    # entry points report "cannot verify" and five correct closures look like
    # failures.
    refobjs=$(find "$build/abi-ref" -name '*.o' 2>/dev/null | tr '\n' ' ')
    hdr=$(llvm-dwarfdump --name="$sym" --show-children "$build/vmlinux" $refobjs 2>/dev/null | python3 -c '
import sys,re
txt=sys.stdin.read().split("DW_TAG_subprogram")
for blk in txt[1:]:
    f=re.search(r"DW_AT_decl_file\s*\(\"([^\"]*)\"\)",blk)
    if not f: continue
    if "DW_AT_declaration" in blk:
        if not f.group(1).endswith(".h"): continue
    elif not f.group(1).endswith(".c"):
        continue   # a Rust definition is not the C authority
    head_only = blk.split("DW_TAG_formal_parameter")[0]
    ret=re.search(r"DW_AT_type\s*\(0x[0-9a-f]+ \"([^\"]*)\"\)",head_only)
    ps=re.findall(r"DW_TAG_formal_parameter.*?DW_AT_type\s*\(0x[0-9a-f]+ \"([^\"]*)\"\)",blk,re.S)
    def k(t):
        t = t.strip()
        if t.endswith("*"): return "ptr"
        for q in ("const ", "volatile "): t = t.replace(q, "")
        return t.strip()
    print("|".join(k(x) for x in ps) + " -> " + (k(ret.group(1)) if ret else "void"))
    break')
    if [ -z "$hdr" ]; then
        printf '%-24s %s\n' "$sym" "*** no header declaration DIE -- cannot verify this pin"
        fail=1; continue
    fi
    # NORMALISE BOTH SIDES THE SAME WAY BEFORE COMPARING. The first version
    # scraped `base_type NAME byte_size` out of the pin with one regex, which
    # finds the ELEMENT type inside `pointer_type { const_type { base_type
    # char ... } }` and reports the parameter as `char` where the header says
    # `const char *`. Every pinned symbol taking a pointer was then declared
    # STALE. Six files were reverted on that false alarm while crc-check --
    # the gate that actually matters -- read CHANGED 0.
    pin_types=$(printf '%s' "$pinned" | python3 -c '
import sys, re
s = sys.stdin.read()
head, sep, ret = s.partition(") -> ")
if not sep:
    # No arrow at all: the function returns void. partition() left the whole
    # string in head, so restore it and record void explicitly -- otherwise a
    # void return reads as "?" and every void-returning pin is called stale.
    head, ret = s, "void"

def kind(chunk):
    c = chunk.strip()
    if c in ("", "void"):
        return "void"
    if c.startswith("pointer_type"):
        return "ptr"
    # `byte_size` is OPTIONAL: a void return is emitted as the bare
    # `base_type void`, with no size and no encoding. Requiring byte_size made
    # that fall through to the generic `(\w+)_type` branch and report the
    # return type as literally "base", so every void-returning pin looked
    # stale. Three files were reverted on that.
    m = re.match(r"base_type ([A-Za-z_][A-Za-z_ ]*?)(?: byte_size|\s*$)", c)
    if m:
        return m.group(1)
    m = re.match(r"typedef_type (\w+)", c)
    if m:
        return m.group(1)
    m = re.match(r"(\w+)_type", c)
    return m.group(1) if m else "?"

ps = [kind(x) for x in head.split("formal_parameter ")[1:]]
print("|".join(ps) + " -> " + kind(ret))')
    if [ "$hdr" = "$pin_types" ]; then
        printf '%-24s %s\n' "$sym" "pin types match the header  ($hdr)"
    else
        printf '%-24s %s\n' "$sym" "*** PIN IS STALE"
        echo "      pin says:  $pin_types"
        echo "      header is: $hdr"
        echo "      A STALE PIN ASSERTS A FINGERPRINT FOR A SIGNATURE THAT NO LONGER EXISTS."
        fail=1
    fi
done < "$work/have.txt"

echo
echo "$(wc -l < "$work/have.txt") pin(s) checked"
[ "$fail" = 0 ] || echo "*** a KABI_TYPE_STRING pin no longer describes its header declaration" >&2
exit $fail
