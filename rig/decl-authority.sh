#!/usr/bin/env bash
# decl-authority.sh <build-dir>
#
# Every exported symbol this port is responsible for must still have a REAL C
# PROTOTYPE in a header.
#
# WHY THIS EXISTS, and it is a guard built BEFORE the thing it guards.
#
# MODVERSIONS stamps each exported symbol with a fingerprint so a mismatched
# module is refused rather than crashing. Two ways to compute it: from the
# DEFINITION's debug info (GENDWARFKSYMS, what we ship) or from the
# DECLARATION (GENKSYMS). The second is what would let a Rust definition carry
# an exported symbol with no C entry thunk -- the change that would dissolve
# GOALS.md §1's first exception and delete 95 hand-offs.
#
# It has two silent failure modes, both DEMONSTRATED on 2026-09-04, neither
# detectable by anything the project owned:
#
#   FAIL-OPEN.    With `EXPORT_SYMBOL(foo)` and no declaration in the
#                 translation unit, genksyms emits nothing and exits 0 --
#                 kbuild does not pass -w and genksyms defaults to quiet. Then
#                 kernel/module/version.c:24-26 reads
#                 "Exporting module didn't supply crcs? OK, we're already
#                 tainted" and RETURNS SUCCESS. A missing fingerprint is
#                 indistinguishable from a matching one.
#
#   FABRICATION.  A declaration carrying no type information still produces a
#                 confident number. `rust/exports.c` expands to
#                 `extern int <sym>;`, and 995 of this kernel's 4,889 exports
#                 got a CRC that is a pure function of the symbol's NAME.
#
# This guard addresses the first: it asserts that every exported symbol the
# port owns is still declared, with arguments, in a header the kernel actually
# includes. Delete a thunk and take the last declaration with it and this fails
# -- where MODVERSIONS itself would quietly wave it through.
#
# It is useful under BOTH generators. Under GENDWARFKSYMS a missing declaration
# is merely untidy; under GENKSYMS it is the difference between a checked
# symbol and an unchecked one.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: decl-authority.sh <build-dir>}
[ -d "$root/$build" ] && build="$root/$build"
[ -f "$build/vmlinux" ] || { echo "no vmlinux at $build/vmlinux" >&2; exit 2; }

# Symbols the port owns: every global defined by the object built from ANY file
# under port/tree.
#
# The first version keyed on object NAME -- '*_thunk.o' and '*_rs.o' -- and so
# missed every ported file that still carries its thunks inside the original
# .c, which is 32 of them pending RAISE 2. Adversarial review found the gap by
# the case it lets through: lib/clz_ctz.c's four exported symbols are declared
# in the .c itself, in no header at all, and the guard could not see them.
# Derive the set from what we have touched, not from what we named things.
owned=$(mktemp); trap 'rm -f "$owned"' EXIT
for src in $(find "$root/port/tree" \( -name '*.c' -o -name '*_rs.rs' \) | sort); do
    rel=${src#"$root/port/tree/"}
    o="$build/${rel%.*}.o"
    [ -f "$o" ] || continue
    # T and W: lib/clz_ctz.c's four exports are __weak, so nm types them W,
    # and taking only T is how they stayed invisible to this guard through two
    # versions -- including the version that was supposed to fix exactly that.
    nm --defined-only "$o" 2>/dev/null | awk '$2=="T" || $2=="W"{print $3}'
done | sort -u > "$owned"

# Headers the kernel can actually reach. Overridable ONLY so the guard can be
# shown to fail -- a guard nobody has seen fail is not a guard. Point
# DECL_HDRS at nothing and every symbol must be reported UNDECLARED.
if [ -n "${DECL_HDRS:-}" ]; then
    read -r -a hdrs <<< "$DECL_HDRS"
else
    hdrs=("$root/src/linux/include/linux" "$root/src/linux/include/uapi/linux"
          "$root/src/linux/lib" "$root/src/linux/include/crypto"
          "$root/src/linux/arch/x86/include")
fi

n_ok=0; n_undecl=0; n_notexp=0; fail=0
printf '%-34s %s\n' "EXPORTED SYMBOL" "DECLARATION"
while IFS= read -r sym; do
    [ -n "$sym" ] || continue
    # only exported symbols matter -- an internal Rust definition needs no
    # C declaration and is not this guard's business
    grep -q "^__ksymtab_$sym\$" <(nm --defined-only "$build/vmlinux" 2>/dev/null | awk '{print $3}') \
      || { n_notexp=$((n_notexp + 1)); continue; }

    # Recorded exceptions: a symbol whose declaration legitimately lives
    # somewhere other than a header. Each needs a reason, because under
    # GENKSYMS the declaration IS the fingerprint's source, so "declared in the
    # .c" means the CRC moves if the port edits that line -- including editing
    # `__weak` or an attribute. Measured by adversarial review on __ctzsi2:
    # dropping `__weak` moved it 0xc4777aa9 -> 0x5141d366.
    if grep -qs "^$sym	" "$root/rig/decl-except.txt"; then
        printf '%-34s %s\n' "$sym" \
            "EXCEPT -- $(grep -s "^$sym	" "$root/rig/decl-except.txt" | cut -f2)"
        n_ok=$((n_ok + 1)); continue
    fi

    # a real prototype: the name followed by '(' in a header
    h=$(grep -rl --include='*.h' -E "\b$sym[[:space:]]*\(" "${hdrs[@]}" 2>/dev/null | head -1)
    if [ -n "$h" ]; then
        printf '%-34s %s\n' "$sym" "${h#"$root"/src/linux/}"
        n_ok=$((n_ok + 1))
    else
        printf '%-34s %s\n' "$sym" "*** NO PROTOTYPE IN ANY HEADER"
        n_undecl=$((n_undecl + 1)); fail=1
    fi
done < "$owned"

echo
echo "$n_ok exported symbols declared, $n_undecl UNDECLARED," \
     "$n_notexp port-defined but not exported (not this guard's business)"
[ "$fail" = 0 ] || {
    echo "*** an exported symbol has no C prototype. Under GENKSYMS its fingerprint" >&2
    echo "    would be absent, and an absent fingerprint is accepted silently." >&2
}
exit $fail
