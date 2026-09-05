#!/usr/bin/env bash
# layout-check.sh <build-dir>
#
# FINAL INSPECTION: every ported Rust struct measured against the C struct it
# claims to mirror, dimension for dimension.
#
# WHY THIS EXISTS. Adam's framing, 2026-09-04: in construction you build to a
# blueprint, you measure along the way to stay on track, and then the finished
# part is inspected against the blueprint. This project had no such inspection.
# Every `#[repr(C)]` struct in the port claims to have the same shape as a C
# struct, and until now that claim rested on the author having got it right and
# on nothing having drifted since. Nothing measured it.
#
# WHAT IT CATCHES that nothing else does:
#   - a mirrored struct with a field of the wrong width, in the wrong order, or
#     with different padding -- the differential only notices if the corpus
#     happens to exercise the affected field through the affected path;
#   - and the one that actually worries me: the C struct changing at a REBASE
#     while the Rust does not. Nothing in the rig would see that today.
#
# HOW. The port already carries the convention `/// Mirrors `struct foo`` on
# every struct that has a C counterpart, so the pairing is machine-readable and
# does not need a hand-maintained list. Both sides are then read out of the SAME
# vmlinux with pahole, which reads DWARF -- so this measures what the compiler
# actually laid out, not what the source says it should have.
#
# Field NAMES and TYPE SPELLINGS are deliberately not compared: `uLong` vs `u64`
# and `char *` vs `i8 *` are the same geometry described in two languages. What
# must match is offset, size, and the struct's total footprint.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: layout-check.sh <build-dir>}
[ -d "$root/$build" ] && build="$root/$build"
vmlinux="$build/vmlinux"
[ -f "$vmlinux" ] || { echo "no vmlinux at $vmlinux" >&2; exit 2; }
command -v pahole >/dev/null || { echo "pahole not installed" >&2; exit 2; }

# (offset,size) per member, then the struct's total size -- the geometry only.
geom() {
    pahole -C "$1" "$vmlinux" 2>/dev/null \
      | sed -n 's|.*/\*[[:space:]]*\([0-9]\+\)[[:space:]]\+\([0-9]\+\)[[:space:]]*\*/.*|\1:\2|p;
                s|.*/\* size: \([0-9]\+\).*|size=\1|p'
}

n_ok=0; n_bad=0; n_missing=0; fail=0
printf '%-26s %-26s %s\n' "RUST STRUCT" "MIRRORS C STRUCT" "VERDICT"

# Pair each `Mirrors `struct X`` with the struct declared just below it.
while IFS=$'\t' read -r rs c file; do
    [ -n "$rs" ] || continue
    a=$(geom "$c"); b=$(geom "$rs")
    if [ -z "$a" ] || [ -z "$b" ]; then
        printf '%-26s %-26s %s\n' "$rs" "$c" \
            "not in this vmlinux ($([ -z "$a" ] && echo "C side" || echo "Rust side") absent)"
        n_missing=$((n_missing + 1)); continue
    fi
    # AMBIGUITY, and the first version of this reported it as a defect.
    # `pahole -C NAME` returns ONE definition. Two crates may each declare a
    # struct of the same name at different truncations -- lib/zlib_inflate has
    # exactly that: inffast_rs.rs keeps a deliberately short InflateState (22
    # fields) and inflate_rs.rs the full one (30). They are separate crates and
    # separate types, which is legitimate, but it makes a name-keyed DWARF
    # lookup unable to say which one it measured. Refuse to judge rather than
    # report the wrong one as broken.
    ndecl=$(grep -rc "^\(pub \)\?struct $rs\b" "$root/port/tree" --include='*_rs.rs' 2>/dev/null \
            | awk -F: '{n+=$2} END{print n+0}')
    if [ "${ndecl:-0}" -gt 1 ]; then
        printf '%-26s %-26s %s\n' "$rs" "$c" \
            "AMBIGUOUS -- $ndecl crates declare this name; pahole returns one"
        n_missing=$((n_missing + 1)); continue
    fi

    if [ "$a" = "$b" ]; then
        printf '%-26s %-26s %s\n' "$rs" "$c" "ok ($(echo "$a" | grep -c ':') fields, $(echo "$a" | sed -n 's/size=//p') bytes)"
        n_ok=$((n_ok + 1))
    else
        printf '%-26s %-26s %s\n' "$rs" "$c" "*** GEOMETRY DIFFERS"
        diff <(echo "$a") <(echo "$b") | sed 's/^/      /'
        n_bad=$((n_bad + 1)); fail=1
    fi
done < <(
    for f in $(find "$root/port/tree" -name '*_rs.rs' | sort); do
        awk -v F="$f" '
            /Mirrors[[:space:]]+`?struct[[:space:]]/ {
                if (match($0, /struct[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/))
                    cname = substr($0, RSTART+7, RLENGTH-7)
                gsub(/^[[:space:]]+|`.*$/, "", cname); next
            }
            /^(pub |pub\(crate\) )?struct [A-Za-z_]/ && cname != "" {
                # `$NF` is the brace on `pub struct Foo {`, which is how the
                # first version of this silently paired nothing at all.
                if (match($0, /struct[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                    rs = substr($0, RSTART+7, RLENGTH-7)
                    gsub(/[[:space:]]/, "", rs)
                    print rs "\t" cname "\t" F
                }
                cname = ""
            }' "$f"
    done | sort -u
)

echo
echo "$n_ok match, $n_bad differ, $n_missing not inspectable (absent or ambiguous)"
[ "$fail" = 0 ] || echo "*** a ported struct does not have the geometry of the C struct it claims to mirror" >&2
exit $fail
