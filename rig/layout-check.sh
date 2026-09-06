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
#
# PADDING IS EXCLUDED, ON BOTH SIDES, NOT JUST NOT-COMPARED-BY-ACCIDENT.
# C's compiler-inserted padding has no member of its own -- pahole reports
# it as a standalone `/* XXX N bytes hole, try to pack */` comment, which
# never matched the two-number regex below and so never contributed a
# line. A `#[repr(C)]` struct that needs MORE padding than Rust's natural
# alignment gives it (e.g. a `____cacheline_aligned_in_smp` field) has no
# per-field alignment attribute to ask for that the same way C's attribute
# does without also raising the whole struct's alignof -- so it reproduces
# the gap with an explicit, `_`-prefixed named field instead (see
# dynamic_queue_limits_rs.rs's `Dql`). Pahole reports THAT as an ordinary
# member with an ordinary offset:size comment, which DID match the regex --
# so a struct using this pattern always failed here even when byte-for-byte
# identical to the C (found 2026-09-05 porting `struct dql`; verified with
# `pahole -C dql`/`pahole -C Dql` directly against the same vmlinux: same
# 128 bytes, same offsets throughout, same real `alignof` of 8 on both
# sides -- the three lines that differed were exactly the three padding
# spots, spelled two different ways for a reason neither language can
# avoid). So: a member whose name starts with exactly ONE underscore is
# filtered out here (this project's own synthetic-padding convention --
# `_pad0`, `_cacheline_pad`), and holes were already implicitly filtered
# by never matching in the first place.
#
# NOT a member starting with TWO underscores. Found 2026-09-05, one port
# later (`struct sg_mapping_iter`, mpicoder_rs.rs): the kernel's OWN
# naming convention for a real, meaningful "internal use" field is a
# DOUBLE leading underscore (`__offset`, `__remaining`, `__nents`,
# `__rb_parent_color` -- the same convention interval_tree_rs.rs's own
# RbNode mirror already relies on). A single-`_` filter catches those
# too, and since pahole only ever emits the `name __attribute__(...)`
# adjacency this filter keys on for RUST members -- never for C ones,
# which get no per-field attribute at all -- the filter is structurally
# ONE-SIDED: it can only ever remove lines from the Rust geometry, never
# the C one. For a real, double-underscore field that exists on BOTH
# sides, removing it from only the Rust side manufactured exactly the
# false "GEOMETRY DIFFERS" this file exists to prevent, on a struct that
# was byte-for-byte identical (confirmed the same way as `dql` was:
# `pahole -C sg_mapping_iter` vs `pahole -C SgMappingIter` directly).
# Restricting the filter to exactly one leading underscore keeps it
# matching only this project's own padding convention, never the
# kernel's real-field one. What is actually being verified is unchanged
# -- every REAL field's offset/size, and the struct's total size -- just
# no longer accidentally sensitive to which of the two possible ways of
# spelling "unused bytes" either side happened to use, and no longer
# confusable with the kernel's own leading-underscore field names.
geom() {
    pahole -C "$1" "$vmlinux" 2>/dev/null | awk '
        /\/\* size: [0-9]+/ {
            match($0, /size: [0-9]+/)
            print "size=" substr($0, RSTART + 6, RLENGTH - 6)
            next
        }
        {
            # The member name is the identifier immediately before
            # `__attribute__` (pahole annotates every member with one,
            # alignment-forced or not) -- the type name is never
            # adjacent to it, only ever separated by padding whitespace.
            if (match($0, /[A-Za-z_][A-Za-z0-9_]*(\[[0-9]*\])?[[:space:]]+__attribute__/)) {
                ident = substr($0, RSTART, RLENGTH)
                sub(/[[:space:]]+__attribute__.*/, "", ident)
                sub(/\[.*/, "", ident)
                if (ident ~ /^_[^_]/) next
            }
            if (match($0, /\/\*[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]*\*\//)) {
                n = split(substr($0, RSTART, RLENGTH), parts, /[^0-9]+/)
                print parts[2] ":" parts[3]
            }
        }'
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
