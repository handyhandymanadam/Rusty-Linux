#!/usr/bin/env bash
# fanin.sh <build-dir> -- rank lib/ modules by how many call sites the LINKER
# actually resolved against them (SCOPE.md §1).
#
# Not a call graph. `objdump -r` on vmlinux.o -- the pre-link aggregate of every
# built-in object -- lists the relocations the build already produced. A
# relocation IS a symbol boundary, which is exactly where a C<->Rust shim has to
# exist, so this measures shim surface directly rather than approximating it.
#
# vmlinux itself carries no relocations: the final link consumed them. Use
# vmlinux.o.
#
# KNOWN GAP, accepted (SCOPE.md §1): a function always inlined in C has no
# symbol, so it counts zero here even if the Rust version would need a real one.
set -u
BUILD=${1:?usage: fanin.sh <build-dir>}
OUT=/home/adam/Rusty-Linux/logs/fanin-$(basename "$BUILD").tsv
TMP=$(mktemp -d)

# 1. Every symbol defined by an object built from lib/, and which object.
find "$BUILD/lib" -name '*.o' ! -name '*.mod.o' -print0 |
while IFS= read -r -d '' o; do
    nm --defined-only "$o" 2>/dev/null |
        awk -v m="${o#$BUILD/}" '$2 ~ /^[TtWwDdRr]$/ {print $3"\t"m}'
done | sort -u > "$TMP/defs"

# 2. Every relocation target in the linked-together kernel, counted.
objdump -r "$BUILD/vmlinux.o" 2>/dev/null |
    awk 'NF==3 && $1 ~ /^[0-9a-f]+$/ {sub(/[-+]0x.*$/,"",$3); print $3}' |
    sort | uniq -c | awk '{print $2"\t"$1}' | sort -u > "$TMP/counts"

# 3. Join, then aggregate per object file -- the module is the unit of work.
join -t $'\t' "$TMP/defs" "$TMP/counts" 2>/dev/null |
    awk -F'\t' '{n[$2]+=$3; s[$2]++} END {for (m in n) print n[m]"\t"s[m]"\t"m}' |
    sort -rn > "$OUT"

echo "fan-in written to $OUT   ($(wc -l < "$OUT") objects)"
echo
printf '%8s  %6s  %s\n' RELOCS SYMS OBJECT
head -15 "$OUT" | awk -F'\t' '{printf "%8s  %6s  %s\n", $1, $2, $3}'
echo "  ..."
echo "lowest fan-in (candidates to port first):"
awk -F'\t' '$1 > 0' "$OUT" | tail -15 | awk -F'\t' '{printf "%8s  %6s  %s\n", $1, $2, $3}'
rm -rf "$TMP"
