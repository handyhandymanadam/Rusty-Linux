#!/usr/bin/env bash
# crc-check.sh <build-dir>
#
# Criterion 4, mechanically: compare every exported symbol's CRC in the
# ported build against logs/baseline/Module.symvers-<build>.
#
# It reports what it READ from both tables. Symbols that only exist on one
# side are listed separately -- a symbol that appeared or vanished is a
# finding too, and folding it into "no CRC changed" would hide it.
#
# FOUR COLUMNS OF Module.symvers MATTER, not one. An adversarial review on
# 2026-09-04 changed a symbol's NAMESPACE from "" to "RUSTY_ADV_NS" -- the CRC
# did not move, the licence did not move, this script read CHANGED 0, and a
# module importing that symbol then failed to build:
#
#     ERROR: modpost: module modabi uses symbol _bcd2bin from namespace
#            RUSTY_ADV_NS, but does not import it.
#
# That is criterion 4 failing while its own check says it passed. Column 5 is
# now compared alongside the CRC and the licence.
#
# AN ADDED SYMBOL WITH CRC 0x00000000 IS ALSO A FAILURE. gendwarfksyms emits
# that, on a warning and exit 0, for a symbol it has no information about --
# so a NEW Rust export whose pin does not resolve lands as a zero CRC. ADDED
# alone is not fatal (ports legitimately add symbols), so it was exiting 0.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: crc-check.sh <build-dir>}
name=$(basename "$build")
base="$root/logs/baseline/Module.symvers-$name"
now="$root/$name/Module.symvers"

[ -f "$base" ] || { echo "no baseline: $base  (run rig/baseline-symvers.sh $name)"; exit 2; }
[ -f "$now" ]  || { echo "no ported Module.symvers: $now"; exit 2; }

awk -F'\t' -v b="$base" '
BEGIN {
    while ((getline line < b) > 0) {
        n = split(line, f, "\t")
        if (n >= 2) { crc[f[2]] = f[1]; lic[f[2]] = f[4]; ns_[f[2]] = f[5] }
    }
}
{
    if (!($2 in crc)) {
        added = added "\n  + " $2 " " $1 " " $4 ($5 == "" ? "" : " ns:" $5)
        na++
        if ($1 == "0x00000000") {
            zero = zero "\n  ! " $2 "  ADDED with a zero CRC -- gendwarfksyms had"
            zero = zero " no information for it (unresolved pin?)"
            nz++
        }
        next
    }
    seen[$2] = 1
    if ($1 != crc[$2]) { changed = changed "\n  ! " $2 "  " crc[$2] " -> " $1; nc++ }
    else if ($4 != lic[$2]) { changed = changed "\n  ! " $2 "  licence " lic[$2] " -> " $4; nc++ }
    else if ($5 != ns_[$2]) {
        changed = changed "\n  ! " $2 "  namespace \"" ns_[$2] "\" -> \"" $5 "\""
        nc++
    }
    ns++
}
END {
    for (s in crc) if (!(s in seen)) { removed = removed "\n  - " s " " crc[s]; nr++ }
    printf "baseline %d symbols, ported build %d matched\n", length(crc), ns
    printf "CHANGED  %d%s\n", nc+0, changed
    printf "ADDED    %d%s\n", na+0, added
    printf "REMOVED  %d%s\n", nr+0, removed
    printf "ZERO-CRC %d%s\n", nz+0, zero
    exit (nc+nr+nz) ? 1 : 0
}' "$now"
