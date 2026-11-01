#!/usr/bin/env bash
# kabi-symtypes.sh <object.o> <symbol>...
# Print the Rust text for kabi_export! contracts in the --symtypes (back-reference) form, taken from a C
# OBJECT that still defines the symbols: one kernel::kabi_rule!("type_string", ...) per referenced type
# (each once), then `contract = "..."` per symbol. rig/kabi-pin.sh --capture does the same for lib/
# objects only (and emits C); this one takes any object, for kernel/, fs/, arch/ ports. A contract copied
# from `--dump-versions` expands the first use of every type inline and cannot express a self-referential
# struct (timecounter -> cyclecounter -> read(cyclecounter *)): gendwarfksyms then reports "unknown type
# reference". Run it BEFORE the C object is replaced. Rule text goes in port files via the C fingerprint
# it prints, which rig/crc-check.sh must keep.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
G="$root/build-full/scripts/gendwarfksyms/gendwarfksyms"
obj=${1:?usage: kabi-symtypes.sh <object.o> <symbol>...}; shift
tmp=$(mktemp -d); : > "$tmp/types"; : > "$tmp/fp"; trap 'rm -rf "$tmp"' EXIT
for sym in "$@"; do
    printf '%s\n' "$sym" | "$G" --stable --symtypes "$tmp/$sym.st" "$obj" >/dev/null 2>&1
    crc=$(printf '%s\n' "$sym" | "$G" --stable --dump-versions "$obj" 2>/dev/null | sed -n "s/^#SYMVER $sym //p" | head -1)
    [ -s "$tmp/$sym.st" ] || { echo "// $sym: no symtypes from $obj" >&2; exit 1; }
    echo "// $sym: C fingerprint $crc" >> "$tmp/fp"
    while IFS= read -r l; do
        n=${l%% *}
        [ "$n" = "$sym" ] && continue
        printf '%s\n' "$l" >> "$tmp/types"
    done < "$tmp/$sym.st"
    l=$(grep -m1 "^$sym " "$tmp/$sym.st"); printf '%s\t%s\n' "$sym" "${l#* }" >> "$tmp/contracts"
done
cat "$tmp/fp"
sort -u "$tmp/types" | while IFS= read -r l; do
    printf 'kernel::kabi_rule!("type_string", "%s",\n    "%s");\n' "${l%% *}" "${l#* }"
done
while IFS=$'\t' read -r s c; do printf '// contract for %s:\n//   contract = "%s",\n' "$s" "$c"; done < "$tmp/contracts"
