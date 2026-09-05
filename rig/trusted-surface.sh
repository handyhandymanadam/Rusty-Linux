#!/usr/bin/env bash
# rig/trusted-surface.sh -- the project's headline metric. See logs/trusted-surface.md.
#
# Counts the TRUSTED SURFACE: unsafe blocks in the ported Rust, and the files
# that have none. This is the number that goes down.
#
# It is deliberately NOT a proof-to-code ratio. Gernot Heiser lists that on his
# benchmarking-crimes list ("Comparing meaningless metrics"), and we learned the
# same lesson the same day about absolute mutation scores. A count of unsafe
# blocks means something directly: it is the set of places where a memory bug
# can originate at all.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tot=0 files=0 clean=0
printf '%-46s %8s %10s %7s\n' FILE BLOCKS UNSAFE-FN LINES
for f in $(find "$root/port/tree" -name '*.rs' | sort); do
  b=$(grep -cE 'unsafe \{' "$f")
  fn=$(grep -cE 'unsafe (extern|fn)' "$f")
  l=$(wc -l < "$f")
  if [ "$b" -eq 0 ] && [ "$fn" -eq 0 ]; then clean=$((clean+1)); continue; fi
  printf '%-46s %8s %10s %7s\n' "${f#$root/port/tree/}" "$b" "$fn" "$l"
  tot=$((tot+b)); files=$((files+1))
done
echo
echo "unsafe blocks:            $tot"
echo "files carrying unsafe:    $files"
echo "files with NONE:          $clean"
