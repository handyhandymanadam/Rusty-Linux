#!/usr/bin/env bash
# e820_boot_compare.sh [fast|full|both]     (NOT RUN by wt-pe3: rig/boot-cmdline.sh holds `rm -rf "$TMP"` for Adam's approval)
#
# Boots the unmodified-C kernel (build-<cfg>-base, in the main checkout) and the ported kernel (build-<cfg> of the tree
# this is run in) with each kernel command line below, and diffs every e820-related line the two serial logs print, with
# the timestamps stripped:
#   BIOS-provided physical RAM map / BIOS-e820 lines, `e820: update|remove [mem ...] <type> ==> <type>`,
#   `user-defined physical RAM map` / `user:` lines, `modified physical RAM map`, `last_pfn = ... max_arch_pfn = ...`,
#   `[mem ...] available for PCI devices`, `too many entries; ignoring`, `mem=nopentium ignored`.
# Prints N (the number of command lines x configs compared) and exits 1 on the first difference.
# Needs: rig/boot-cmdline.sh (BZ_APPEND, BZ_LOG), qemu, the two build dirs. Run it from the worktree root.
set -u
root=$(cd "$(dirname "$0")/../.." && pwd)
main=${MAIN_CHECKOUT:-/home/adam/Claude/rusty-linux-private}
which=${1:-both}
scratch=${SCRATCH:-/home/adam/Claude/tmp-pe3/e820-boot}; mkdir -p "$scratch"
# 140 memmap items: more than E820_MAX_ENTRIES on config-fast (131) so the "too many entries; ignoring" message prints
many=$(python3 -c "print(' '.join('memmap=4K\$0x%x' % (0x2000000 + 0x2000*i) for i in range(140)))")
cmdlines=(
  ""
  "mem=64M"
  "mem=0x3000000"
  "memmap=16M\$0x2000000"
  "memmap=1M#0x3000000"
  "memmap=2M!0x3200000"
  "memmap=exactmap memmap=640K@0 memmap=127M@1M"
  "memmap=exactmap memmap=640K@0 memmap=63M@1M memmap=1M\$0x4000000"
  "memmap=8M%0x1000000-1+2"
  "memmap=8M%0x2000000+2"
  "memmap=4M%0x2800000-1"
  "memmap=4M%0x2800000"
  "memmap=1G@0x100000000"
  "mem=nopentium"
  "memmap=nonsense memmap=12M@x"
  "$many"
)
filt() { sed -E 's/^\[ *[0-9]+\.[0-9]+\] //' "$1" | grep -E "BIOS-|e820|physical RAM map|last_pfn|available for PCI|too many entries|mem=nopentium|user:|modified:|extended:" | awk '/^last_pfn/ { if (seen++) next } { print }' | { if [[ "$2" == *exactmap* ]]; then sed -E 's/^\[mem 0x[0-9a-f]+-0xffffffff\] available for PCI devices/[mem MASKED-0xffffffff] available for PCI devices (exactmap: start follows the noisy 2nd last_pfn)/'; else cat; fi; } }
n=0; bad=0
for cfg in $( [ "$which" = both ] && echo "fast full" || echo "$which" ); do
  for i in "${!cmdlines[@]}"; do
    a="${cmdlines[$i]}"
    for side in base port; do
      d=$([ $side = base ] && echo "$main/build-$cfg-base" || echo "$root/build-$cfg")
      BZ_APPEND="$a" BZ_LOG="$scratch/$cfg-$side-$i.log" "$root/rig/boot-cmdline.sh" "$d" 90 > "$scratch/$cfg-$side-$i.report" 2>&1
      filt "$scratch/$cfg-$side-$i.log" "$a" > "$scratch/$cfg-$side-$i.e820"
    done
    n=$((n+1))
    if [ ! -s "$scratch/$cfg-base-$i.e820" ] || [ ! -s "$scratch/$cfg-port-$i.e820" ]; then
      if [ ! -s "$scratch/$cfg-base-$i.e820" ] && [ ! -s "$scratch/$cfg-port-$i.e820" ]; then
        echo "same  $cfg #$i (BOTH kernels print nothing: silent hang on this cmdline)  cmdline: ${a:0:80}"; continue
      fi
      echo "DIFF  $cfg #$i  one kernel printed nothing: base $(wc -l < "$scratch/$cfg-base-$i.e820") lines, port $(wc -l < "$scratch/$cfg-port-$i.e820") lines  cmdline: ${a:0:80}"; bad=$((bad+1)); continue
    fi
    if diff -u "$scratch/$cfg-base-$i.e820" "$scratch/$cfg-port-$i.e820" > "$scratch/$cfg-$i.diff"; then
      echo "same  $cfg #$i ($(wc -l < "$scratch/$cfg-base-$i.e820") e820 lines, init: $(grep -c 'RIG: done' "$scratch/$cfg-port-$i.log") reached userspace)  cmdline: ${a:0:80}"
    else
      echo "DIFF  $cfg #$i  cmdline: ${a:0:80}"; cat "$scratch/$cfg-$i.diff" | head -20; bad=$((bad+1))
    fi
  done
done
echo "e820_boot_compare: N=$n boots-pairs compared, $bad differ"
[ $bad = 0 ]
