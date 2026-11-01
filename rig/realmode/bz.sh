#!/usr/bin/env bash
# bz.sh <c|rs> <out.bzImage> [build-dir]  -- build the bzImage with the real-mode setup all-C ("c": rm_objs empty)
# or with the Rust files of the Makefile's rm_objs ("rs"), from the SAME tree, and copy it out. Run rig/apply.sh
# first. Only arch/x86/boot is rebuilt after the first full build of the build dir. Prints setup.elf _end + size.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd); cd "$root"; . ./kbuild-env.sh >/dev/null 2>&1
mode=$1; out=$2; B=${3:-build-fast}
case $mode in c) extra="rm_objs=";; rs) extra="";; *) echo "mode c|rs"; exit 2;; esac
kmake O="$PWD/$B" -j4 $extra bzImage > "$out.build.log" 2>&1 || { echo "BUILD FAILED rc=$? see $out.build.log"; tail -20 "$out.build.log"; exit 1; }
cp "$B/arch/x86/boot/bzImage" "$out"; cp "$B/arch/x86/boot/setup.elf" "${out%.bzImage}.setup.elf"
echo "$mode: $(nm $B/arch/x86/boot/setup.elf | grep -w _end) $(size $B/arch/x86/boot/setup.elf | tail -1)"
