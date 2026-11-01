#!/usr/bin/env bash
# baseline-symvers.sh <build-dir>
#
# Record the UNPORTED kernel's exported-symbol CRCs, so criterion 4 has
# something to be checked against.
#
# WHEN TO RE-TAKE A BASELINE, AND WHEN NOT TO
#   Re-take it when the CONFIG SET changes -- a newly enabled symbol legitimately
#   ADDs exports, and crc-check.sh will say so. NEVER re-take it to make a
#   CHANGED line go away. A changed CRC is criterion 4 failing; re-recording
#   the baseline is how that becomes invisible, and this script would do it
#   without complaint. That is the one way this file can be used to lie.
#
# WHY IT IS NOT ENOUGH TO NOTE A CRC BEFORE EACH PORT
#   That was tried and it failed on the second module: reciprocal_value's CRC
#   was noted and reciprocal_value_adv's was not, because the grep that
#   captured them matched whole symbol names. The gap was invisible until the
#   ported build produced a number with nothing to compare it to.
#   Deriving the whole table mechanically has no such gap.
#
# HOW
#   Install port/pristine/ over the tree, rebuild, copy Module.symvers out,
#   then put the port back. Both states are verified by reading the tree
#   back, never by trusting the copy.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: baseline-symvers.sh <build-dir>}
name=$(basename "$build")
out="$root/logs/baseline/Module.symvers-$name"

source "$root/kbuild-env.sh"

# Kconfig is deliberately NOT restored. The port's Kconfig changes only add
# prompts and symbols -- they contain no ported code -- and restoring them
# makes olddefconfig drop CONFIG_GLOB and CONFIG_MATH_SELFTEST, so the
# baseline would be measured on a DIFFERENT CONFIGURATION from the ported
# build. Then every symbol that exists in one and not the other shows up as
# added or removed, and the one comparison this file exists to make is buried
# in noise. Same config, different code: that is the only useful baseline.
echo "== making the tree upstream's again (every port/tree file: tarball copy, or removed if upstream has none; Kconfig excluded, see above)"
# 2026-10-27 repair: the old install copied only port/pristine/, which has no copy of kernel/Makefile, the composite Makefiles of later ports, or rust/kernel,
# so the port's Makefile blocks and *_rs.rs files stayed in the build (`kabi_rule` not found) and the script died with the tree half pristine. The tarball is
# the oracle for every file the port touches; port-only files are deleted; rig/apply.sh below puts all of it back.
tarball="$root/src/linux-6.18.49.tar.xz"
up=$(mktemp -d); trap 'rm -rf "$up"' EXIT
mapfile -d '' ported < <(cd "$root/port/tree" && find . -type f -print0 | sort -z)
list=(); for f in "${ported[@]}"; do list+=("linux-6.18.49/${f#./}"); done
tar -C "$up" -xJf "$tarball" --ignore-failed-read "${list[@]}" 2>/dev/null || true
nrep=0; ndel=0
for f in "${ported[@]}"; do
    rel=${f#./}
    case $(basename "$rel") in Kconfig) continue;; esac
    if [ -f "$up/linux-6.18.49/$rel" ]; then cp -- "$up/linux-6.18.49/$rel" "$root/src/linux/$rel"; nrep=$((nrep+1))
    else rm -f -- "$root/src/linux/$rel"; ndel=$((ndel+1)); fi
done
echo "  $nrep files restored from the tarball, $ndel port-only files removed"

# NOT a bare olddefconfig: the pristine Kconfigs lack the prompts the port
# added, and olddefconfig will drop those symbols without a word. config.sh
# reads the built .config back and says so. The baseline is ALLOWED to lose
# the port's own symbols -- that is what a baseline is -- so a non-zero exit
# here is reported and tolerated, and the restore below is what must be clean.
echo "== configuring the pristine build (drops are expected here)"
"$root/rig/config.sh" "$name" || true
kmake O="$root/$name" -j"${KB_JOBS:-$(nproc)}" >/dev/null
cp "$root/$name/Module.symvers" "$out"
echo "== baseline recorded: $(wc -l < "$out") symbols -> logs/baseline/$(basename "$out")"

echo "== restoring the port"
"$root/rig/apply.sh"
echo "== restoring the config; THIS one must come back clean"
"$root/rig/config.sh" "$name"
kmake O="$root/$name" -j"${KB_JOBS:-$(nproc)}" >/dev/null
echo "== rebuilt with the port back in place"
