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
echo "== installing port/pristine/ over the tree (Kconfig excluded, see above)"
while IFS= read -r -d '' f; do
    rel=${f#"$root"/port/pristine/}
    case $(basename "$rel") in Kconfig) printf '  skipped   %s\n' "$rel"; continue;; esac
    cp -- "$f" "$root/src/linux/$rel"
    printf '  %s  %s\n' "$(sha256sum "$root/src/linux/$rel" | cut -c1-16)" "$rel"
done < <(find "$root/port/pristine" -type f -print0 | sort -z)

# NOT a bare olddefconfig: the pristine Kconfigs lack the prompts the port
# added, and olddefconfig will drop those symbols without a word. config.sh
# reads the built .config back and says so. The baseline is ALLOWED to lose
# the port's own symbols -- that is what a baseline is -- so a non-zero exit
# here is reported and tolerated, and the restore below is what must be clean.
echo "== configuring the pristine build (drops are expected here)"
"$root/rig/config.sh" "$name" || true
kmake O="$root/$name" -j"$(nproc)" >/dev/null
cp "$root/$name/Module.symvers" "$out"
echo "== baseline recorded: $(wc -l < "$out") symbols -> logs/baseline/$(basename "$out")"

echo "== restoring the port"
"$root/rig/apply.sh"
echo "== restoring the config; THIS one must come back clean"
"$root/rig/config.sh" "$name"
kmake O="$root/$name" -j"$(nproc)" >/dev/null
echo "== rebuilt with the port back in place"
