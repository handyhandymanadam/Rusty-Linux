#!/usr/bin/env bash
# config.sh <build-dir>
#
# Apply configs/<name>.fragment to a build tree, then READ BACK every line of
# the fragment from the built .config and report what it found.
#
# WHY THIS EXISTS -- a defect, 2026-09-02
#   rig/baseline-symvers.sh installs port/pristine/ over the tree to measure
#   the unported CRCs. The pristine lib/Kconfig has no CONFIG_GLOB prompt and
#   the pristine lib/math/Kconfig has no CONFIG_MATH_SELFTEST, so olddefconfig
#   silently dropped CONFIG_GLOB, CONFIG_GLOB_SELFTEST and CONFIG_MATH_SELFTEST
#   from BOTH build trees. Restoring the files afterwards did not restore the
#   config, because a symbol that lost its prompt does not come back on its
#   own.
#
#   The next build was clean, booted, and rig/crc-check.sh reported zero CRC
#   changes -- truthfully, on a kernel that no longer contained the ported
#   code paths at all. That is PRIOR-ART.md §2's kernel-that-contained-no-Rust,
#   reproduced by our own rig within a day of reading about it.
#
#   It was caught because rig/init distinguishes ABSENT from PASS. This script
#   is so that the next one is caught one step earlier and mechanically.
#
# It reports the state it READ from the built .config, never the fact that it
# appended a fragment. Exit 1 if any line of the fragment did not survive.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:?usage: config.sh <build-dir>}
name=$(basename "$build")
frag="$root/configs/${name#build-}.fragment"

[ -f "$frag" ] || { echo "no fragment: $frag"; exit 2; }
[ -f "$root/$name/.config" ] || { echo "no .config in $name"; exit 2; }

source "$root/kbuild-env.sh"

cat "$frag" >> "$root/$name/.config"
kmake O="$root/$name" olddefconfig >/dev/null

rc=0
n=0
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=*)
            n=$((n + 1))
            if grep -qxF "$line" "$root/$name/.config"; then
                printf '  ok       %s\n' "$line"
            else
                sym=${line%%=*}
                got=$(grep -E "^($sym=|# $sym is not set)" "$root/$name/.config" || true)
                printf '  DROPPED  %s   -> built .config says: %s\n' \
                       "$line" "${got:-nothing at all}"
                rc=1
            fi
            ;;
        "# CONFIG_"*" is not set")
            # A symbol absent from .config altogether is OFF, which is what
            # the line asks for. Only an explicit =y is a failure. Getting
            # this wrong the other way makes the guard cry wolf, and a guard
            # that cries wolf gets ignored, which is worse than none.
            n=$((n + 1))
            sym=${line#\# }
            sym=${sym% is not set}
            if grep -qE "^$sym=" "$root/$name/.config"; then
                printf '  DROPPED  %s   -> built .config says: %s\n' \
                       "$line" "$(grep -E "^$sym=" "$root/$name/.config")"
                rc=1
            elif grep -qxF "$line" "$root/$name/.config"; then
                printf '  ok       %s\n' "$line"
            else
                printf '  ok       %s   (symbol absent, which is off)\n' "$line"
            fi
            ;;
    esac
done < "$frag"

echo "  $n fragment lines checked against the BUILT .config in $name/"
[ "$rc" -eq 0 ] || echo "  ^^ at least one did not survive olddefconfig"
exit $rc
