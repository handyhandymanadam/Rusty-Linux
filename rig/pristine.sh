#!/usr/bin/env bash
# pristine.sh <kernel-relative-path> [...]
#
# Extract the UNMODIFIED original of a kernel file from the tarball into
# port/pristine/, mirroring its path.
#
# WHY: port/tree/ overwrites files in src/linux, and the differential tests
# need the original C body as their oracle. Reading it back out of the tree
# after a port reads OUR file, which is a test agreeing with itself -- one of
# the shapes PRIOR-ART.md §5 records a helper refusing to build. The tarball
# is the only copy that cannot have been touched; it is sha256-verified and
# src/ is gitignored, so port/pristine/ is also where the oracle gets
# versioned.
#
# Run it once per file, when that file is first ported.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tar="$root/src/linux-6.18.49.tar.xz"
top=linux-6.18.49

for rel in "$@"; do
    dst="$root/port/pristine/$rel"
    mkdir -p "$(dirname "$dst")"
    tar -xJf "$tar" -O "$top/$rel" > "$dst"
    printf '%s  %s\n' "$(sha256sum "$dst" | cut -c1-16)" "port/pristine/$rel"
done
