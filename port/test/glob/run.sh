#!/usr/bin/env bash
# Differential test for the lib/glob port. Userspace, seconds, no kernel.
#
# Builds the Rust from port/tree/lib/glob_rs.rs -- the SAME file the kernel
# build compiles. Not a copy: a stale copy tested here while the kernel built
# something else is exactly the failure notes/PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
src="$root/port/tree/lib/glob_rs.rs"
out="${TMPDIR:-/tmp}/glob-difftest.$$"

source "$root/kbuild-env.sh"

mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

# The corpus is EXTRACTED from lib/globtest.c every run, never copied.
python3 "$here/extract_corpus.py" "$root/port/pristine/lib/globtest.c" \
        "$here/corpus_generated.h"

echo "rust source: $src"
echo "            $(sha256sum "$src" | cut -c1-16)  $(stat -c %y "$src")"
echo "rustc:      $("$KB_RUSTC" --version)"
echo

# The kernel injects no_std via -Zcrate-attr. Here the file is compiled as an
# ordinary staticlib; it uses only `core::` paths, so both work from one source.
"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C debug-assertions=on -C overflow-checks=on \
    -D unsafe_op_in_unsafe_fn -W missing-docs \
    --crate-name glob_rs -o "$out/libglob_rs.a" "$src"

cc -O2 -Wall -Wextra -Wno-unused-parameter -o "$out/difftest" \
    "$here/main.c" "$here/ref_glob.c" "$out/libglob_rs.a"

echo "prove-can-fail (the guard page must actually kill us):"
set +e
GLOB_PROVE_CAN_FAIL=1 "$out/difftest" >/dev/null 2>&1
rc=$?
set -e
# 139 = SIGSEGV. Report the code we READ, not the fact that we ran it.
if [ "$rc" -ne 139 ]; then
    echo "  FAILED -- expected SIGSEGV (139), got rc=$rc;"
    echo "  the over-read survived, so the guard-page stage proves nothing"
    exit 1
fi
echo "  ok, killed by SIGSEGV (rc=$rc)"
echo

"$out/difftest" "${1:-2000000}"
