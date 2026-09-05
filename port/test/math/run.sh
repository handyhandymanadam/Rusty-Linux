#!/usr/bin/env bash
# Differential test for the lib/math/ port. Userspace, seconds, no kernel.
#
# Compiles the SAME .rs files the kernel build compiles, out of port/tree/.
# Not copies: a stale copy tested here while the kernel built something else
# is the failure PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/math-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

# The log table is EXTRACTED from the pristine lib/math/int_log.c, never
# retyped and never read out of the ported file.
python3 "$here/extract_logtable.py" \
        "$root/port/pristine/lib/math/int_log.c" \
        "$here/ref_logtable_generated.h"

srcs=("$root"/port/tree/lib/math/*_rs.rs)
echo "rust sources:"
for s in "${srcs[@]}"; do
    printf '  %s  %s\n' "$(sha256sum "$s" | cut -c1-16)" "${s#"$root"/}"
done
echo "rustc: $("$KB_RUSTC" --version)"
echo

objs=()
for s in "${srcs[@]}"; do
    n=$(basename "$s" .rs)
    "$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
        -C panic=abort -C debug-assertions=on -C overflow-checks=on \
        -D unsafe_op_in_unsafe_fn -W missing-docs \
        --crate-name "$n" -o "$out/lib$n.a" "$s"
    objs+=("$out/lib$n.a")
done

cc -O2 -Wall -Wextra -o "$out/difftest" "$here/main.c" "$here/ref_math.c" "${objs[@]}"
"$out/difftest" "${1:-4000000}"
