#!/usr/bin/env bash
# Regenerate lib/libtest_zstd_generated.h from SYSTEM libzstd.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
cc -O2 -Wall -Wextra -o "$out/gen" "$here/gen_kernel_vectors.c" -lzstd
cd "$root" && "$out/gen" port/tree/lib/libtest_zstd_generated.h
