#!/usr/bin/env bash
# Regenerate lib/libtest_lzo_generated.h from the pristine in-tree encoder.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
P="$root/port/pristine/lib/lzo"
cc -O2 -Wno-sign-compare -I "$here/shim" -I "$P" \
   -o "$out/gen" "$here/gen_kernel_vectors.c" "$P/lzo1x_compress.c"
cd "$root" && "$out/gen" port/tree/lib/libtest_lzo_generated.h
