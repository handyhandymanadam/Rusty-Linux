#!/usr/bin/env bash
# Regenerate lib/libtest_lz4_generated.h.
#
# Compressed by the SYSTEM liblz4, so the expectation comes from outside this
# project entirely: liblz4 produced the stream and the kernel has to reproduce
# the plaintext. See port/test/lz4/sysenc.c for why the in-tree encoder is not
# used here.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT

# The generator rule lives in two places by necessity -- one has to run in
# userspace and one in the kernel. Refuse to run if they have drifted.
sed -n '/LT_L4GEN_BEGIN/,/LT_L4GEN_END/p' "$here/gen_kernel_vectors.c" > "$out/a"
sed -n '/LT_L4GEN_BEGIN/,/LT_L4GEN_END/p' "$root/port/tree/lib/libtest.c" > "$out/b"
if ! diff -q "$out/a" "$out/b" >/dev/null; then
    echo "lt_l4gen() has drifted between gen_kernel_vectors.c and lib/libtest.c:" >&2
    diff "$out/a" "$out/b" >&2 || true
    exit 1
fi

cc -O2 -Wall -Wextra -o "$out/gen" "$here/gen_kernel_vectors.c" /usr/lib64/liblz4.so.1
"$out/gen" > "$root/port/tree/lib/libtest_lz4_generated.h"
echo "wrote port/tree/lib/libtest_lz4_generated.h"
wc -l "$root/port/tree/lib/libtest_lz4_generated.h"
