#!/usr/bin/env bash
# Differential test for the top-level lib/ ports. Userspace, seconds, no kernel.
#
# Compiles the SAME .rs files the kernel build compiles, out of port/tree/.
# Not copies: a stale copy tested here while the kernel built something else
# is the failure PRIOR-ART.md §2 records four times.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="${TMPDIR:-/tmp}/lib-difftest.$$"

source "$root/kbuild-env.sh"
mkdir -p "$out"
trap 'rm -rf "$out"' EXIT

# The CRC-16 table is EXTRACTED from the pristine lib/crc/crc16.c. The Rust
# generates its table from the polynomial; this is what proves the generator
# reproduces the 256 literals the kernel actually shipped.
python3 "$here/extract_crc16_table.py" \
        "$root/port/pristine/lib/crc/crc16.c" \
        "$here/ref_crc16_table_generated.h"

python3 "$here/extract_bsearch.py" \
        "$root/src/linux/include/linux/bsearch.h" \
        "$here/bsearch_inline_generated.h"

srcs=("$root"/port/tree/lib/*_rs.rs "$root"/port/tree/lib/crc/*_rs.rs \
      "$root"/port/tree/lib/crypto/*_rs.rs \
      "$root"/port/tree/lib/crypto/mpi/*_rs.rs)
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

# The sort() oracle is the PRISTINE lib/sort.c, compiled -- not a copy.
cc -O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -I "$here/shim" -I "$root/port/test/common/shim" \
   -o "$out/difftest" \
   "$here/main.c" "$here/ref_lib.c" "$here/ref_sort.c" "$here/ref_sort_x86.c" "$here/ref_bsearch.c" "$here/ref_list_sort.c" "$here/ref_xxhash.c" "$here/ref_earlycpio.c" "$here/ref_plist.c" "$here/ref_arc4.c" "$here/ref_crc_ccitt.c" "$here/ref_chacha.c" "$here/ref_crypto_utils.c" "$here/ref_ucs2.c" "$here/ref_check_signature.c" \
   "${objs[@]}"
"$out/difftest" "${1:-4000000}"
