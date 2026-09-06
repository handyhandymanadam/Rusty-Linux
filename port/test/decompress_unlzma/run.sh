#!/usr/bin/env bash
# port/test/decompress_unlzma/run.sh -- the userspace differential for
# lib/decompress_unlzma.c's unlzma(). See drv.c's header for the shape:
# self-contained algorithm (like decompress_bunzip2), no shared backend.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_unlzma"
out="${TMPDIR:-/tmp}/decompress_unlzma-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_unlzma.c"
RS="$root/port/tree/lib/decompress_unlzma_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_unlzma_rs -o "$out/librs.a" "$RS"

# shim/ takes priority over the real kernel include path. mm.h's shim
# defines STATIC/INIT as empty and malloc/free/large_malloc/large_free as
# libc's -- after decompress_unlzma.c's own top-of-file `#ifdef STATIC`
# has already resolved (undefined there -- this test never defines
# STATIC, selecting the non-PREBOOT arm this port's Rust replaces;
# decompress_unlzma.c ITSELF is never modified by this port, see
# decompress_unlzma_rs.rs's module doc for why).
INC=(-I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux/include")
CF=(-O2 -g -Wall -Wno-unused-parameter)

cc "${CF[@]}" "${INC[@]}" -Dunlzma=cref_unlzma -c -o "$out/c_oracle.o" "$C"
cc "${CF[@]}" "${INC[@]}" -c -o "$out/drv.o" "$here/drv.c"
cc -o "$out/t" "$out/drv.o" "$out/c_oracle.o" "$out/librs.a"

# --- corpus: plaintext this script owns, archived by the real xz CLI in
#     the legacy "lzma_alone" format (-F lzma) ---
gen="$out/gen"; mkdir -p "$gen"
python3 - "$gen" "$C" <<'PYEOF'
import os, random, sys
d, c_source_path = sys.argv[1], sys.argv[2]
random.seed(20260906)

def write(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

write("empty.txt", b"")
write("one_byte.txt", b"x")
write("ascii_repeat.txt", (b"the quick brown fox jumps over the lazy dog\n") * 5000)
write("all_same.txt", b"A" * 200000)
write("random.bin", bytes(random.randrange(256) for _ in range(150000)))
write("sparse_bytes.bin", bytes((i * 37) % 256 for i in range(300000)))
with open(c_source_path, "rb") as f:
    write("c_source.c", f.read() * 3)
PYEOF

pairs=()
poison_pairs=()
# Levels 0/1/3 (dict sizes 256KB/1MB/4MB) rather than the higher presets
# this CLI defaults to (up to 64MB at -9) -- buffer mode's output sizing
# for a NULL `output` is MIN(dst_size, dict_size), and these archives'
# dst_size is the lzma_alone "unknown" sentinel by default, so the
# allocation is dict_size itself; keeping it small keeps the corpus fast
# without changing what's under test (the wrapper logic, not dict_size
# handling specifically).
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for level in 0 1 3; do
        arc="$out/${base}.lzma.${level}"
        xz -F lzma -q -q "-$level" -c "$plain" > "$arc"
        pairs+=("$arc" "$plain")
        [ "$(wc -c <"$plain")" -ge 64 ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/level combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# 3 cases per pair (buffer, callback, corrupt) -- same reasoning as the
# rest of this file family's run.sh: poison_pairs is filtered so the
# corrupt-case stage never skips for any included pair, so 3x is exact.
n_poison=$(( (${#poison_pairs[@]} / 2) * 3 ))
poison_out=$(DBZ_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
if [ "$poison_rc" -eq 0 ]; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
if grep -q "cases skipped" <<<"$poison_out"; then
    echo "*** POISON RUN SKIPPED A CASE -- n_poison's 3x-per-pair prediction no longer holds:"
    echo "$poison_out"
    exit 1
fi
if ! grep -qxF "0/$n_poison cases passed" <<<"$poison_out"; then
    echo "*** THE HARNESS CANNOT DISAGREE ON EVERY CASE -- expected \"0/$n_poison cases passed\":"
    echo "$poison_out"
    exit 1
fi
echo "prove-can-fail: poisoned output is detected on all $n_poison poisonable cases"

"$out/t" "${pairs[@]}"
