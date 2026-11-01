#!/usr/bin/env bash
# port/test/decompress_unlz4/run.sh -- the userspace differential for
# lib/decompress_unlz4.c. See drv.c's header for the shape (both arms link
# the SYSTEM liblz4's LZ4_decompress_safe, isolating the wrapper logic).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/port/test/decompress_unlz4"
out="${TMPDIR:-/tmp}/decompress_unlz4-diff.$$"
mkdir -p "$out"; trap 'rm -rf "$out"' EXIT
# shellcheck source=/dev/null
source "$root/kbuild-env.sh"

C="$root/port/pristine/lib/decompress_unlz4.c"
RS="$root/port/tree/lib/decompress_unlz4_rs.rs"
for f in "$C" "$RS"; do [ -f "$f" ] || { echo "missing $f"; exit 2; }; done

"$KB_RUSTC" --edition 2021 --crate-type staticlib -O \
    -C panic=abort -C overflow-checks=on -D unsafe_op_in_unsafe_fn -D warnings \
    --crate-name decompress_unlz4_rs -o "$out/librs.a" "$RS"

# shim/ takes priority over the real kernel include path -- real
# linux/types.h and friends need a full kernel build environment (asm/*
# arch headers, -D__KERNEL__, C11 without _Bool-as-keyword conflicts) this
# userspace compile doesn't have. mm.h's shim DOES define STATIC (matching
# the real header's non-STATIC arm exactly), but only after unlz4.c's own
# top-of-file `#ifdef STATIC` has already resolved -- STATIC is undefined
# there, selecting the non-PREBOOT arm this port replaces. See the shim's
# own header comment for why the later #define is still needed.
CF=(-O2 -g -Wall -Wno-unused-parameter \
    -I "$here/shim" -I "$root/port/test/common/shim" -I "$root/src/linux/include")
cc "${CF[@]}" -Dunlz4=cref_unlz4 -c -o "$out/c.o" "$C"
cc -O2 -g -Wall -c -o "$out/drv.o" "$here/drv.c"
cc -O2 -g -Wall -o "$out/gen_archive" "$here/gen_archive.c" -l:liblz4.so.1
cc -o "$out/t" "$out/drv.o" "$out/c.o" "$out/librs.a" -l:liblz4.so.1

# --- corpus: plaintext this script owns, archived by gen_archive.c ---
gen="$out/gen"; mkdir -p "$gen"
python3 - "$gen" <<'PYEOF'
import os, random, sys
d = sys.argv[1]
random.seed(20260905)

def write(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

write("empty.txt", b"")
write("one_byte.txt", b"x")
write("ascii_repeat.txt", (b"the quick brown fox jumps over the lazy dog\n") * 5000)
write("all_same.txt", b"A" * 200000)
write("random.bin", bytes(random.randrange(256) for _ in range(150000)))
write("sparse_bytes.bin", bytes((i * 37) % 256 for i in range(300000)))
try:
    with open("/home/adam/Rusty-Linux-wt-decompress/port/pristine/lib/decompress_unlz4.c", "rb") as f:
        write("c_source.c", f.read() * 3)
except OSError:
    pass
PYEOF

pairs=()
poison_pairs=()
# Small chunk sizes too, to force MULTIPLE chunks per archive (the loop's
# repeat path), not just the single-chunk case every file under 8MB gives by
# default.
for plain in "$gen"/*; do
    base=$(basename "$plain")
    for chunk in 8388608 4096 37; do
        arc="$out/${base}.lz4a.${chunk}"
        "$out/gen_archive" "$plain" "$arc" "$chunk"
        pairs+=("$arc" "$plain")
        [ -s "$plain" ] && poison_pairs+=("$arc" "$plain")
    done
done

echo "corpus: $((${#pairs[@]} / 2)) plaintext/chunk-size combinations, $(ls "$gen" | wc -l) distinct plaintexts"

# A nonzero exit alone only proves AT LEAST ONE case disagreed, not that
# every poisonable case did -- found by adversarial review: the printed
# claim "detected on all N cases" was unverified, exit code being nonzero
# on even a single mismatch. Checked by reading the "N/M cases passed" line
# back instead.
n_poison=$((${#poison_pairs[@]} / 2))
poison_out=$(DBZ_PROVE_CAN_FAIL=1 "$out/t" "${poison_pairs[@]}" 2>&1) && poison_rc=0 || poison_rc=$?
if [ "$poison_rc" -eq 0 ]; then
    echo "*** THE HARNESS CANNOT DISAGREE -- poisoned run reported no mismatch"
    exit 1
fi
if ! grep -qxF "0/$n_poison cases passed" <<<"$poison_out"; then
    echo "*** THE HARNESS CANNOT DISAGREE ON EVERY CASE -- expected \"0/$n_poison cases passed\":"
    echo "$poison_out"
    exit 1
fi
echo "prove-can-fail: poisoned output is detected on all $n_poison poisonable cases"

"$out/t" "${pairs[@]}"
